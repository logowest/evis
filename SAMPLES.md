# Samples

The `samples/` directory holds synthetic ETSI TS 102 232 handover files: what
each one contains and what it is useful for testing. Every `.etsi` file is raw
BER (one or more PS-PDUs back to back) and has a matching `.hex` annotated hex
dump.

All samples are generated, never captured: regenerate them with

```bash
go run ./cmd/gen -out samples
```

The same samples are built into the visualiser (`go run ./cmd/visualise`) as
the buttons listed under each heading, so you can browse them without
uploading.

## Common to every sample

| Field | Value |
| --- | --- |
| Header module | LI-PS-PDU version 43 (`li-psDomainId 0.4.0.2.2.5.1.43`), TS 102 232-1 V3.38.1 |
| LIID | `DEMO-LIID-0001` |
| Operator (`operatorIdentifier`) | `DEMO-CSP` |
| Target address | `198.51.100.23` |
| Base timestamp | `2026-10-12 21:11:00Z`, qualifier `timeOfInterception` |
| Test data | Addresses are RFC 5737 documentation ranges; names are `example.com`. Nothing resembles a real target. |

Each scenario has its own network element and CIN, so DNS, HTTP and VoIP are
three separate communication sessions:

| Scenario | `networkElementIdentifier` | CIN |
| --- | --- | --- |
| DNS | `ne-dns-01` | 1001 |
| HTTP | `ne-http-01` | 1002 |
| VoIP | `ne-voip-01` | 1003 |

IRI and CC are separate sequence number contexts (TS 102 232-1 §5.2.5), so
each starts at 0. In files holding both, the IRI PDU and the first CC PDU
therefore both carry `sequenceNumber 0`. This is expected, not a bug.

Every packet carried in CC has valid IPv4, UDP and TCP checksums, so it
also decodes cleanly in Wireshark.

## Overview

| File | Size | PS-PDUs | Payload | Demonstrates |
| --- | ---: | ---: | --- | --- |
| `dns-request-cc.etsi` | 162 | 1 | CC · IPCC | A whole packet in `iPPackets`, decoded as IPv4 / UDP / DNS |
| `dns-request-iri-only.etsi` | 151 | 1 | IRI · IPIRIOnly | Header-only IRI with `uDPInformation` |
| `dns-request-iri-cc.etsi` | 313 | 2 | IRI + CC | IRI and CC for one session in one file |
| `http-request-cc.etsi` | 253 | 1 | CC · IPCC | IPv4 / TCP / HTTP decoding |
| `http-request-iri-only.etsi` | 168 | 1 | IRI · IPIRIOnly | `tCPInformation`, including BIT STRING fields |
| `http-request-iri-cc.etsi` | 421 | 2 | IRI + CC | As DNS, over TCP |
| `http-exchange-cc.etsi` | 9461 | 7 | CC · IPCC | TCP reassembly across PDUs, gzip body decoding, both directions |
| `http-exchange-reordered-cc.etsi` | 11086 | 8 | CC · IPCC | Reassembly with out-of-order and retransmitted segments |
| `voip-call-iri.etsi` | 643 | 1 | IRI · IPMMIRI | SIP INVITE + SDP as an IRI-BEGIN (TS 102 232-5) |
| `voip-call-cc.etsi` | 1032 | 3 | CC · IPMMCC | RTP media, one packet per PS-PDU |
| `voip-call-iri-cc.etsi` | 1675 | 4 | IRI + CC | A call's signalling and media correlated by CIN and `streamIdentifier` |

## DNS request

An `A` query for `example.com.` (ID `0x1a2b`, recursion desired) from
`198.51.100.23:49152` to the resolver `203.0.113.53:53`, over UDP.

### `dns-request-cc.etsi`: CC

Visualiser: **DNS → CC payload**

One CC PS-PDU. `cCContents` holds `iPCC` (TS 102 232-3 IPAccessPDU v20,
`iPCCObjId 5.3.20.2`), whose `iPPackets` is the complete 57-byte IPv4/UDP/DNS
datagram. `payloadDirection` is `fromTarget`.

Demonstrates:
- The basic PS-PDU layout: `pSHeader`, then `payload` → `cCPayloadSequence` →
  `cCPayload` → `cCContents` → `iPCC`.
- Explicit tagging of CHOICE types: `payload [2]`, `cCContents [2]` and
  `iPCCContents [1]` each wrap the selected alternative.
- Decoding the inner packet: the IPv4 header, the UDP header, and the DNS
  header and question. The DNS decoder is chosen because the port is 53.

### `dns-request-iri-only.etsi`: IRI-only

Visualiser: **DNS → IRI-only**

One IRI PS-PDU, `iRIType iRI-Report`. `iRIContents` holds `iPIRIOnly`
(`iPIRIOnlyObjId 5.3.20.3`): the packet's header fields without its content.

Demonstrates:
- `iPv4Information`: total length 57, identification, TTL, protocol UDP,
  source and destination. Each is an OCTET STRING of the raw header bytes.
- `protocolInformation` → `uDPInformation`: ports, length and checksum.
- Explicit tagging of `iPInformation [1]` and `protocolInformation [2]`.

### `dns-request-iri-cc.etsi`: IRI + CC

Visualiser: **DNS → IRI + CC**

The IRI-only PDU followed by the CC PDU. They are separate PDUs because
`payload` is a CHOICE: one PS-PDU carries IRI or CC, never both.

Demonstrates:
- Correlating IRI and CC through the same LIID and CIN.
- Separate sequence number contexts: both PDUs carry `sequenceNumber 0`.

## HTTP request

A `GET /` for `Host: example.com` (also sending `User-Agent`, `Accept` and
`Accept-Encoding: gzip`) from `198.51.100.23:49200` to `203.0.113.80:80`. It
is one TCP segment with `PSH, ACK`, sequence number 1000001 and ack 2000001,
sent on an already-established connection. The handshake is not included.

### `http-request-cc.etsi`: CC

Visualiser: **HTTP → CC payload**

As the DNS CC sample, but the 140-byte packet in `iPPackets` is IPv4/TCP/HTTP.

Demonstrates:
- Decoding the TCP header: ports, sequence and ack numbers, data offset, flags,
  window, checksum and urgent pointer.
- Decoding an HTTP/1.1 request: method, request-target and version, each
  header field, and the empty line ending the headers.

### `http-request-iri-only.etsi`: IRI-only

Visualiser: **HTTP → IRI-only**

As the DNS IRI-only sample, but `protocolInformation` holds `tCPInformation`.

Demonstrates:
- The TCP alternative of `protocolInformation` (`[1]`, where UDP is `[2]`).
- BIT STRING fields: `dataOffset` is a 4-bit BIT STRING (value 5, meaning a
  20-byte header), and `controlBits` is a 6-bit BIT STRING (`PSH, ACK`).

### `http-request-iri-cc.etsi`: IRI + CC

Visualiser: **HTTP → IRI + CC**

The IRI-only PDU followed by the CC PDU, as for DNS.

## HTTP exchange (TCP reassembly)

The HTTP request above, followed by the server's response.

The response is `HTTP/1.1 200 OK` with `Content-Type: text/html`,
`Content-Encoding: gzip`, and a gzip body of 8054 bytes (19018 bytes once
decompressed). The page is an HTML table of SHA-256 strings, chosen because it
compresses poorly and so still needs several segments. The response is 8219
bytes in total, split into six segments of at most 1460 bytes (the MSS). Each
segment is carried in its own CC PS-PDU, `toTarget`, from `203.0.113.80:80`
with TTL 56.

Request and response share one CC sequence number context (same LIID and CID),
so `sequenceNumber` counts up across all the PDUs. The timestamps carry
milliseconds: the response starts 30 ms after the request, then each segment
follows 1 ms after the one before.

### `http-exchange-cc.etsi`: in order

Visualiser: **HTTP → Exchange**

PS-PDU #1 is the request (`fromTarget`); #2–#7 are the response segments, in
order.

Demonstrates:
- **Payload direction:** `fromTarget` for the request, `toTarget` for the
  response.
- **Per-packet decoding of a partial message:** PDU #2 starts with the status
  line, so it decodes as an HTTP response. Its body is incomplete, and gzip
  decodes only the first 2794 bytes before reporting that the data ended.
- **TCP reassembly across PDUs:** PDU #7 completes the response, so it gets a
  "reassembled HTTP response" node: "8219 bytes from 6 segments, PS-PDUs
  #2–#7". Under it:
  - a "segments" list, where hovering a segment highlights its bytes;
  - the full status line and headers;
  - the body, whose "decoded content" holds the whole decompressed page with a
    preview.
- **Simple highlighting:** a field that spans segments, such as the body,
  highlights the part in its first segment, and its tooltip lists the PDUs it
  spans.
- **Back-references:** PDUs #3–#7 show their payload as "part of the HTTP
  response reassembled in PS-PDU #7".

### `http-exchange-reordered-cc.etsi`: reordered + retransmission

Visualiser: **HTTP → Reordered**

The same exchange, but the response segments are intercepted in the order
1, 3, 2, 4, 5, 6, 3 (1-based). The third segment arrives before the second,
and it is sent again at the end as a retransmission in PS-PDU #8.

Demonstrates:
- Ordering by TCP sequence number: the reassembled response is identical to the
  in-order sample. The "segments" list shows stream order: PDU #2, #4, #3, #5,
  #6, #7.
- Retransmission handling: PDU #8 is marked "retransmission: bytes already
  seen, not used", and its bytes are not counted twice.
- `sequenceNumber` reflects interception order (0–7), unlike the TCP
  sequence numbers.

Gaps (lost segments) have no sample file. They are covered by
`TestHTTPExchangeGap`, which shows "cut off by N missing bytes" on the
reassembled message and "follows N missing bytes" on the next segment.

## VoIP call (TS 102 232-5)

The start of a call from `alice@example.com` to `bob@example.com`, using the
IP multimedia module (IPMultimediaPDU v17, the version LI-PS-PDU v43 imports).
Signalling goes from the target `198.51.100.23:5060` to the SIP proxy
`203.0.113.5:5060`. The SDP offers G.711 µ-law (PCMU) audio on port 40000.
Media flows from `198.51.100.23:40000` to `203.0.113.40:40002`.

### `voip-call-iri.etsi`: SIP IRI

Visualiser: **VoIP → SIP IRI**

One IRI PS-PDU, `iRIType iRI-Begin` (the INVITE starts the session).
`iRIContents` holds `iPMMIRI [11]` (`iPMMIRIObjId 5.5.17.1`), whose
`iPMMIRIContents` is a `sIPMessage`.

Demonstrates:
- **`sIPMessage`:** the SIP content plus the network-layer source and
  destination addresses, as TS 102 232-5 clause 5.2.7 describes.
- **`IPAddress` (TS 102 232-1):** `iP-type iPV4`, `iP-value` →
  `iPBinaryAddress`, and `iP-assignment dynamic`. `iP-value` is another
  explicitly tagged CHOICE, like `iPMMIRIContents`.
- **SIP decoding:** request line (`INVITE sip:bob@example.com SIP/2.0`), Via,
  From/To with tags, Call-ID, CSeq, Contact, Content-Type and Content-Length.
- **SDP decoding,** line by line. `c=` and `m=audio 40000 RTP/AVP 0` say where
  the media goes; `a=rtpmap:0 PCMU/8000` names the codec.

### `voip-call-cc.etsi`: RTP CC

Visualiser: **VoIP → RTP CC**

Three CC PS-PDUs, one RTP packet each: TS 102 232-5 allows only one packet per
`IPMMCC`. `cCContents` holds `iPMMCC [12]` (`iPMMCCObjId 5.5.17.2`) with:
- `mMCCContents`: the complete 200-byte IPv4/UDP/RTP packet;
- `frameType ipFrame`: all headers are present;
- `streamIdentifier "m=audio 40000 RTP/AVP 0"`: the SDP media line;
- `mMCCprotocol rTP`.

Demonstrates:
- **RTP decoding:** version/P/X/CC, marker and payload type (`0 = PCMU`),
  sequence number, timestamp, SSRC `0x5eed1e55`, and a 160-byte payload of µ-law
  silence (20 ms at 8 kHz).
- **A media stream across PDUs:**

  | RTP packet | RTP seq | RTP timestamp | Marker |
  | --- | --- | --- | --- |
  | 1 | 1 | 160 | set (start of talkspurt) |
  | 2 | 2 | 320 | — |
  | 3 | 3 | 480 | — |

  The PS-PDU timestamps are 20 ms apart (`…02Z`, `…02.02Z`, `…02.04Z`), and
  `sequenceNumber` counts 0, 1, 2.
- **RTP detection by heuristic:** RTP has no fixed port, so it is recognised
  from its header (version 2, payload type outside the RTCP range).

### `voip-call-iri-cc.etsi`: IRI + CC

Visualiser: **VoIP → IRI + CC**

The SIP IRI PDU followed by the three RTP CC PDUs. The media starts 2 seconds
after the INVITE.

Demonstrates:
- Correlating signalling and media: the same LIID and CIN, and a
  `streamIdentifier` that matches the SDP `m=` line in the IRI.
- Separate sequence number contexts again: the IRI and the first CC are both 0.

## What the samples do not cover

These are decoded when they appear in uploaded files, but no sample shows
them; most have unit tests instead:

- SIP as a full packet (`originalIPMMMessage`) and RTP without IP/UDP headers
  (`frameType rtpFrame`): `voip_test.go`.
- Chunked bodies, deflate, and truncated gzip: `internal/httpmsg`.
- Two requests sent back to back in one segment (pipelining): `TestPipelinedRequests`.
- Lost TCP segments: `TestHTTPExchangeGap`.
- RTP with CSRCs, header extensions or padding: `internal/rtp`.

Not decoded at all: IPv6, Brotli (`br`) bodies, H.323 content, TLS (HTTPS) and
TS 102 232 service modules other than IP access (-3) and IP multimedia (-5).
These appear in the tree with generic labels.
