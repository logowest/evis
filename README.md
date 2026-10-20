# evis — ETSI TS 102 232 handover for a single DNS request

Generates ETSI TS 102 232 (HI2/HI3) handover PDUs wrapping **one DNS query**, and
serves a **Go + a-h/templ + Datastar** web UI that decodes the file and shows the
nested PDUs — `PS-PDU → payload → IPCC / IPIRIOnly → IPv4 · UDP · DNS` — as an
expandable tree cross-linked to a live hex view.

Everything is synthetic test data: the DNS lookup is `example.com`, and the IP
addresses use the RFC 5737 documentation ranges (`198.51.100.0/24`,
`203.0.113.0/24`). Nothing here intercepts anything — it builds and inspects the
*handover file format* that a mediation function would emit from an already-
authorised intercept, the way a conformance/QA harness does.

## What it produces

Three handover files:

| File | Payload | Carries |
|------|---------|---------|
| `dns-request-cc.etsi` | `cCPayloadSequence → CCPayload → IPCC` | the whole intercepted datagram (IPv4/UDP/DNS) as `iPPackets` — content of communication |
| `dns-request-iri-only.etsi` | `iRIPayloadSequence → IRIPayload → IPIRIOnly` | the IPv4 + UDP header fields only — intercept-related information, no content |
| `dns-request-iri-cc.etsi` | both of the above, as two concatenated `PS-PDU`s | the IRI PDU then the CC PDU, same LIID + CIN, both `sequenceNumber` 0 — `payload` is a CHOICE, so IRI and CC can't share one PS-PDU, and they are separate sequence number contexts (TS 102 232-1 5.2.5) |

Each also has a `.hex` annotated dump.

## Quick start

```bash
# 1. (Re)generate the sample files + a printed PDU tree sanity check
go run ./cmd/gen -out samples

# 2. Visualise — open http://localhost:8080
go run ./cmd/visualise
#   -addr :9000   to change the port
```

The UI ships the three samples built in (the buttons), and you can **upload any
`.etsi` file**. Hover a field in the tree to highlight its exact bytes in the hex
pane. The byte highlighting is driven by Datastar signals; sample switching and
upload use Datastar's `sse()` backend action (SSE fragment merge).

The module vendors its one dependency (the templ runtime), so it builds and runs
offline with no toolchain fuss.

## Encoding, and how faithful it is

The structure follows the ASN.1 modules for **TS 102 232-1 V3.38.1 (2026-08)**,
from the ETSI LI forge (`forge.etsi.org/rep/li/schemas-definitions`):

- **TS 102 232-1** `LI-PS-PDU` — `PS-PDU` / `PSHeader` / `Payload`, module version 43
  (`li-psDomainId = 0.4.0.2.2.5.1.43`).
- **TS 102 232-3** `IPAccessPDU` — `IPCC`, `IPIRIOnly`, module version 20
  (`iPCCObjId = 5.3.20.2`, `iPIRIOnlyObjId = 5.3.20.3`).

Every field these samples use is unchanged since v31 / v13 (later versions only
add extensions), so the encoding is the same apart from those version arcs. The
decoder labels any `li-psDomainId` / IP-access version, so older captures still
read clearly.

Both modules are `DEFINITIONS IMPLICIT TAGS`. The encoder (`internal/ber`) applies
the two rules that matter:

- every field is **implicitly** context-tagged (the context tag replaces the base
  type's universal tag), and
- a context tag on a **CHOICE** is automatically **EXPLICIT** — it wraps the full
  TLV of the selected alternative. These are the `ber.CExplicit` calls in
  `internal/etsi/etsi.go` (`payload`, `cCContents`, `iPCCContents`, `iRIContents`,
  `iPInformation`, `protocolInformation`).

The output is valid definite-length BER and parses cleanly under
`openssl asn1parse -inform DER`. It's a faithful, representative file built from
the public modules — not guaranteed byte-identical to a specific vendor's profile.
If you have the exact ASN.1 you're targeting (or a reference capture), drop it in
and I can line the encoder up with it field-for-field.

The DNS query and the IPv4/UDP wrapper are real wire-format bytes with correct
IPv4 header and UDP checksums, so `dns-request-cc.etsi`'s `iPPackets` also opens
cleanly in Wireshark.

## Layout

```
cmd/gen/                 generator CLI  → samples/*.etsi + *.hex
cmd/visualise/           web server (templ + Datastar + embedded assets)
  templates.templ          UI components (generated: templates_templ.go)
  helpers.go               view model, Datastar expression helpers
  static/                  datastar.js (vendored v0.21.4) + app.css
internal/ber/            BER TLV encoder + parser + Node tree
internal/dns/            DNS query builder + decoder
internal/ipstack/        IPv4/UDP builder (+ checksums) + decoder
internal/etsi/           ETSI PDU builders (etsi.go) + tree annotator (annotate.go)
samples/                 generated handover files
```

## Editing the UI

`templates_templ.go` is committed, so you don't need the templ toolchain to build.
If you change `templates.templ`, regenerate with the standard CLI:

```bash
go run github.com/a-h/templ/cmd/templ@latest generate   # or: templ generate
```

## Notes

- `authorizationCountryCode`, `microSecondTimeStamp`, and other optional PSHeader
  fields are omitted for brevity; the annotator labels them if present in an
  uploaded file.
- To emit a combined PDU (IRI + CC in one `PS-PDU`, per clause 6.2.3) or a
  different QTYPE/target, see `etsi.DefaultScenario` / `etsi.DefaultMeta` and the
  `BuildCC` / `BuildIRIOnly` builders.
