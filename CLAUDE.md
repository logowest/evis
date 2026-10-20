# CLAUDE.md

Guidance for working on **evis** — a Go tool that builds ETSI TS 102 232
(HI2/HI3) handover PDUs for a single DNS request and serves a templ + Datastar
web UI that decodes them. Read this before changing the encoder or the UI.

## Commands

```bash
go build ./...                       # build everything
go run ./cmd/gen -out samples        # (re)generate samples/*.etsi + *.hex, prints a PDU tree
go run ./cmd/visualise               # web UI on :8080  (flag: -addr :9000)
go vet ./...
```

Dependencies are **vendored** (just the templ runtime), so build/run works
offline with no module fetches. After changing deps: `go mod tidy && go mod vendor`.

`templates_templ.go` is **committed**, so the templ CLI is NOT needed to build.
Only regenerate after editing `cmd/visualise/templates.templ`:

```bash
go run github.com/a-h/templ/cmd/templ@latest generate   # or: templ generate
```

## The encoding rules that matter (don't break these)

Both ASN.1 modules are `DEFINITIONS IMPLICIT TAGS`. The encoder in
`internal/ber` and the builders in `internal/etsi/etsi.go` rely on two rules:

1. **Implicit context tagging** — a field's context tag *replaces* the base
   type's universal tag. `ber.CPrim/CCons/CInt/COID/CRelOID/COctet/...` do this.
2. **A context tag on a CHOICE is automatically EXPLICIT** (X.680 §30.6c) — it
   *wraps* the full TLV of the selected alternative. These are the `ber.CExplicit`
   calls, and every one is load-bearing:
   - `payload` ([2], Payload is CHOICE)
   - `cCContents` ([2]), `iPCCContents` ([1])
   - `iRIContents` ([2]), `iPInformation` ([1]), `protocolInformation` ([2])

If you add a field whose type is a CHOICE, it needs `CExplicit`, not `CCons`.
If it's anything else, it's implicit. Getting this wrong still produces parseable
BER but the wrong structure — always re-validate (below).

## Authoritative spec source

Targets **TS 102 232-1 V3.38.1 (2026-08)**. ASN.1 from the public ETSI LI forge
(`forge.etsi.org/rep/li/schemas-definitions`), commit
`e531df05fd5c21c596ffed1028775b87bd61c2a0` (its LI-PS-PDU is identical to
`LI-PS-PDU,ver43.asn` in the spec's `ts_10223201v033801p0.zip`):

- `102232-1/LI-PS-PDU.asn` — TS 102 232-1, module **version 43**.
  `li-psDomainId = 0.4.0.2.2.5.1.43`.
- `102232-3/IPAccessPDU.asn` — TS 102 232-3, module **version 20**.
  RELATIVE-OIDs: `iPCCObjId = 5.3.20.2`, `iPIRIOnlyObjId = 5.3.20.3`.

Every field used here is unchanged since v31 / v13 (the earlier `li/trial`
commit `49d1c4c2…`); newer versions only added extensions.

**Sequence numbers:** IRI and CC are separate sequence number contexts (the
payload type is part of the context, TS 102 232-1 5.2.5 table 1A) and each
starts at 0, so `BuildIRIAndCC` gives both PDUs the same `sequenceNumber`.

Fetch raw with `…/-/raw/<commit>/102232-1/LI-PS-PDU.asn`. To match a different
profile/version, diff against that module and adjust tags in `etsi.go` +
labels/enum maps in `annotate.go` together.

## Architecture

```
internal/ber/        BER toolkit. ber.go = encoder (TLV + C* helpers).
                     parse.go = parser + Node tree (absolute Offset/HeaderLen/Length).
internal/dns/        DNS query Build() + DecodeNodes() (RFC 1035, query only).
internal/ipstack/    IPv4/UDP UDPDatagram() with real checksums + DecodeNodes().
internal/etsi/       etsi.go   = PDU builders (BuildCC, BuildIRIOnly, Meta, Scenario).
                     annotate.go = walks a decoded tree, labels ETSI fields,
                                   drills iPPackets into IPv4/UDP/DNS nodes.
                     fieldinfo.go = per-field descriptions (Node.Note), shown
                                   as tree tooltips; § refs are TS 102 232-1 V3.38.1.
cmd/gen/             generator CLI; also prints the annotated tree as a self-check.
cmd/visualise/       web server (main.go), view model + Datastar expr helpers
                     (helpers.go), UI (templates.templ), embedded static/.
```

Import direction (no cycles): `ber` depends on nothing; `dns`/`ipstack` import
`ber` (to emit `Node`s); `etsi` imports `ber`+`dns`+`ipstack`; `cmd/*` import
`etsi`+`ber`.

`ber.Node` is the single tree type. A normal node is a TLV. A node with
`Raw = true` is a labelled byte range (HeaderLen 0) — used for the decoded inner
IPv4/UDP/DNS fields, with absolute offsets so hex highlighting works through the
protocol layers.

## Web UI specifics

- **templ + Datastar only** (no HTMX — removed deliberately). Datastar v0.21.4 is
  vendored at `cmd/visualise/static/datastar.js`.
- **Use v0.21 expression syntax, not v1.0.** Signals are `name.value` (not
  `$name`); the only backend action is `sse(url, {method, contentType})` (no
  `@get`/`@post`). With v1.0 syntax the page throws `$x is not defined` on load, which
  kills every binding on the page. Upgrading datastar.js means rewriting all
  expressions *and* the SSE event format in `mergeResult`.
- Sample-switch/upload use `sse('/view?…')` and
  `sse('/upload', {method:'post', contentType:'form'})`. The server replies with a `text/event-stream`
  containing one `event: datastar-merge-fragments` + `data: fragments <html>`
  lines — see `mergeResult` in `main.go`. `Result` renders `<div id="result">`,
  which Datastar morphs by id.
- Signals live on `<main data-signals="{o,l,sample}">` (persists across merges).
  Tree rows set `o.value/l.value` on mouseenter; each hex byte has
  `data-class="{hl: N >= o.value && N < o.value + l.value}"`.
- templ may HTML-escape attribute values (`'`→`&#39;`, `<`→`&lt;`; v0.2 did,
  v0.3 emits static attributes verbatim). Either is fine — the browser decodes
  entities before Datastar reads them. Do not "fix" the entities.

## Conventions

- **Test data only.** DNS target is `example.com`; IPs are RFC 5737 doc ranges
  (`198.51.100.0/24`, `203.0.113.0/24`). Keep new examples synthetic — this tool
  is for format/QA work, never real intercept targets.
- Output is a faithful, representative file from the public modules — not claimed
  byte-identical to a vendor profile. If given a reference capture or exact ASN.1,
  align to it and say so.

## Extending

- **New payload/content type**: add a builder path in `etsi.go` (watch the
  implicit-vs-CExplicit rule) and a matching annotate branch + enum map in
  `annotate.go`, plus a description in `fieldinfo.go` (`fieldNotes` for ASN.1
  fields, `protoNotes` for decoded packet bytes). Keep them in sync —
  `go test ./internal/etsi` fails if any node in the samples lacks a description.
- **Aggregated payloads in one PS-PDU** (clause 6.2.3): several IRI records, *or*
  several CC payloads, can share a PDU — `iRIPayloadSequence`/`cCPayloadSequence`
  are `SEQUENCE OF`, so append items inside the context-tagged container.
  IRI and CC can **not** share a PS-PDU: `payload` is a CHOICE, so a PDU holds
  exactly one of iRIPayloadSequence / cCPayloadSequence / tRIPayload. Send IRI
  and CC as separate PDUs with the same LIID and CIN.
- **Other QTYPE / target / metadata**: `etsi.DefaultScenario` / `etsi.DefaultMeta`.

## Verify after any encoder change

```bash
openssl asn1parse -inform DER -in samples/dns-request-cc.etsi   # must exit 0, tags as expected
```

`go run ./cmd/gen` round-trips (encode→parse→annotate) and prints the tree — eyeball
it. The CC file's `iPPackets` should also open cleanly in Wireshark (checksums are real).

## Environment / toolchain gotchas (restricted sandboxes)

These bit me in the build sandbox; a normal dev machine won't hit them, but note:

- The agent proxy **blocks jsdelivr and `proxy.golang.org`**. Don't depend on JS
  CDNs at build time or on the Go module proxy. Use `GOPROXY=direct GOSUMDB=off`
  (fetches via git/GitHub). The npm registry *is* reachable — `datastar.js` was
  vendored via `npm pack @starfederation/datastar` (dist/datastar.js).
- Installing the full **templ CLI** fails in such sandboxes: its LSP command pulls
  vanity-host deps (`golang.org/x/tools`, `go.uber.org/zap`, `go.lsp.dev/*`) that
  are blocked. The templ *runtime* and `generator`/`parser/v2` packages are fine.
  Regenerate templates on a normal network, or rely on the committed
  `*_templ.go`. (A ~30-line generator over `templ/generator` + `parser/v2` works
  but still needs `github.com/a-h/parse`, so it isn't fully offline either.)
