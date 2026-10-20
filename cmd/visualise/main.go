// Command visualise serves a Datastar + a-h/templ web UI that decodes an ETSI
// TS 102 232 handover file and shows its nested PDUs (PS-PDU → payload → IPCC /
// IPIRIOnly / IPMMCC / IPMMIRI → IPv4 · UDP/TCP · DNS/HTTP/SIP/RTP) as an
// expandable tree cross-linked to a hex view. It ships nine built-in samples
// (DNS, HTTP and VoIP) and accepts uploads.
//
//	go run ./cmd/visualise            # then open http://localhost:8080
//	go run ./cmd/visualise -addr :9000
package main

import (
	"bytes"
	"context"
	"embed"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"evis/internal/etsi"
)

//go:embed static/*
var staticFS embed.FS

func main() {
	addr := flag.String("addr", ":9990", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/view", handleView)
	mux.HandleFunc("/upload", handleUpload)

	log.Printf("ETSI PDU visualiser on http://localhost%s", normaliseAddr(*addr))
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func sampleView(which string) View {
	m, s := etsi.DefaultMeta(), etsi.DefaultScenario()
	hm, hs := etsi.DefaultHTTPMeta(), etsi.DefaultHTTPScenario()
	vm, vs := etsi.DefaultVoIPMeta(), etsi.DefaultVoIPScenario()
	switch which {
	case "http-exchange":
		return buildView("sample · HTTP exchange (request + gzip response over several segments)", which,
			etsi.BuildHTTPExchange(hm, hs, etsi.DefaultHTTPExchange(hm)))
	case "http-reordered":
		return buildView("sample · HTTP exchange, reordered + retransmission", which,
			etsi.BuildHTTPExchange(hm, hs, etsi.ReorderedHTTPExchange(hm)))
	case "voip-iri":
		return buildView("sample · VoIP IRI (IPMMIRI / SIP INVITE)", which, etsi.BuildSIPIRI(vm, vs))
	case "voip-cc":
		return buildView("sample · VoIP CC (IPMMCC / RTP, three PS-PDUs)", which, etsi.BuildVoIPCC(vm, vs))
	case "voip-both":
		return buildView("sample · VoIP IRI + CC (four PS-PDUs)", which, etsi.BuildVoIPIRIAndCC(vm, vs))
	case "http-cc":
		return buildView("sample · HTTP CC (IPCC / iPPackets)", which, etsi.BuildHTTPCC(hm, hs))
	case "http-iri":
		return buildView("sample · HTTP IRI-only (IPIRIOnly)", which, etsi.BuildHTTPIRIOnly(hm, hs))
	case "http-both":
		return buildView("sample · HTTP IRI + CC (two PS-PDUs)", which, etsi.BuildHTTPIRIAndCC(hm, hs))
	case "iri":
		return buildView("sample · DNS IRI-only (IPIRIOnly)", "iri", etsi.BuildIRIOnly(m, s))
	case "both":
		return buildView("sample · DNS IRI + CC (two PS-PDUs)", "both", etsi.BuildIRIAndCC(m, s))
	default:
		return buildView("sample · DNS CC (IPCC / iPPackets)", "cc", etsi.BuildCC(m, s))
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Page(sampleView("cc")).Render(r.Context(), w)
}

func handleView(w http.ResponseWriter, r *http.Request) {
	v := sampleView(r.URL.Query().Get("sample"))
	mergeResult(w, r.Context(), v)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	var v View
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		v = errorView("could not read upload: " + err.Error())
	} else if f, hdr, err := r.FormFile("file"); err != nil {
		v = errorView("no file received")
	} else {
		defer f.Close()
		b, _ := io.ReadAll(io.LimitReader(f, 8<<20))
		v = buildView("upload · "+hdr.Filename, "", b)
	}
	mergeResult(w, r.Context(), v)
}

func errorView(msg string) View {
	return View{Source: "upload", Summary: "could not decode", Err: msg}
}

// mergeResult renders the Result fragment and sends it as a Datastar
// merge-fragments SSE event, so the backend action updates #result in place.
func mergeResult(w http.ResponseWriter, ctx context.Context, v View) {
	var buf bytes.Buffer
	if err := Result(v).Render(ctx, &buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	fmt.Fprint(w, "event: datastar-merge-fragments\n")
	for _, line := range strings.Split(buf.String(), "\n") {
		fmt.Fprintf(w, "data: fragments %s\n", line)
	}
	fmt.Fprint(w, "\n")
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
}

func normaliseAddr(a string) string {
	if strings.HasPrefix(a, ":") {
		return a
	}
	return ":" + a
}
