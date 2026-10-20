.PHONY: gen run templ build clean

gen:        ## generate the sample .etsi files + hex dumps
	go run ./cmd/gen -out samples

run:        ## start the web visualiser on :8080
	go run ./cmd/visualise

templ:      ## regenerate *_templ.go from *.templ (needs the templ CLI)
	go run github.com/a-h/templ/cmd/templ@latest generate

build:
	go build ./...

clean:
	rm -f samples/*.etsi samples/*.hex
