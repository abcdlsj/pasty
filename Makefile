.DEFAULT: help

help:
	@echo "Commands:"
	@echo "  build"
	@echo "  install"

.PHONY: build
build: 
	go build -o pasty


.PHONY: install
install: build
	rm ${GOPATH}/bin/pasty 2> /dev/null || true
	mv pasty ${GOPATH}/bin/