.DEFAULT_GOAL := test

Coding/bin/Makefile.base:
	git clone https://github.com/dedis/Coding
include Coding/bin/Makefile.base

test_local:
	go test -v -short ./...

local: test_fmt test_lint test_local
