.DEFAULT_GOAL := all

Coding/bin/Makefile.base:
	git clone https://github.com/dedis/Coding
include Coding/bin/Makefile.base

.PHONY: local test_codecov test_local
local: test_fmt test_lint test_verbose
test_codecov: test_goveralls
test_local: test_verbose

private go-cmds := client server
define go-cmd-build =
cmd/$1/$1: cmd/$1/*.go $(wildcard */*.go */*/*.go */*/*/*.go)
	go build -o $$@ ./$$(<D)
endef
$(foreach c,$(go-cmds),$(eval $(call go-cmd-build,$c)))

.PHONY: all
all: $(foreach c,$(go-cmds),cmd/$c/$c)
