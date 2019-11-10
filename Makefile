.DEFAULT_GOAL := all

EXCLUDE_LINT = "_test.go"

test_fmt:
	@echo Checking correct formatting of files
	@{ \
		files=$$( go fmt ./... ); \
		if [ -n "$$files" ]; then \
		echo "Files not properly formatted: $$files"; \
		exit 1; \
		fi; \
		if ! go vet ./...; then \
		exit 1; \
		fi \
	}

test_lint:
	@echo Checking linting of files
	@{ \
		GO111MODULE=off go get -u golang.org/x/lint/golint; \
		el=$(EXCLUDE_LINT); \
		lintfiles=$$( golint ./... | egrep -v "$$el" ); \
		if [ -n "$$lintfiles" ]; then \
		echo "Lint errors:"; \
		echo "$$lintfiles"; \
		exit 1; \
		fi \
	}

test_local:
	go test -v -race -short -p=1 ./...

test_codecov:
	./coveralls.sh

test: test_fmt test_lint test_codecov

local: test_fmt test_lint test_local


private go-cmds := client server

define go-cmd-build =
cmd/$1/$1: cmd/$1/*.go $(wildcard */*.go */*/*.go)
	go build -o $$@ ./$$(<D)
endef
$(foreach c,$(go-cmds),$(eval $(call go-cmd-build,$c)))

.PHONY: all
all: $(foreach c,$(go-cmds),cmd/$c/$c)
