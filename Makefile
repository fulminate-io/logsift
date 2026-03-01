BINARY  := logsift
BUILDDIR := build
BINPATH  := $(CURDIR)/$(BUILDDIR)/$(BINARY)
SETTINGS := $(HOME)/.claude.json
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test setup

build:
	@mkdir -p $(BUILDDIR)
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINPATH) ./cmd/logsift

test:
	go test ./... -count=1

setup: build
	@if [ ! -f $(SETTINGS) ]; then echo '{}' > $(SETTINGS); fi
	@if jq -e '.mcpServers.logsift' $(SETTINGS) >/dev/null 2>&1; then \
		echo "logsift MCP server already configured in $(SETTINGS)"; \
	else \
		jq --arg bin "$(BINPATH)" '.mcpServers.logsift = {"command": $$bin}' $(SETTINGS) > $(SETTINGS).tmp \
		&& mv $(SETTINGS).tmp $(SETTINGS); \
		echo "Added logsift MCP server to $(SETTINGS)"; \
		echo ""; \
		echo "logsift reads env vars from your shell automatically (e.g., AWS_PROFILE, DD_API_KEY)."; \
		echo "No extra configuration needed if your env vars are already set."; \
		echo "See README.md for the full list of supported env vars."; \
	fi
