BINARY  := logsift
BUILDDIR := build
BINPATH  := $(CURDIR)/$(BUILDDIR)/$(BINARY)
SETTINGS := .claude/settings.json

.PHONY: build test setup

build:
	@mkdir -p $(BUILDDIR)
	go build -o $(BINPATH) ./cmd/logsift

test:
	go test ./... -count=1

setup: build
	@mkdir -p .claude
	@if [ ! -f $(SETTINGS) ]; then echo '{}' > $(SETTINGS); fi
	@if jq -e '.mcpServers.logsift' $(SETTINGS) >/dev/null 2>&1; then \
		echo "logsift MCP server already configured in $(SETTINGS)"; \
	else \
		jq --arg bin "$(BINPATH)" '.mcpServers.logsift = {"command": $$bin}' $(SETTINGS) > $(SETTINGS).tmp \
		&& mv $(SETTINGS).tmp $(SETTINGS); \
		echo "Added logsift MCP server to $(SETTINGS)"; \
		echo "Set env vars in $(SETTINGS) as needed:"; \
		echo "  LOGSIFT_GCP_PROJECTS  - comma-separated GCP project IDs"; \
		echo "  KUBECONFIG            - path to kubeconfig (default: ~/.kube/config)"; \
	fi
