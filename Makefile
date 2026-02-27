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
		echo "Set env vars in $(SETTINGS) as needed:"; \
		echo "  LOGSIFT_GCP_PROJECTS    - comma-separated GCP project IDs"; \
		echo "  KUBECONFIG              - path to kubeconfig (default: ~/.kube/config)"; \
		echo "  LOGSIFT_LOKI_ADDRESS    - Loki base URL (e.g., http://localhost:3100)"; \
		echo "  LOGSIFT_LOKI_TENANT_ID  - X-Scope-OrgID for multi-tenant Loki"; \
		echo "  LOGSIFT_CW_REGION       - AWS region for CloudWatch Logs (e.g., us-east-1)"; \
		echo "  LOGSIFT_CW_PROFILE      - AWS SSO/config profile (optional)"; \
		echo "  LOGSIFT_CW_LOG_GROUP_PREFIX - Default log group prefix (e.g., /ecs/prod/)"; \
	fi
