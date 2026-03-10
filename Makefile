.PHONY: help dev lint format test e2e audit

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

dev: ## Install all dependencies
	uv sync --all-groups

lint: ## Run linter and type checker
	uv run ruff format --check . && uv run ruff check . && uv run ty check dropkit/

format: ## Auto-format code
	uv run ruff format .

test: ## Run tests
	uv run pytest

e2e: ## Run E2E lifecycle test (creates a real droplet)
	./tests/e2e/test_lifecycle.sh

audit: ## Audit dependencies for vulnerabilities
	uv run pip-audit
