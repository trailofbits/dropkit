.PHONY: help dev lint format test audit

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

dev: ## Install all dependencies
	uv sync --all-groups

lint: ## Run linter and type checker
	uv run ruff format --check . && uv run ruff check . && uv run ty check dropkit/

format: ## Auto-format code
	uv run ruff format .

test: ## Run tests
	uv run pytest

audit: ## Audit dependencies for vulnerabilities
	uv run pip-audit
