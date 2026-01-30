.PHONY: dev lint format test audit

dev:
	uv sync --all-groups

lint:
	uv run ruff format --check . && uv run ruff check . && uv run ty check dropkit/

format:
	uv run ruff format .

test:
	uv run pytest

audit:
	uv run pip-audit
