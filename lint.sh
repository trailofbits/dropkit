#!/bin/bash
# Run linters and formatters

set -e

echo "Running ruff format..."
uv run ruff format .

echo ""
echo "Running ruff check..."
uv run ruff check .

echo ""
echo "Running ty..."
uv run ty check tobcloud/

echo ""
echo "✓ All linting passed!"
