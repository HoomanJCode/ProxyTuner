.PHONY: install install-dev test lint format typecheck build clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the package
	pip install .

install-dev: ## Install with dev dependencies
	pip install -e ".[dev]"

test: ## Run all tests
	python -m pytest tests/ -v

test-fast: ## Run tests without verbose output
	python -m pytest tests/ -q

lint: ## Run linter
	ruff check src/ tests/

format: ## Format code
	ruff format src/ tests/

typecheck: ## Run type checker
	mypy src/proxy_tuner/ --ignore-missing-imports

build: ## Build package
	python -m build

clean: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

check: lint typecheck test ## Run all checks (lint + typecheck + test)

release: clean build ## Build for release
	@echo "Ready to upload: twine upload dist/*"
