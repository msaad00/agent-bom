.PHONY: help install test lint docker-build docker-run scan clean build-ui

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## Install agent-bom in development mode
	pip install -e ".[dev]"

test:  ## Run unit tests
	pytest tests/ -v --cov=agent_bom

lint:  ## Run linters (ruff + mypy)
	ruff check src/ tests/
	mypy src/ --ignore-missing-imports

format:  ## Format code with ruff
	ruff format src/ tests/

docker-build:  ## Build Docker image
	docker build -t agent-bom:latest .

docker-run:  ## Run agent-bom in Docker container
	docker run --rm \
		-v $(PWD):/workspace \
		-v ~/.config:/root/.config:ro \
		agent-bom:latest scan --help

scan:  ## Run local scan with enrichment
	agent-bom scan --enrich --format json --output report.json

scan-transitive:  ## Run scan with transitive dependencies
	agent-bom scan --enrich --transitive --max-depth 3 --output report.json

e2e-test:  ## Run end-to-end tests
	chmod +x test_e2e.sh
	./test_e2e.sh

docker-compose-up:  ## Start Docker Compose services
	docker-compose up -d

docker-compose-down:  ## Stop Docker Compose services
	docker-compose down -v

build-ui:  ## Build Next.js dashboard and bundle into package
	bash scripts/build-ui.sh

clean:  ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	rm -f report.json ai-bom*.json *.cdx.json

publish-test:  ## Publish to TestPyPI
	python -m build
	twine upload --repository testpypi dist/*

publish:  ## Publish to PyPI
	python -m build
	twine upload dist/*

version:  ## Show agent-bom version
	agent-bom --version

demo:  ## Run demo scan
	@echo "Running demo scan..."
	agent-bom scan --enrich --format console
	@echo ""
	@echo "JSON output:"
	agent-bom scan --enrich --format json --output demo.json
	@cat demo.json | python -m json.tool | head -50

# Git workflow commands
git-feature:  ## Create new feature branch (usage: make git-feature name=my-feature)
	@if [ -z "$(name)" ]; then \
		echo "Error: Please provide branch name: make git-feature name=my-feature"; \
		exit 1; \
	fi
	git checkout main
	git pull origin main
	git checkout -b feature/$(name)
	@echo "✓ Created and switched to feature/$(name)"

git-pr:  ## Create pull request for current branch
	gh pr create --fill --base main

git-sync:  ## Sync main branch with remote
	git checkout main
	git pull origin main
	@echo "✓ main branch updated"

git-cleanup:  ## Delete merged feature branches
	git branch --merged main | grep -v "^\* main" | xargs -n 1 git branch -d || true
	@echo "✓ Cleaned up merged branches"

git-status:  ## Show git status and current branch
	@echo "Current branch:"
	@git branch --show-current
	@echo ""
	@git status
