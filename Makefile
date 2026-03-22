.PHONY: help install test lint docker-build docker-run scan clean build-ui analytics dev

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## Install agent-bom in development mode
	pip install -e ".[dev]"

install-all:  ## Install agent-bom with all development extras
	pip install -e ".[dev-all]"

dev:  ## Start API server + Next.js dashboard for development
	@echo "Starting API server on :8422 and dashboard on :3000..."
	@echo "  API docs  → http://localhost:8422/docs"
	@echo "  Dashboard → http://localhost:3000"
	@echo "  Press Ctrl+C to stop."
	@$(MAKE) -j2 _dev-api _dev-ui

_dev-api:
	@python -m agent_bom.cli._entry serve --port 8422 --cors-allow-all --reload 2>&1

_dev-ui:
	@cd ui && npm run dev 2>&1

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
	docker-compose -f deploy/docker-compose.yml up -d

docker-compose-down:  ## Stop Docker Compose services
	docker-compose -f deploy/docker-compose.yml down -v

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

analytics:  ## Show adoption metrics (PyPI downloads, GitHub traffic, stars)
	@echo "=== PyPI downloads (recent) ==="
	@curl -sf "https://pypistats.org/api/packages/agent-bom/recent" 2>/dev/null \
		| python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(f\"  Last day:   {d['last_day']:>8,}\n  Last week:  {d['last_week']:>8,}\n  Last month: {d['last_month']:>8,}\")" \
		|| echo "  (pypistats rate-limited — try again in 60s)"
	@echo ""
	@echo "=== PyPI downloads by Python version ==="
	@curl -sf "https://pypistats.org/api/packages/agent-bom/python_minor" 2>/dev/null \
		| python3 -c "import json,sys; d=json.load(sys.stdin)['data']; [print(f\"  Python {r['category']:6} {r['downloads']:>8,}\") for r in sorted(d, key=lambda x: x['downloads'], reverse=True)[:8] if r['category'] and r['category'] != 'null']" \
		|| echo "  (pypistats rate-limited)"
	@echo ""
	@echo "=== GitHub traffic (last 14 days) ==="
	@gh api /repos/msaad00/agent-bom/traffic/views 2>/dev/null \
		| python3 -c "import json,sys; d=json.load(sys.stdin); print(f\"  Views:  {d['count']:>8,}  unique: {d['uniques']:,}\")" \
		|| echo "  (requires repo write access)"
	@gh api /repos/msaad00/agent-bom/traffic/clones 2>/dev/null \
		| python3 -c "import json,sys; d=json.load(sys.stdin); print(f\"  Clones: {d['count']:>8,}  unique: {d['uniques']:,}\")" \
		|| true
	@echo ""
	@echo "=== GitHub stars & forks ==="
	@gh api /repos/msaad00/agent-bom --jq '"  Stars: " + (.stargazers_count|tostring) + "   Forks: " + (.forks_count|tostring)' 2>/dev/null || true
