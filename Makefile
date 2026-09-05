.PHONY: help install test lint lint-ruff lint-mypy format format-check preflight preflight-fix docker-build docker-run scan clean build-ui release-build publish-test publish analytics dev check-dupes clean-dupes secrets platform-up fullstack-up

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## Install agent-bom with the full contributor test extras
	pip install -e ".[dev-all]"

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

# Every Python directory that ships or gates a release. `scripts/` was outside
# this set, so a dead local in `generate_doc_architecture_svgs.py` sat on main
# unnoticed — release gates, drift checks and the SVG generators all live there.
# CI's Ruff step calls `lint-ruff` rather than repeating the paths, so the two
# cannot disagree about what gets linted.
LINT_PATHS := src/ tests/ scripts/ fuzz/

lint-ruff:  ## Ruff over every linted path
	ruff check $(LINT_PATHS)

lint-mypy:  ## MyPy over the shipped package
	mypy src/ --ignore-missing-imports --disable-error-code import-untyped

lint: lint-ruff lint-mypy  ## Run linters (ruff + mypy)

format:  ## Format code with ruff
	ruff format $(LINT_PATHS)

format-check:  ## Fail if anything is unformatted (what CI runs)
	ruff format --check $(LINT_PATHS)

preflight:  ## Run the drift gates that CI's "Version Alignment" job runs — do this before pushing a PR
	@echo "→ OpenAPI artifacts (docs/openapi/)";   python scripts/export_openapi.py --check
	@echo "→ v1 schemas (docs/schemas/v1/)";        python scripts/generate_v1_schemas.py --check
	@echo "→ agent capability manifest";             python scripts/generate_agent_capability_manifest.py --check
	@echo "→ documented surface counts";            python scripts/check-counts.py
	@echo "→ product surface contract";             python scripts/check_product_surface_contract.py
	@echo "→ graph proof fixtures";                 python scripts/check_graph_epic_proof.py
	@echo "→ enterprise demo surfaces";             python scripts/check_enterprise_demo_surfaces.py
	@echo "→ release/README consistency";           python scripts/check_release_consistency.py
	@echo "→ release evidence matrix";              python scripts/check_release_evidence_matrix.py
	@echo "→ published counts vs shipped build";    python scripts/check_published_counts.py
	@echo "→ CI pipefail policy";                   python scripts/check_ci_pipefail.py
	@echo "→ product metrics snapshot";             python scripts/product_metrics_snapshot.py --check
	@echo "→ CVE matching accuracy";                python scripts/cve_matching_accuracy.py --check
	@echo "→ env-var reference";                    python scripts/generate_env_var_reference.py --check
	@echo "→ SDK patterns.json";                    python sdks/shared/generate-patterns.py --check
	@echo "→ documentation SVGs";                    python scripts/generate_doc_architecture_svgs.py --check
	@echo "→ blast-radius SVGs";                     python scripts/generate_blast_radius_svgs.py --check
	@echo "✓ preflight passed — CI's Version Alignment gate will be green (run 'make lint' separately for ruff/mypy)"

preflight-fix:  ## Regenerate every drift artifact so you never push stale OpenAPI/schemas/patterns; then review + commit
	python scripts/export_openapi.py
	python scripts/generate_v1_schemas.py
	python scripts/generate_env_var_reference.py
	python sdks/shared/generate-patterns.py
	python scripts/product_metrics_snapshot.py --write
	@echo "✓ regenerated — run 'git status', review, and commit the artifacts"

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

secrets:  ## Generate the mounted Docker secret files (idempotent; run before platform/fullstack up)
	python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose

platform-up: secrets  ## Bring up the production-shaped platform stack (generates secrets first)
	docker compose -f deploy/docker-compose.platform.yml up --build -d

fullstack-up: secrets  ## Bring up the dev full-stack (API + UI + Postgres); generates secrets first
	docker compose -f deploy/docker-compose.fullstack.yml up --build -d

build-ui:  ## Build Next.js dashboard and bundle into package
	bash scripts/build-ui.sh

release-build: build-ui  ## Build and verify release artifacts with the bundled dashboard
	rm -rf dist/
	uv build
	uv run python scripts/verify_release_wheel.py dist

check-dupes:  ## Detect Finder-style duplicate files (incl. untracked) in the working tree
	python3 scripts/check_duplicate_artifacts.py --working-tree

clean-dupes:  ## Delete untracked Finder-style duplicates (e.g. 'foo 2.py'); tracked files are never removed
	@python3 scripts/check_duplicate_artifacts.py --working-tree 2>&1 | sed -n 's/^- //p' | while IFS= read -r f; do \
		if [ -n "$$f" ] && [ -z "$$(git ls-files -- "$$f")" ]; then echo "removing $$f"; rm -rf -- "$$f"; fi; \
	done; echo "✓ untracked duplicates removed (tracked files untouched)"

clean:  ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	rm -f report.json ai-bom*.json *.cdx.json

publish-test: release-build  ## Publish verified artifacts to TestPyPI
	twine upload --repository testpypi dist/*

publish: release-build  ## Publish verified artifacts to PyPI
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
