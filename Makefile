# Linux Hardening Agent -- development entry points.
#
# `make help` lists every target. `make check` runs exactly what CI runs, so a
# green local run means a green pipeline.

.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# Prefer uv when available: it resolves and installs an order of magnitude
# faster than pip, but nothing here depends on it.
UV := $(shell command -v uv 2>/dev/null)
VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
AGENT := $(VENV)/bin/hardening-agent

IMAGE ?= hardening-agent
TAG ?= local
PYTEST_ARGS ?=

# On Windows the venv layout differs; detect and adjust so the same Makefile
# works under Git Bash / WSL and native Linux.
ifeq ($(OS),Windows_NT)
	PYTHON := $(VENV)/Scripts/python.exe
	PIP := $(VENV)/Scripts/pip.exe
	AGENT := $(VENV)/Scripts/hardening-agent.exe
endif

.PHONY: help
help: ## Show this help
	@echo "Linux Hardening Agent"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
.PHONY: install
install: ## Create the venv and install the package with dev extras
ifdef UV
	uv venv $(VENV)
	uv pip install --python $(PYTHON) -e ".[dev]"
else
	python3 -m venv $(VENV) || python -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"
endif
	@echo "Environment ready. Activate with: source $(VENV)/bin/activate"

$(PYTHON):
	@$(MAKE) install

.PHONY: clean
clean: ## Remove build, cache and coverage artefacts
	rm -rf build dist *.egg-info src/*.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov
	rm -f .coverage coverage.xml report.json report.sarif
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.py[co]' -delete 2>/dev/null || true
	@echo "Cleaned."

.PHONY: distclean
distclean: clean ## Also remove the virtualenv
	rm -rf $(VENV)

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------
.PHONY: fmt
fmt: $(PYTHON) ## Format the code with ruff
	$(PYTHON) -m ruff format src tests scripts
	$(PYTHON) -m ruff check --fix src tests scripts

.PHONY: fmt-check
fmt-check: $(PYTHON) ## Verify formatting without modifying files
	$(PYTHON) -m ruff format --check --diff src tests scripts

.PHONY: lint
lint: $(PYTHON) ## Lint with ruff (includes bandit security rules)
	$(PYTHON) -m ruff check src tests scripts

.PHONY: docs
docs: $(PYTHON) ## Regenerate docs/checks.md from the check registry
	$(PYTHON) scripts/generate_check_docs.py

.PHONY: docs-check
docs-check: $(PYTHON) ## Fail if docs/checks.md is out of date
	$(PYTHON) scripts/generate_check_docs.py --check

.PHONY: typecheck
typecheck: $(PYTHON) ## Type-check with mypy --strict
	$(PYTHON) -m mypy src

.PHONY: test
test: $(PYTHON) ## Run the test suite with coverage
	$(PYTHON) -m pytest --cov --cov-report=term-missing --cov-report=xml $(PYTEST_ARGS)

.PHONY: test-fast
test-fast: $(PYTHON) ## Run only the unit tests (no sockets, no subprocesses)
	$(PYTHON) -m pytest -m "not integration" -q $(PYTEST_ARGS)

.PHONY: test-watch
test-watch: $(PYTHON) ## Re-run tests on change (requires pytest-watch)
	$(PYTHON) -m pytest_watch -- -q

.PHONY: check
check: fmt-check lint typecheck docs-check test ## Everything CI runs
	@echo ""
	@echo "All checks passed."

# ---------------------------------------------------------------------------
# Running the agent
# ---------------------------------------------------------------------------
.PHONY: audit
audit: $(PYTHON) ## Run an audit against this machine
	$(AGENT) audit --verbose

.PHONY: audit-json
audit-json: $(PYTHON) ## Run an audit and emit JSON
	$(AGENT) audit --format json --log-level ERROR

.PHONY: checks
checks: $(PYTHON) ## List the check catalogue
	$(AGENT) list-checks

.PHONY: metrics
metrics: $(PYTHON) ## Print the Prometheus exposition output
	$(AGENT) export --stdout --log-level ERROR

.PHONY: serve
serve: $(PYTHON) ## Run the HTTP exporter in the foreground
	$(AGENT) serve --log-format text

.PHONY: dry-run
dry-run: $(PYTHON) ## Show what remediation would change, without changing it
	$(AGENT) remediate --dry-run --verbose

# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------
.PHONY: docker
docker: ## Build the container image
	docker build -t $(IMAGE):$(TAG) .
	@echo ""
	@docker images $(IMAGE):$(TAG) --format 'Image size: {{.Size}}'

.PHONY: docker-size
docker-size: docker ## Build and assert the image is under 200MB
	@size=$$(docker image inspect $(IMAGE):$(TAG) --format '{{.Size}}'); \
	limit=$$((200 * 1000 * 1000)); \
	human=$$(echo "$$size" | awk '{printf "%.1f MB", $$1/1000/1000}'); \
	if [ "$$size" -gt "$$limit" ]; then \
		echo "FAIL: image is $$human, budget is 200 MB"; exit 1; \
	fi; \
	echo "OK: image is $$human (budget 200 MB)"

.PHONY: docker-run
docker-run: docker ## Run the agent container against this host
	docker run --rm -it \
		-p 127.0.0.1:9101:9101 \
		-v /proc:/host/proc:ro \
		-v /sys:/host/sys:ro \
		-v /etc:/host/etc:ro \
		--cap-drop ALL --security-opt no-new-privileges:true \
		$(IMAGE):$(TAG) serve --root /host

.PHONY: docker-scan
docker-scan: docker ## Scan the image with trivy
	trivy image --severity HIGH,CRITICAL --exit-code 1 $(IMAGE):$(TAG)

.PHONY: demo
demo: ## Start the compose stack (agent + Prometheus + node_exporter)
	docker compose up --build -d
	@echo ""
	@echo "  Prometheus     http://localhost:9090"
	@echo "  Agent metrics  http://localhost:9101/metrics"
	@echo "  node_exporter  http://localhost:9100/metrics"
	@echo ""
	@echo "  Stop with: make demo-down"

.PHONY: demo-down
demo-down: ## Stop the compose stack and remove volumes
	docker compose down -v

.PHONY: demo-logs
demo-logs: ## Follow the agent container logs
	docker compose logs -f agent

# ---------------------------------------------------------------------------
# Shell scripts
# ---------------------------------------------------------------------------
.PHONY: shellcheck
shellcheck: ## Lint the shell scripts
	shellcheck --severity=style --external-sources scripts/*.sh scripts/lib/*.sh

.PHONY: preflight
preflight: ## Check whether this host can run the agent
	./scripts/preflight.sh

# ---------------------------------------------------------------------------
# Release
# ---------------------------------------------------------------------------
.PHONY: build
build: $(PYTHON) ## Build the sdist and wheel
	$(PYTHON) -m pip install --quiet build
	$(PYTHON) -m build

.PHONY: version
version: $(PYTHON) ## Print the agent version
	@$(AGENT) --version
