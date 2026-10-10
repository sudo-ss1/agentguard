.PHONY: up down test attack attack-docker attack-llm bench lint lock hooks dashboard-docker

TRIALS ?= 5

up:            ## build and start the Docker lab (with COMPOSE_PROFILES=local-ollama, also Ollama)
	@# The agent (harness) image is behind the `agent` profile, so `up` alone never rebuilds it:
	@# a stale one once ran attack 8's old stub and skipped it. Build every image first.
	docker compose --profile agent build
	docker compose up -d

down:
	docker compose down

test:          ## unit tests + attack tests in both modes
	AGENTGUARD_MODE=baseline uv run pytest
	AGENTGUARD_MODE=guarded uv run pytest tests/attacks

attack:        ## scripted attacks against a local lab, both modes; prints the results tables
	AGENTGUARD_MODE=baseline uv run agentguard attack --local
	AGENTGUARD_MODE=guarded uv run agentguard attack --local

# The host's phase, and the scenarios available at it, from the code: a Docker run is checked
# against these, not against whatever (possibly stale) code is inside the image.
PHASE := $(shell uv run --quiet python -c "import agentguard; print(agentguard.CURRENT_PHASE)")
SCENARIOS ?= $(shell uv run --quiet python -c "from agentguard.attacks import load_all; \
	from agentguard import CURRENT_PHASE as p; print(*[s.id for s in load_all() if s.available_from_phase <= p])")

attack-docker: ## scripted attacks in the Docker lab (guarded), one scenario at a time
	@# The harness image is rebuilt first (cached, so quick): an image built from older code
	@# runs older scenarios and harness code, and can pass for current.
	docker compose --profile agent build agent
	@# Guard state (taint, budgets, kill list) is on the gateway-only volume, so it is reset
	@# from the host before each scenario; the agent container has no way to reset it.
	@for n in $(SCENARIOS); do \
		docker compose exec -T gateway agentguard guards reset || exit 1; \
		AGENTGUARD_MODE=guarded docker compose run --rm -T agent \
			agentguard attack --scenario $$n --expect-phase $(PHASE) || exit 1; \
	done

attack-llm:    ## scripted + LLM attacks inside the Docker lab (AGENTGUARD_MODE picks the stack)
	docker compose --profile agent build agent
	docker compose exec gateway agentguard guards reset   # revive agents, clear budgets/taint
	docker compose run --rm agent agentguard attack --llm --trials $(TRIALS) --expect-phase $(PHASE)

bench:         ## per-call latency direct vs through the gateway
	uv run python bench/latency.py --out bench/baseline.json
	uv run python bench/latency.py --guarded --out bench/gateway.json --compare bench/baseline.json

lint:
	uv run ruff check src tests bench
	uv run ruff format --check src tests bench
	uv run mypy src

lock:          ## refresh the pinned requirements used by the Docker image
	uv pip compile pyproject.toml -o requirements.lock

hooks:         ## install the pre-commit hook (lint + unit tests must pass to commit)
	git config core.hooksPath .githooks

DASH_DIR := run-logs/dashboard-docker/$(shell date +%Y%m%d-%H%M%S)

dashboard-docker: ## view-only dashboard on 127.0.0.1, from a read-only snapshot of the Docker lab
	@# `docker compose cp` only reads from the gateway container; the lab is never written.
	@# The snapshot's public key comes from the same lab: pin one out of band for a real audit.
	mkdir -p $(DASH_DIR)
	docker compose cp gateway:/ledger/receipts.jsonl $(DASH_DIR)/receipts.jsonl
	docker compose cp gateway:/ledger-roots/checkpoints.jsonl $(DASH_DIR)/checkpoints.jsonl
	docker compose cp gateway:/ledger-roots/ledger-key.pub.json $(DASH_DIR)/ledger-key.pub.json
	docker compose cp gateway:/gateway-pins/pins.json $(DASH_DIR)/pins.json
	uv run agentguard scan --agents config/inventory.yaml --out $(DASH_DIR)/inventory.json \
		|| [ $$? -le 3 ]  # 1 = credentials found, 3 = something not scanned: still an inventory
	uv run --extra dashboard agentguard dashboard --receipts $(DASH_DIR)/receipts.jsonl \
		--public-key $(DASH_DIR)/ledger-key.pub.json --checkpoints $(DASH_DIR)/checkpoints.jsonl \
		--pins $(DASH_DIR)/pins.json --inventory $(DASH_DIR)/inventory.json
