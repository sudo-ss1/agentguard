.PHONY: up down test attack attack-docker attack-llm bench lint lock hooks

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
	@# Guard state (taint, budgets, kill list) is on the gateway-only volume, so it is reset
	@# from the host before each scenario; the agent container has no way to reset it.
	@for n in $(SCENARIOS); do \
		docker compose exec -T gateway agentguard guards reset || exit 1; \
		AGENTGUARD_MODE=guarded docker compose run --rm -T agent \
			agentguard attack --scenario $$n --expect-phase $(PHASE) || exit 1; \
	done

attack-llm:    ## scripted + LLM attacks inside the Docker lab (AGENTGUARD_MODE picks the stack)
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
