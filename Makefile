.PHONY: up down test attack attack-docker attack-llm bench lint lock hooks

TRIALS ?= 5

up:            ## build and start the Docker lab (with COMPOSE_PROFILES=local-ollama, also Ollama)
	docker compose up -d --build

down:
	docker compose down

test:          ## unit tests + attack tests in both modes
	AGENTGUARD_MODE=baseline uv run pytest
	AGENTGUARD_MODE=guarded uv run pytest tests/attacks

attack:        ## scripted attacks against a local lab, both modes; prints the results tables
	AGENTGUARD_MODE=baseline uv run agentguard attack --local
	AGENTGUARD_MODE=guarded uv run agentguard attack --local

SCENARIOS ?= 1 2 3 4 5 6 7

attack-docker: ## scripted attacks in the Docker lab (guarded), one scenario at a time
	@# Guard state (taint, budgets, kill list) is on the gateway-only volume, so it is reset
	@# from the host before each scenario; the agent container has no way to reset it.
	@for n in $(SCENARIOS); do \
		docker compose exec -T gateway agentguard guards reset || exit 1; \
		AGENTGUARD_MODE=guarded docker compose run --rm -T agent agentguard attack --scenario $$n || exit 1; \
	done

attack-llm:    ## scripted + LLM attacks inside the Docker lab (AGENTGUARD_MODE picks the stack)
	docker compose exec gateway agentguard guards reset   # revive agents, clear budgets/taint
	docker compose run --rm agent agentguard attack --llm --trials $(TRIALS)

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
