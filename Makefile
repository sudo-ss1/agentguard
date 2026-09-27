.PHONY: up down test attack attack-llm bench lint lock

TRIALS ?= 5

up:            ## start the lab stack (pulls the Ollama model on first run)
	docker compose up -d --build

down:
	docker compose down

test:          ## unit tests + attack tests in both modes
	AGENTGUARD_MODE=baseline uv run pytest
	AGENTGUARD_MODE=guarded uv run pytest tests/attacks

attack:        ## scripted attacks against a local lab, both modes; prints the results tables
	AGENTGUARD_MODE=baseline uv run agentguard attack --local
	AGENTGUARD_MODE=guarded uv run agentguard attack --local

attack-llm:    ## scripted + LLM attacks inside the Docker lab (AGENTGUARD_MODE picks the stack)
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
