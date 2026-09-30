"""Runtime settings, read from environment variables (see .env.example)."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    agentguard_mode: Literal["baseline", "guarded"] = "baseline"
    # Defaults to config/agent.<mode>.yaml: baseline talks to the tools, guarded to the gateway.
    agentguard_config: Path | None = None

    llm_provider: Literal["ollama", "anthropic"] = "ollama"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b-instruct"
    anthropic_model: str = "claude-sonnet-5"
    llm_seed: int = 7
    llm_timeout_s: float = 300  # per model request
    llm_num_ctx: int = 8192  # pinned context length (Ollama's default depends on the server)

    # Lab state: the files server sees LAB_ROOT as "/", the email stub writes OUTBOX_PATH.
    lab_root: Path = Path(".lab-state/rootfs")
    outbox_path: Path = Path(".lab-state/outbox.jsonl")
    receipts_path: Path = Path(".lab-state/receipts.jsonl")
    # Docker lab: the ledger's checkpoints and exported public key (read-only for the harness).
    ledger_roots_dir: Path = Path(".lab-state/ledger-roots")
    guard_state_dir: Path = Path(".lab-state/guards")  # the gateway's kill list and reset epoch
    credentials_dir: Path = Path(".lab-state/agent-creds")  # Docker lab: from `provision`
    # `agentguard attack` on a local lab keeps each run's gateway decision log (and per-trial
    # index) in <run_log_dir>/<timestamp>/. Tests and the bench use a temporary folder instead.
    run_log_dir: Path = Path("run-logs")
    rug_pull_settle_s: float = 3.0  # > the Docker gateway's refresh_interval_s
    rugpull_flag: Path = Path(
        ".lab-state/rugpull.flag"
    )  # weather server rug-pulls once this exists
    evil_site: str = "http://evil.test"

    @property
    def agent_config_path(self) -> Path:
        return self.agentguard_config or Path(f"config/agent.{self.agentguard_mode}.yaml")


@lru_cache
def get_settings() -> Settings:
    return Settings()
