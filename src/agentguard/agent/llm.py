"""Chat model factory. Ollama by default; set LLM_PROVIDER=anthropic to swap in Claude."""

from langchain_core.language_models import BaseChatModel

from agentguard.settings import Settings


def get_chat_model(settings: Settings) -> BaseChatModel:
    if settings.llm_provider == "anthropic":
        from langchain_anthropic import ChatAnthropic  # optional extra: agentguard[anthropic]

        return ChatAnthropic(model=settings.anthropic_model, temperature=0)  # type: ignore[call-arg]

    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=settings.ollama_model,
        base_url=settings.ollama_base_url,
        temperature=0,
        seed=settings.llm_seed,
        num_ctx=settings.llm_num_ctx,
        # Without a timeout, a request the server drops (e.g. it restarts) hangs the run forever.
        client_kwargs={"timeout": settings.llm_timeout_s},
    )
