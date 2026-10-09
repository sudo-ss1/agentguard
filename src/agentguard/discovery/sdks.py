"""LLM SDK imports and model names in source and config files.

SDKs are found by import statements (Python, JavaScript, TypeScript) and `package.json`
dependencies. Model names are a heuristic: quoted or assigned strings shaped like model ids.
A candidate that a secret rule matches is dropped.
"""

import json
import re
from pathlib import PurePath

from agentguard.guards.secrets import SecretScanner

CODE_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})
CONFIG_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".toml", ".env"})

_PY_IMPORT = re.compile(
    r"^[ \t]*(?:from|import)[ \t]+("
    r"google\.genai|google\.generativeai|langchain\w*|langgraph|anthropic|openai|ollama|"
    r"litellm|mistralai|cohere|mcp)\b",
    re.MULTILINE,
)
JS_PACKAGES = (
    "@anthropic-ai/sdk",
    "@anthropic-ai/claude-agent-sdk",
    "openai",
    "@google/genai",
    "@google/generative-ai",
    "@modelcontextprotocol/sdk",
    "@mistralai/mistralai",
    "cohere-ai",
    "ollama",
    "langchain",
    "ai",
)
_JS_IMPORT = re.compile(
    r"""(?:from\s+|require\(\s*|import\(\s*)["']((?:@langchain/[\w.-]+)|"""
    + "|".join(re.escape(p) for p in JS_PACKAGES)
    + r""")(?:/[\w./-]*)?["']"""
)
_MODEL = re.compile(
    r"""(?:["'`=:\s])("""
    r"claude-[a-z0-9][a-z0-9.-]{1,40}|gpt-[0-9a-z][a-z0-9.-]{0,30}|"
    r"gemini-[0-9a-z][a-z0-9.-]{1,30}|"
    r"(?:qwen|llama|mistral|gemma|phi|deepseek)[0-9a-z.-]*:[a-z0-9.-]{1,30}"
    r""")(?=["'`\s,]|$)""",
    re.IGNORECASE | re.MULTILINE,
)


def sdks_in(rel: str, text: str) -> set[str]:
    path = PurePath(rel)
    if path.suffix == ".py":
        return set(_PY_IMPORT.findall(text))
    if path.suffix in CODE_SUFFIXES:
        return set(_JS_IMPORT.findall(text))
    if path.name == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return set()
        deps: set[str] = set()
        for field in ("dependencies", "devDependencies", "peerDependencies"):
            section = data.get(field) if isinstance(data, dict) else None
            if isinstance(section, dict):
                deps |= {d for d in section if d in JS_PACKAGES or str(d).startswith("@langchain/")}
        return deps
    return set()


def models_in(rel: str, text: str, scanner: SecretScanner) -> set[str]:
    path = PurePath(rel)
    if path.suffix not in CODE_SUFFIXES | CONFIG_SUFFIXES and path.name != ".env":
        return set()
    return {m for m in _MODEL.findall(text) if not scanner.scan_text(m)}
