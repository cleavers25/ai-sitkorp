"""Provider-agnostic chat adapters (PRD 15-16).

Each adapter speaks its provider's native message format. The engine keeps the native transcript
per turn and replays it unchanged, so tool calls/results (and Claude thinking blocks) stay
append-only across turns.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

import anthropic
import openai

from app.ai.tools import ToolDef
from app.core.enums import AIProviderKind
from app.core.redaction import redact_text

# Claude models where the server-side refusal fallback is recommended by default.
ANTHROPIC_FALLBACK_MODELS = {"claude-opus-5", "claude-fable-5-1"}
ANTHROPIC_FALLBACK_BETA = "server-side-fallback-2026-07-01"
REQUEST_TIMEOUT = 120.0


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: Any  # parsed JSON (dict) or the raw string when unparseable


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall]
    native: list[dict]  # native messages to append to history (the assistant message)
    stop: str | None
    usage: dict = field(default_factory=dict)
    model: str | None = None


class ProviderError(Exception):
    """A provider failure with a message safe to show to users (never contains the key)."""


class ChatProvider(Protocol):
    key: str

    def user_message(self, text: str) -> dict: ...
    def assistant_text(self, text: str) -> dict: ...
    def tool_results(self, results: list[tuple[ToolCall, str, bool]]) -> list[dict]: ...
    def complete(self, system: list[str], history: list[dict], tools: list[ToolDef]) -> Turn: ...


# --- OpenAI / OpenAI-compatible ------------------------------------------------

class OpenAICompatibleProvider:
    def __init__(self, model: str, api_key: str | None, base_url: str | None, max_tokens: int,
                 temperature: float | None, http_client=None):
        self.model = model
        self.official = not base_url
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.key = f"openai:{base_url or 'api.openai.com'}:{model}"
        self.client = openai.OpenAI(api_key=api_key or "not-needed", base_url=base_url or None,
                                    timeout=REQUEST_TIMEOUT, max_retries=2, http_client=http_client)

    def user_message(self, text: str) -> dict:
        return {"role": "user", "content": text}

    def assistant_text(self, text: str) -> dict:
        return {"role": "assistant", "content": text}

    def tool_results(self, results):
        return [{"role": "tool", "tool_call_id": call.id, "content": text} for call, text, _ in results]

    def complete(self, system, history, tools) -> Turn:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": s} for s in system] + history,
        }
        if tools:  # an empty tools array is rejected by OpenAI
            kwargs["tools"] = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                                 "parameters": t.parameters}} for t in tools]
        # api.openai.com expects max_completion_tokens; many compatible servers only know max_tokens.
        kwargs["max_completion_tokens" if self.official else "max_tokens"] = self.max_tokens
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        try:
            resp = self.client.chat.completions.create(**kwargs)
        except openai.AuthenticationError as exc:
            raise ProviderError(f"API key ditolak oleh provider (401): {_short(exc)} "
                                "Periksa key, dan pastikan key berasal dari region/endpoint yang sama dengan Base URL.")
        except openai.PermissionDeniedError as exc:
            raise ProviderError(f"API key tidak punya izin untuk model ini (403): {_short(exc)}")
        except openai.NotFoundError as exc:
            raise ProviderError(f"Model '{self.model}' atau endpoint tidak ditemukan (404): {_short(exc)}")
        except openai.RateLimitError:
            raise ProviderError("Kena rate limit / kuota provider habis (429). Coba lagi nanti.")
        except openai.BadRequestError as exc:
            raise ProviderError(f"Request ditolak provider (400): {_short(exc)}")
        except openai.APIConnectionError:
            raise ProviderError("Tidak bisa terhubung ke provider AI (jaringan/base URL).")
        except openai.APIStatusError as exc:
            raise ProviderError(f"Provider error ({exc.status_code}). Coba lagi nanti.")

        choice = resp.choices[0]
        msg = choice.message
        calls, native_calls = [], []
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = tc.function.arguments
            calls.append(ToolCall(tc.id, tc.function.name, args))
            native_calls.append({"id": tc.id, "type": "function",
                                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}})
        native = {"role": "assistant", "content": msg.content or ""}
        if native_calls:
            native["tool_calls"] = native_calls
        text = msg.content or ""
        if getattr(msg, "refusal", None):
            text = f"(Model menolak menjawab: {msg.refusal})"
        usage = {"input_tokens": resp.usage.prompt_tokens, "output_tokens": resp.usage.completion_tokens} \
            if resp.usage else {}
        return Turn(text, calls, [native], choice.finish_reason, usage, resp.model)


# --- Anthropic (Claude) --------------------------------------------------------

_INTERNAL_BLOCKS = {"thinking", "redacted_thinking", "tool_use"}


def _echo_safe(content: list[dict]) -> list[dict]:
    """Prepare assistant content for replay: drop model-internal blocks before a fallback boundary."""
    last_fb = max((i for i, b in enumerate(content) if b.get("type") == "fallback"), default=-1)
    out = []
    for i, block in enumerate(content):
        if block.get("type") == "fallback":
            continue  # audit marker only
        if i < last_fb and block.get("type") in _INTERNAL_BLOCKS:
            continue
        out.append(block)
    return out


class AnthropicProvider:
    def __init__(self, model: str, api_key: str | None, base_url: str | None, max_tokens: int,
                 http_client=None):
        self.model = model
        self.max_tokens = max_tokens
        self.key = f"anthropic:{base_url or 'api.anthropic.com'}:{model}"
        self.client = anthropic.Anthropic(api_key=api_key, base_url=base_url or None,
                                          timeout=REQUEST_TIMEOUT, max_retries=2, http_client=http_client)

    def user_message(self, text: str) -> dict:
        return {"role": "user", "content": text}

    def assistant_text(self, text: str) -> dict:
        return {"role": "assistant", "content": text}

    def tool_results(self, results):
        # All results for one assistant turn go back in a single user message.
        return [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": call.id, "content": text, **({"is_error": True} if err else {})}
            for call, text, err in results]}]

    def complete(self, system, history, tools) -> Turn:
        blocks = [{"type": "text", "text": system[0], "cache_control": {"type": "ephemeral"}}]
        blocks += [{"type": "text", "text": s} for s in system[1:]]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": blocks,
            "messages": history,
        }
        if tools:
            kwargs["tools"] = [{"name": t.name, "description": t.description, "input_schema": t.parameters}
                               for t in tools]
        try:
            if self.model in ANTHROPIC_FALLBACK_MODELS:
                resp = self.client.beta.messages.create(betas=[ANTHROPIC_FALLBACK_BETA], fallbacks="default", **kwargs)
            else:
                resp = self.client.messages.create(**kwargs)
        except anthropic.AuthenticationError as exc:
            raise ProviderError(f"API key ditolak oleh Anthropic (401): {_short(exc)}")
        except anthropic.PermissionDeniedError:
            raise ProviderError("API key tidak punya izin untuk model ini (403).")
        except anthropic.NotFoundError:
            raise ProviderError(f"Model '{self.model}' tidak ditemukan (404).")
        except anthropic.RateLimitError:
            raise ProviderError("Kena rate limit Anthropic (429). Coba lagi nanti.")
        except anthropic.BadRequestError as exc:
            raise ProviderError(f"Request ditolak Anthropic (400): {_short(exc)}")
        except anthropic.APIConnectionError:
            raise ProviderError("Tidak bisa terhubung ke Anthropic (jaringan/base URL).")
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"Anthropic error ({exc.status_code}). Coba lagi nanti.")

        content = resp.to_dict()["content"]
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        calls = [ToolCall(b["id"], b["name"], b.get("input", {})) for b in content if b.get("type") == "tool_use"]
        native = [{"role": "assistant", "content": _echo_safe(content)}]
        if resp.stop_reason == "refusal":
            # A refusal can cut a tool_use off mid-input; never replay it without a tool_result.
            text = text or "(Model menolak menjawab permintaan ini karena kebijakan keamanan provider.)"
            calls = []
            native = [{"role": "assistant", "content": text}]
        usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens,
                 "cache_read_input_tokens": getattr(resp.usage, "cache_read_input_tokens", None)}
        return Turn(text, calls, native, resp.stop_reason, usage, resp.model)


def _short(exc: Exception) -> str:
    """Provider's own error text (e.g. 'Invalid API-key provided'), clipped and scrubbed of secrets."""
    return redact_text(str(getattr(exc, "message", exc)))[:300]


def build_provider(kind: AIProviderKind, *, model: str, api_key: str | None, base_url: str | None,
                   max_tokens: int, temperature: float | None, http_client=None) -> ChatProvider:
    if kind == AIProviderKind.ANTHROPIC:
        return AnthropicProvider(model, api_key, base_url, max_tokens, http_client)
    return OpenAICompatibleProvider(model, api_key, base_url, max_tokens, temperature, http_client)
