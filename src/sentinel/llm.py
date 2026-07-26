"""The LLM narrative layer.

The engine has already decided each dependency's risk. This layer asks a model
to write a short, practical migration note for the high-risk ones: what the
upgrade likely involves, what to watch for, how urgent it is. It is handed the
deterministic findings and instructed not to contradict them.

The model never changes a risk level, never adds or removes an advisory. If it
is unavailable, the report is complete without narrative. This reuses the
fallback-chain pattern: free models rate-limit and lose free status, so no
single model is load-bearing, and total failure degrades to no-narrative rather
than crashing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import httpx

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

DEFAULT_MODEL_CHAIN: tuple[str, ...] = (
    "qwen/qwen3-coder:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "openrouter/free",
)

SYSTEM_PROMPT = (
    "You are a senior engineer writing a brief, practical dependency upgrade note. "
    "You are given a dependency, its current and installed versions, its known "
    "security advisories, and a fixed risk assessment. Write two or three sentences: "
    "what upgrading likely involves, what breaking changes or risks to watch for, and "
    "how urgent it is given the advisories. Do not restate the version numbers "
    "mechanically. Do not contradict the risk assessment or the advisories you are "
    "given; they are fixed. Be concrete and sober, not promotional."
)


@dataclass
class LLMResult:
    text: str
    model_used: str
    degraded: bool = False


def _strip_think(text: str) -> str:
    return re.sub(r"<think>[\s\S]*?</think>", "", text).strip()


class LLMClient:
    def __init__(
        self,
        model_chain: tuple[str, ...] = DEFAULT_MODEL_CHAIN,
        api_key: str | None = None,
        timeout: float = 60.0,
        http_client: object | None = None,
    ) -> None:
        self._chain = model_chain
        self._api_key = api_key if api_key is not None else os.environ.get("OPENROUTER_API_KEY", "")
        self._timeout = timeout
        self._http = http_client

    def available(self) -> bool:
        return bool(self._api_key) or self._http is not None

    def generate(self, system: str, user: str) -> LLMResult | None:
        if not self.available():
            return None
        for index, model in enumerate(self._chain):
            try:
                text = self._call(model, system, user)
                if text:
                    return LLMResult(_strip_think(text), model, degraded=index > 0)
            except Exception:
                continue
        return None

    def _call(self, model: str, system: str, user: str) -> str:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "transforms": ["middle-out"],
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        if self._http is not None:
            data = self._http.post(OPENROUTER_URL, json=payload, headers=headers)
        else:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(OPENROUTER_URL, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        return data["choices"][0]["message"]["content"]


def build_prompt(assessment) -> str:
    """Construct the user prompt from a completed assessment."""
    dep = assessment.dependency
    adv_lines = (
        "\n".join(
            f"  - {a.advisory_id} [{a.severity.value}]: {a.summary[:120]}"
            for a in assessment.advisories
        )
        or "  (none)"
    )
    return (
        f"Dependency: {dep.name} ({dep.ecosystem.value})\n"
        f"Installed: {dep.pinned_version or 'unpinned'}  Current: {assessment.facts.current_version}\n"
        f"Versions behind: {assessment.facts.versions_behind}\n"
        f"Risk (fixed): {assessment.risk.value}\n"
        f"Reasons: {'; '.join(assessment.risk_reasons)}\n"
        f"Advisories:\n{adv_lines}\n\n"
        f"Write the upgrade note."
    )


def narrate(assessment, llm: LLMClient | None) -> str:
    """Return a migration note for an assessment, or empty string if unavailable."""
    if llm is None or not llm.available():
        return ""
    result = llm.generate(SYSTEM_PROMPT, build_prompt(assessment))
    return result.text if result else ""