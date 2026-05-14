"""Thin client to communicate with the agent under assessment."""

from __future__ import annotations

import os
from typing import Any

import anthropic

from .models import AgentConfig


class AgentClient:
    """Sends messages to the target agent and returns raw responses."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._anthropic: anthropic.Anthropic | None = None

    def _get_anthropic(self) -> anthropic.Anthropic:
        if self._anthropic is None:
            api_key = self.config.api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError(
                    "No API key found. Set ANTHROPIC_API_KEY or provide api_key in config."
                )
            self._anthropic = anthropic.Anthropic(api_key=api_key)
        return self._anthropic

    def send(
        self,
        user_message: str,
        system_override: str | None = None,
        conversation: list[dict[str, Any]] | None = None,
    ) -> str:
        """Send a message and return the text response."""
        if self.config.provider_type == "anthropic":
            return self._send_anthropic(user_message, system_override, conversation)
        raise NotImplementedError(f"Provider {self.config.provider_type!r} not yet supported.")

    def _send_anthropic(
        self,
        user_message: str,
        system_override: str | None,
        conversation: list[dict[str, Any]] | None,
    ) -> str:
        client = self._get_anthropic()
        system = system_override if system_override is not None else self.config.system_prompt

        messages: list[dict[str, Any]] = list(conversation or [])
        messages.append({"role": "user", "content": user_message})

        response = client.messages.create(
            model=self.config.model,
            max_tokens=1024,
            system=system,
            messages=messages,
        )
        return response.content[0].text

    def health_check(self) -> bool:
        """Verify the agent is reachable."""
        try:
            resp = self.send("Hello. Respond with OK.")
            return len(resp) > 0
        except Exception:
            return False
