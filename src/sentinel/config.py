"""Runtime configuration and network posture.

Enterprise deployment needs one honest place that answers: what does this tool
phone home to, what secrets does it read, and how do I turn each off? This module
is that place. It resolves configuration from environment variables and makes the
egress surface explicit and auditable.

Secrets are read from the environment only. Nothing is written to disk, logged,
or committed. The three external endpoints are enumerated below so a security
reviewer can allowlist or block each one deliberately.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# The complete outbound egress surface. Every external call the tool can make
# goes to one of these. Offline mode disables all of them.
EGRESS = {
    "pypi": "https://pypi.org",
    "npm": "https://registry.npmjs.org",
    "osv": "https://api.osv.dev",
    "github": "https://api.github.com",
    "openrouter": "https://openrouter.ai",
}


@dataclass
class SecretStatus:
    """Which secrets are present, without ever exposing their values."""

    github_token: bool = False
    openrouter_key: bool = False

    def to_dict(self) -> dict:
        return {
            "github_token_present": self.github_token,
            "openrouter_key_present": self.openrouter_key,
        }


@dataclass
class Config:
    """Resolved runtime configuration."""

    offline: bool = False
    use_llm: bool = True
    secrets: SecretStatus = field(default_factory=SecretStatus)

    @property
    def active_egress(self) -> dict[str, str]:
        """The endpoints this configuration will actually contact."""
        if self.offline:
            return {}
        active = {k: v for k, v in EGRESS.items() if k != "openrouter"}
        if self.use_llm and self.secrets.openrouter_key:
            active["openrouter"] = EGRESS["openrouter"]
        return active

    def posture_summary(self) -> dict:
        return {
            "offline": self.offline,
            "llm_enabled": self.use_llm and not self.offline and self.secrets.openrouter_key,
            "secrets": self.secrets.to_dict(),
            "active_egress": self.active_egress,
        }


def resolve(offline: bool = False, no_llm: bool = False) -> Config:
    """Build a Config from the environment and flags."""
    secrets = SecretStatus(
        github_token=bool(os.environ.get("GITHUB_TOKEN", "")),
        openrouter_key=bool(os.environ.get("OPENROUTER_API_KEY", "")),
    )
    return Config(
        offline=offline,
        use_llm=not no_llm,
        secrets=secrets,
    )