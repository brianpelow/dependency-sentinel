"""Config/posture tests: egress surface and secret detection."""

from __future__ import annotations

from sentinel.config import Config, SecretStatus, resolve


def test_offline_has_no_egress():
    cfg = Config(offline=True, secrets=SecretStatus(github_token=True, openrouter_key=True))
    assert cfg.active_egress == {}


def test_online_egress_without_llm_key():
    cfg = Config(offline=False, use_llm=True,
                 secrets=SecretStatus(github_token=True, openrouter_key=False))
    egress = cfg.active_egress
    assert "openrouter" not in egress
    assert "pypi" in egress and "osv" in egress and "github" in egress


def test_online_egress_includes_llm_when_key_present():
    cfg = Config(offline=False, use_llm=True,
                 secrets=SecretStatus(github_token=True, openrouter_key=True))
    assert "openrouter" in cfg.active_egress


def test_no_llm_flag_excludes_openrouter():
    cfg = Config(offline=False, use_llm=False,
                 secrets=SecretStatus(openrouter_key=True))
    assert "openrouter" not in cfg.active_egress


def test_secrets_never_expose_values():
    status = SecretStatus(github_token=True, openrouter_key=True)
    d = status.to_dict()
    assert d == {"github_token_present": True, "openrouter_key_present": True}
    # Only booleans, never a value
    assert all(isinstance(v, bool) for v in d.values())


def test_resolve_reads_environment(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    cfg = resolve()
    assert cfg.secrets.github_token
    assert not cfg.secrets.openrouter_key