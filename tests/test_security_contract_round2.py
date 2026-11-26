"""Security contract gates — round 2 (2026-11-26, tek's re-review of #159248).

Covers the two blocking items from teknium1's 2026-11-26 review at ce68fabd:

1. The API key the wizard saves to ``.env`` as ``OPENRECALL_API_KEY`` is read
   back through the profile secret scope; a key left in ``config.yaml`` is
   ignored. Provider ctor and CLI both use the scoped value.
2. The default namespace is profile-specific (``agent:<profile>``), so two
   Hermes profiles on one server do not share ``user:default``. Explicit
   namespaces still win.

No network and no live Hermes install: Hermes modules are stubbed in
``sys.modules``.
"""

from __future__ import annotations

import os
import sys
import types

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from openrecall_provider import client as client_mod  # noqa: E402
from openrecall_provider import config_schema  # noqa: E402
from openrecall_provider import cli as cli_mod  # noqa: E402
import openrecall_provider as provider  # noqa: E402


def _stub_secret_scope(monkeypatch, secrets):
    """Install a fake agent.secret_scope.get_secret over a secret mapping."""
    agent = types.ModuleType("agent")
    scope = types.ModuleType("agent.secret_scope")
    scope.get_secret = lambda name, default=None: secrets.get(name, default)
    agent.secret_scope = scope
    monkeypatch.setitem(sys.modules, "agent", agent)
    monkeypatch.setitem(sys.modules, "agent.secret_scope", scope)


def _stub_hermes_constants(monkeypatch, home):
    """Install a fake hermes_constants.get_hermes_home."""
    hc = types.ModuleType("hermes_constants")
    hc.get_hermes_home = lambda: home
    monkeypatch.setitem(sys.modules, "hermes_constants", hc)


# ---------------------------------------------------------------------------
# Item 1 — API key from scope, never config.yaml
# ---------------------------------------------------------------------------

def test_read_api_key_uses_profile_scope(monkeypatch):
    monkeypatch.delenv("OPENRECALL_API_KEY", raising=False)
    _stub_secret_scope(monkeypatch, {"OPENRECALL_API_KEY": "sk-scoped"})
    assert client_mod.read_api_key() == "sk-scoped"


def test_read_api_key_falls_back_to_env_without_hermes(monkeypatch):
    monkeypatch.delitem(sys.modules, "agent", raising=False)
    monkeypatch.delitem(sys.modules, "agent.secret_scope", raising=False)
    monkeypatch.setenv("OPENRECALL_API_KEY", "sk-standalone")
    assert client_mod.read_api_key() == "sk-standalone"


def test_provider_ignores_api_key_in_config_yaml(monkeypatch, tmp_path):
    """A stale key in config.yaml must not win over the scoped env key."""
    monkeypatch.delenv("OPENRECALL_API_KEY", raising=False)
    _stub_secret_scope(monkeypatch, {"OPENRECALL_API_KEY": "sk-scoped"})
    # Make _config_file_block return a block with a legacy config.yaml key.
    monkeypatch.setattr(provider, "_config_file_block", lambda: {"api_key": "sk-from-config"})
    p = provider.OpenRecallMemoryProvider()
    assert p._api_key == "sk-scoped", "config.yaml key must be ignored"


def test_provider_ctor_api_key_takes_precedence(monkeypatch):
    _stub_secret_scope(monkeypatch, {"OPENRECALL_API_KEY": "sk-scoped"})
    monkeypatch.setattr(provider, "_config_file_block", lambda: {})
    p = provider.OpenRecallMemoryProvider(config={"api_key": "sk-explicit"})
    assert p._api_key == "sk-explicit"


def test_cli_client_from_args_uses_scoped_key(monkeypatch):
    _stub_secret_scope(monkeypatch, {"OPENRECALL_API_KEY": "sk-scoped"})
    monkeypatch.setattr(cli_mod, "_load_config_block",
                        lambda: {"api_key": "sk-from-config"})
    monkeypatch.setattr(cli_mod, "read_passphrase", lambda: "pw")
    args = types.SimpleNamespace(namespace=None)
    client, cfg = cli_mod._client_from_args(args)
    assert client.api_key == "sk-scoped"
    assert cfg.get("api_key") == "sk-from-config"  # block still loaded for other fields


# ---------------------------------------------------------------------------
# Item 2 — profile-specific default namespace
# ---------------------------------------------------------------------------

def test_default_namespace_from_named_profile(monkeypatch, tmp_path):
    from pathlib import Path
    home = tmp_path / ".hermes" / "profiles" / "trader"
    home.mkdir(parents=True)
    _stub_hermes_constants(monkeypatch, Path(home))
    assert client_mod._active_profile_name() == "trader"
    assert client_mod._default_namespace() == "agent:trader"


def test_default_namespace_from_env_profile(monkeypatch):
    monkeypatch.delitem(sys.modules, "hermes_constants", raising=False)
    monkeypatch.setenv("HERMES_PROFILE_NAME", "fleet-sites")
    assert client_mod._default_namespace() == "agent:fleet-sites"


def test_default_namespace_falls_back_without_profile(monkeypatch):
    monkeypatch.delitem(sys.modules, "hermes_constants", raising=False)
    monkeypatch.delenv("HERMES_PROFILE_NAME", raising=False)
    monkeypatch.delenv("HERMES_PROFILE", raising=False)
    assert client_mod._default_namespace() == client_mod.DEFAULT_NAMESPACE


def test_provider_default_namespace_is_profile_specific(monkeypatch, tmp_path):
    from pathlib import Path
    home = tmp_path / ".hermes" / "profiles" / "editor"
    home.mkdir(parents=True)
    _stub_hermes_constants(monkeypatch, Path(home))
    monkeypatch.setattr(provider, "_config_file_block", lambda: {})
    monkeypatch.delenv("OPENRECALL_NAMESPACE", raising=False)
    p = provider.OpenRecallMemoryProvider()
    assert p._namespace == "agent:editor"


def test_explicit_namespace_still_wins(monkeypatch, tmp_path):
    from pathlib import Path
    home = tmp_path / ".hermes" / "profiles" / "editor"
    home.mkdir(parents=True)
    _stub_hermes_constants(monkeypatch, Path(home))
    monkeypatch.setattr(provider, "_config_file_block", lambda: {})
    p = provider.OpenRecallMemoryProvider(config={"namespace": "shared:custom"})
    assert p._namespace == "shared:custom"


def test_wizard_default_namespace_is_profile_specific(monkeypatch, tmp_path):
    from pathlib import Path
    home = tmp_path / ".hermes" / "profiles" / "coo"
    home.mkdir(parents=True)
    _stub_hermes_constants(monkeypatch, Path(home))
    schema = config_schema.build_config_schema("http://127.0.0.1:8080", "")
    ns_field = next(f for f in schema if f["key"] == "namespace")
    assert ns_field["default"] == "agent:coo"


def test_manifest_declares_api_key_as_optional_env():
    import yaml
    manifest = yaml.safe_load(
        open(os.path.join(REPO, "openrecall_provider", "plugin.yaml")).read()
    )
    assert "OPENRECALL_API_KEY" in (manifest.get("optional_env") or [])
    assert "OPENRECALL_API_KEY" not in (manifest.get("requires_env") or [])
