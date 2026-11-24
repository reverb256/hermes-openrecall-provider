"""Security contract gates for the maintainer review (2026-11-24).

Covers the four properties teknium1 asked for on NousResearch/hermes-agent
#159248:

1. The passphrase is resolved through Hermes' profile secret scope, not a bare
   ``os.environ`` read, and an unscoped multiplexed read fails closed.
2. No default passphrase-file probing; only an explicitly configured path is
   read.
3. Redirects cannot carry the ``Authorization`` header to another host.
4. ``hermes memory setup`` writes through ``hermes_cli.config.set_config_value``
   and routes the API key to ``.env`` as a secret.

No network and no live Hermes install required: the Hermes modules are stubbed
in ``sys.modules``.
"""

from __future__ import annotations

import os
import sys
import types
import urllib.request

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from openrecall_provider import client as client_mod  # noqa: E402
from openrecall_provider import config_schema  # noqa: E402
from openrecall_provider.client import (  # noqa: E402
    OpenRecallClient,
    OpenRecallError,
    _configured_passphrase_file,
    read_passphrase,
)


def _stub_hermes(monkeypatch, get_secret=None, config_block=None, writes=None):
    """Install fake ``agent.secret_scope`` / ``hermes_cli.config`` modules."""
    agent = types.ModuleType("agent")
    scope = types.ModuleType("agent.secret_scope")
    scope.get_secret = get_secret or (lambda name, default=None: default)
    agent.secret_scope = scope

    hermes_cli = types.ModuleType("hermes_cli")
    hc = types.ModuleType("hermes_cli.config")

    def load_config_readonly():
        return {"memory": {"openrecall": config_block or {}}}

    def set_config_value(key, value, force=False):
        if writes is not None:
            writes.append((key, value, force))

    hc.load_config_readonly = load_config_readonly
    hc.set_config_value = set_config_value
    hermes_cli.config = hc

    monkeypatch.setitem(sys.modules, "agent", agent)
    monkeypatch.setitem(sys.modules, "agent.secret_scope", scope)
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", hc)
    return scope


# -- 1. profile-scoped secret resolution ---------------------------------

def test_passphrase_uses_scoped_secret_over_process_env(monkeypatch):
    monkeypatch.setenv("OPENRECALL_PASSPHRASE", "launch-profile-value")
    _stub_hermes(monkeypatch, get_secret=lambda name, default=None: "active-profile-value")
    assert read_passphrase() == "active-profile-value"


def test_passphrase_fails_closed_when_scope_missing(monkeypatch):
    monkeypatch.setenv("OPENRECALL_PASSPHRASE", "launch-profile-value")

    def raising(name, default=None):
        raise RuntimeError("no profile secret scope active while multiplexing is on")

    _stub_hermes(monkeypatch, get_secret=raising)
    # Must not fall back to the process environment — that is the leak the
    # review called out.
    assert read_passphrase() == ""


def test_passphrase_reads_process_env_without_hermes(monkeypatch):
    for name in ("agent", "agent.secret_scope", "hermes_cli", "hermes_cli.config"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setenv("OPENRECALL_PASSPHRASE", "standalone-value")
    assert read_passphrase() == "standalone-value"


# -- 2. no default file probing -----------------------------------------

def test_legacy_default_files_are_not_probed(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENRECALL_PASSPHRASE", raising=False)
    for name in ("agent", "agent.secret_scope", "hermes_cli", "hermes_cli.config"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    legacy = tmp_path / ".openrecall-passphrase.txt"
    legacy.write_text("legacy-file-value", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))

    assert read_passphrase() == "", "a default-location file must not be read"


def test_explicit_passphrase_file_is_read(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENRECALL_PASSPHRASE", raising=False)
    path = tmp_path / "pass"
    path.write_text("explicit-file-value\n", encoding="utf-8")
    assert read_passphrase(str(path)) == "explicit-file-value"


def test_configured_passphrase_file_is_read(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENRECALL_PASSPHRASE", raising=False)
    path = tmp_path / "pass"
    path.write_text("configured-file-value", encoding="utf-8")
    _stub_hermes(monkeypatch, config_block={"passphrase_file": str(path)})
    assert _configured_passphrase_file() == str(path)
    assert read_passphrase() == "configured-file-value"


# -- 3. redirect hardening ----------------------------------------------

def test_cross_origin_redirect_is_refused():
    handler = client_mod._SameOriginRedirectHandler()
    req = urllib.request.Request("https://memory.example/api/memory/user:x")
    with pytest.raises(OpenRecallError, match="cross-origin"):
        handler.redirect_request(
            req, None, 302, "Found", {},
            "https://attacker.example/steal",
        )


def test_same_origin_redirect_is_allowed():
    handler = client_mod._SameOriginRedirectHandler()
    req = urllib.request.Request("https://memory.example/api/memory/user:x")
    redirected = handler.redirect_request(
        req, None, 302, "Found", {},
        "https://memory.example/api/memory/user:x/",
    )
    assert redirected is not None


def test_https_downgrade_is_refused():
    handler = client_mod._SameOriginRedirectHandler()
    req = urllib.request.Request("https://memory.example/api")
    with pytest.raises(OpenRecallError, match="downgrade"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://memory.example/api")


def test_client_uses_guarded_opener():
    c = OpenRecallClient(url="http://127.0.0.1:1", namespace="user:t", passphrase="pw", api_key="k")
    opener = c._opener()
    assert any(isinstance(h, client_mod._SameOriginRedirectHandler) for h in opener.handlers)


# -- 4. setup writer + schema -------------------------------------------

def test_schema_marks_api_key_secret_and_env():
    schema = {f["key"]: f for f in config_schema.build_config_schema("http://x", "user:t")}
    assert schema["api_key"]["secret"] is True
    assert schema["api_key"]["env_var"] == "OPENRECALL_API_KEY"
    assert schema["passphrase_file"]["default"] == ""
    assert not schema["url"].get("secret")


def test_writer_uses_set_config_value_and_skips_api_key(monkeypatch):
    writes = []
    _stub_hermes(monkeypatch, writes=writes)
    config_schema.write_provider_config(
        {"url": "http://srv:8080", "namespace": "user:t", "api_key": "should-not-be-written"},
        "/tmp/hermes",
    )
    assert writes == [
        ("memory.openrecall.url", "http://srv:8080", True),
        ("memory.openrecall.namespace", "user:t", True),
    ]


def test_writer_persists_explicit_empty_passphrase_file(monkeypatch):
    writes = []
    _stub_hermes(monkeypatch, writes=writes)
    config_schema.write_provider_config({"passphrase_file": ""}, "/tmp/hermes")
    assert writes == [("memory.openrecall.passphrase_file", "", True)]


# -- packaging consistency ----------------------------------------------

def test_versions_and_dependency_bound():
    root = REPO
    pyproject = open(os.path.join(root, "pyproject.toml"), encoding="utf-8").read()
    plugin = open(
        os.path.join(root, "openrecall_provider", "plugin.yaml"), encoding="utf-8"
    ).read()
    assert 'version = "0.4.1"' in pyproject
    assert "version: 0.4.1" in plugin
    assert '"cryptography>=41,<47"' in pyproject
    assert "cryptography>=41,<47" in plugin


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
