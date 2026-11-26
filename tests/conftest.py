"""Shared pytest fixtures: stub the Hermes runtime modules so the openrecall
provider package can be imported (and its security-contract tests run) without a
live Hermes install present.

Installed at conftest import time (before test modules are collected) so the
module-level ``from openrecall_provider import ...`` statements in the test files
resolve. Individual tests may override via ``monkeypatch`` (which restores).
"""

from __future__ import annotations

import os
import sys
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)


def _install_hermes_stubs() -> None:
    agent = types.ModuleType("agent")
    agent_mp = types.ModuleType("agent.memory_provider")

    class _MemoryProvider:
        @property
        def name(self):
            return "openrecall"

        def is_available(self) -> bool:
            return False

        def initialize(self, session_id: str, **kwargs) -> None:
            return None

        def get_tool_schemas(self):
            return []

        def handle_tool_call(self, tool_name: str, args: dict, **kwargs) -> str:
            return "{}"

        def prefetch(self, query: str, *, session_id: str = "") -> str:
            return ""

        def recall_status(self):
            return None

        def sync_turn(
            self,
            user_content: str,
            assistant_content: str,
            *,
            session_id: str = "",
            messages=None,
            **kwargs,
        ) -> None:
            return None

    class _RecallStatus:
        def __init__(self, provider_label: str, count: int, glyph: str) -> None:
            self.provider_label = provider_label
            self.count = count
            self.glyph = glyph

    setattr(agent_mp, "MemoryProvider", _MemoryProvider)
    setattr(agent_mp, "RecallStatus", _RecallStatus)
    setattr(agent, "memory_provider", agent_mp)
    sys.modules["agent.memory_provider"] = agent_mp
    sys.modules["agent"] = agent

    scope = types.ModuleType("agent.secret_scope")
    setattr(scope, "get_secret", lambda name, default=None: default)
    setattr(agent, "secret_scope", scope)
    sys.modules["agent.secret_scope"] = scope

    hermes_cli = types.ModuleType("hermes_cli")
    hc = types.ModuleType("hermes_cli.config")
    setattr(hc, "load_config_readonly", lambda: {"memory": {"openrecall": {}}})
    setattr(hc, "set_config_value", lambda key, value, force=False: None)
    setattr(hermes_cli, "config", hc)
    sys.modules["hermes_cli"] = hermes_cli
    sys.modules["hermes_cli.config"] = hc

    hermes_constants = types.ModuleType("hermes_constants")
    setattr(hermes_constants, "get_hermes_home", lambda: os.path.expanduser("~/.hermes"))
    sys.modules["hermes_constants"] = hermes_constants


_install_hermes_stubs()
