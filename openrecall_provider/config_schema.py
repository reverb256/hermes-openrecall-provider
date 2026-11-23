"""Config schema + writer for the ``hermes memory setup`` wizard.

The wizard reads ``get_config_schema()`` from the provider and prompts the
user for each field, then calls ``save_config()`` to write the non-secret
values into ``$HERMES_HOME/config.yaml`` under the ``memory.openrecall``
key. Secrets (the passphrase) are kept in ``~/.openrecall-passphrase.txt``
or the ``OPENRECALL_PASSPHRASE`` env var, never in config.yaml.

Field shape matches the contract documented in
``hermes-agent/agent/memory_provider.py``:

  key          — dotted config key
  label        — human-readable label for the prompt
  type         — "text" | "integer" | "number" | "boolean"
  required     — bool
  default      — optional default value
  choices      — optional list of values for enums
  description  — multi-line help text
  env_var      — optional name of an env var that can pre-fill the value
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

CONFIG_BLOCK_KEY = "memory.openrecall"


def build_config_schema(url: str, namespace: str) -> List[Dict[str, Any]]:
    """Return the wizard field list for openrecall.

    Three fields, in prompt order:
      1. ``url`` — server URL (default: the documented live cluster address)
      2. ``namespace`` — memory namespace (default: ``user:<USER>``)
      3. ``api_key`` — optional bearer token, never persisted in config

    The passphrase is NOT prompted here — it is read at runtime from
    ``~/.openrecall-passphrase.txt`` (chmod 600) or ``OPENRECALL_PASSPHRASE``,
    so the setup wizard never sees it.
    """
    user = os.environ.get("USER", "user")
    return [
        {
            "key": "url",
            "label": "openrecall server URL",
            "type": "text",
            "required": True,
            "default": url,
            "description": (
                "Base URL of the openrecall encrypted-memory server. "
                "Default points at the documented live cluster address; "
                "override for self-hosted or staging servers."
            ),
        },
        {
            "key": "namespace",
            "label": "memory namespace",
            "type": "text",
            "required": True,
            "default": namespace or f"user:{user}",
            "description": (
                "Tenant namespace for this install. Use a different value "
                "to isolate profiles or experiments on the same server. "
                "Convention: ``user:<USER>`` or ``agent:<profile>``."
            ),
        },
        {
            "key": "api_key",
            "label": "API key (optional)",
            "type": "text",
            "required": False,
            "default": "",
            "description": (
                "Bearer token for hosted openrecall instances. Leave empty "
                "for self-hosted servers. The key is written to the "
                "``api_key`` field of the config block, NOT to .env."
            ),
        },
    ]


def write_provider_config(values: Dict[str, Any], hermes_home: str) -> None:
    """Persist non-secret fields to ``$HERMES_HOME/config.yaml``.

    Honors the Hermes convention: live ``config.yaml`` editing is gated
    by ``hermes config set``; we write through that path so a running
    agent picks up the new values without a restart.
    """
    # The provider doesn't get a hermes_home write path; delegate to
    # ``hermes config set`` for each non-empty value so the agent's
    # config gate is the only one that touches config.yaml.
    from hermes_cli.config import cfg_set  # type: ignore

    for key in ("url", "namespace", "api_key"):
        val = values.get(key)
        if val is None:
            continue
        if key == "api_key" and not val:
            continue
        cfg_set(f"{CONFIG_BLOCK_KEY}.{key}", val)


def build_hermes_subcommand_table() -> Dict[str, str]:
    """Return a mapping of CLI flags the setup wizard should expose.

    Hermes PR #82649 makes ``hermes memory setup`` provider-aware. The
    wizard reads this table to decide which provider-specific options
    to show on screen.
    """
    return {
        "--openrecall-url": "openrecall server URL (overrides default)",
        "--openrecall-namespace": "memory namespace (overrides default)",
        "--openrecall-api-key": "API key for hosted openrecall instances",
    }
