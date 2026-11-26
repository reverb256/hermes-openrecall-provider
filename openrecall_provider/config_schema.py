"""Config schema + writer for the ``hermes memory setup`` wizard.

The wizard reads ``get_config_schema()`` from the provider, prompts for each
field, writes secret fields (``secret: True`` + ``env_var``) to
``$HERMES_HOME/.env`` itself, and hands the remaining values to
``save_config()``, which persists them under ``memory.openrecall`` in
``$HERMES_HOME/config.yaml``.

The passphrase is not prompted here. It is resolved at runtime by
``client.read_passphrase()`` through Hermes' profile secret scope
(``OPENRECALL_PASSPHRASE``). A passphrase *file* is supported only when the
user names the path in ``passphrase_file``; there is no default location.

Field shape matches the contract in ``hermes-agent/hermes_cli/memory_setup.py``:

  key          — config key under ``memory.openrecall``
  description  — prompt / help text
  required     — bool
  default      — optional default value
  choices      — optional list of values for enums
  secret       — True means "prompt masked, write to .env, never config.yaml"
  env_var      — env var that receives a secret, or pre-fills a plain value
  when         — optional {field: value} gate
"""

from __future__ import annotations

from typing import Any, Dict, List

from .client import _default_namespace

CONFIG_BLOCK_KEY = "memory.openrecall"

#: Fields that are persisted in ``config.yaml`` under ``memory.openrecall``.
#: ``api_key`` is deliberately absent: it is a secret and goes to ``.env`` via
#: the wizard's ``secret``/``env_var`` handling.
CONFIG_FIELDS = ("url", "namespace", "passphrase_file")


def build_config_schema(url: str, namespace: str) -> List[Dict[str, Any]]:
    """Return the wizard field list for openrecall.

    Four fields, in prompt order:
      1. ``url`` — server URL
      2. ``namespace`` — memory namespace (default ``agent:<profile>`` so two
         profiles on one server stay isolated; a user can set a shared value)
      3. ``api_key`` — optional bearer token, written to ``.env``
      4. ``passphrase_file`` — optional explicit path to the passphrase file

    The passphrase itself is never prompted and never persisted here.
    """
    return [
        {
            "key": "url",
            "description": "openrecall server URL",
            "required": True,
            "default": url,
        },
        {
            "key": "namespace",
            "description": (
                "Memory namespace for this profile. Defaults to "
                "``agent:<profile>`` (one namespace per Hermes profile). Set "
                "the same value on two profiles only if you intend to share."
            ),
            "required": True,
            "default": namespace or _default_namespace(),
        },
        {
            "key": "api_key",
            "description": "API key (optional; leave blank for self-hosted servers)",
            "required": False,
            "secret": True,
            "env_var": "OPENRECALL_API_KEY",
        },
        {
            "key": "passphrase_file",
            "description": (
                "Passphrase file path (optional; blank = disabled). Only this "
                "explicit path is read — set OPENRECALL_PASSPHRASE to keep the "
                "passphrase out of a file entirely."
            ),
            "required": False,
            "default": "",
        },
    ]


def write_provider_config(values: Dict[str, Any], hermes_home: str) -> None:
    """Persist non-secret fields under ``memory.openrecall`` in config.yaml.

    Uses ``hermes_cli.config.set_config_value`` — the supported write path —
    so live config editing keeps the agent's gate, managed-key guard and
    atomic save. ``force=True`` suppresses the unknown-key warning: these keys
    belong to the provider, not to Hermes' own schema.
    """
    try:
        from hermes_cli.config import set_config_value  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on host install
        raise RuntimeError(
            "cannot write provider config: hermes_cli.config.set_config_value "
            "is unavailable; run `hermes config set "
            f"{CONFIG_BLOCK_KEY}.<key> <value>` manually"
        ) from exc

    for key in CONFIG_FIELDS:
        val = values.get(key)
        if val is None:
            continue
        text = str(val).strip()
        if not text:
            # An empty value is meaningful for passphrase_file (it means
            # "disabled"); writing "" keeps that intent instead of leaving a
            # stale path behind.
            if key == "passphrase_file":
                set_config_value(f"{CONFIG_BLOCK_KEY}.{key}", "", force=True)
            continue
        set_config_value(f"{CONFIG_BLOCK_KEY}.{key}", text, force=True)


def build_hermes_subcommand_table() -> Dict[str, str]:
    """Return the provider-specific flags ``hermes memory setup`` exposes."""
    return {
        "--openrecall-url": "openrecall server URL (overrides default)",
        "--openrecall-namespace": "memory namespace (overrides default)",
        "--openrecall-api-key": "API key for hosted openrecall instances (-> .env)",
        "--openrecall-passphrase-file": "explicit passphrase file path (default: none)",
    }
