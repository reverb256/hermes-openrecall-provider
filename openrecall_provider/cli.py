"""CLI subcommand for ``hermes openrecall ...``.

Convention-based discovery: ``hermes-agent/plugins/memory/__init__.py``
imports this file at argparse setup time, looks for ``register_cli()``,
and wires it into the root parser. The active-provider gate means the
subcommand only shows in ``hermes --help`` when
``memory.provider = openrecall`` in config.

Subcommands:

  hermes openrecall status        show config + liveness
  hermes openrecall list          list all stored entry keys
  hermes openrecall get <key>     decrypt and print one entry
  hermes openrecall save <k> <v>  write one entry (text or stdin)
  hermes openrecall delete <key>  remove an entry
  hermes openrecall search <q>    literal substring search
  hermes openrecall config        show the current config block
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from .client import (
    DEFAULT_NAMESPACE,
    DEFAULT_URL,
    LEGACY_SALT_PREFIX,
    SALT_PREFIX,
    OpenRecallClient,
    read_passphrase,
    rollback_salt,
)

PROVIDER_NAME = "openrecall"


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_status(_args: argparse.Namespace) -> int:
    cfg = _load_config_block()
    url = cfg.get("url", DEFAULT_URL)
    ns = cfg.get("namespace", DEFAULT_NAMESPACE)
    pw = read_passphrase()
    if not pw:
        print("openrecall: passphrase not found. Create ~/.openrecall-passphrase.txt "
              "(chmod 600) or set OPENRECALL_PASSPHRASE.", file=sys.stderr)
        return 1
    client = OpenRecallClient(url=url, namespace=ns, passphrase=pw,
                            api_key=cfg.get("api_key"))
    print(f"  url        : {client.url}")
    print(f"  namespace  : {client.namespace}")
    print(f"  api_key    : {'set' if client.api_key else '(none)'}")
    print(f"  passphrase : {'set (' + _passphrase_source() + ')' if pw else 'MISSING'}")
    try:
        h = client.health()
        print(f"  server     : alive (store={h.get('store', '?')}, service={h.get('service', '?')})")
        keys = client.list_keys()
        print(f"  entries    : {len(keys)} stored")
    except Exception as e:
        print(f"  server     : UNREACHABLE — {e}", file=sys.stderr)
        return 2
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    client, _ = _client_from_args(args)
    keys = client.list_keys()
    if args.json:
        print(json.dumps(keys, indent=2))
    else:
        for k in keys:
            print(k)
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    client, _ = _client_from_args(args)
    for k, body in client.recall(args.key):
        if k == args.key:
            if args.json:
                print(json.dumps({"key": k, "content": body}, indent=2))
            else:
                print(body)
            return 0
    print(f"openrecall: key not found: {args.key}", file=sys.stderr)
    return 1


def cmd_save(args: argparse.Namespace) -> int:
    client, _ = _client_from_args(args)
    content = args.value
    if content is None:
        # Read from stdin if no value argument was given.
        content = sys.stdin.read()
    if not content:
        print("openrecall: empty content; nothing saved", file=sys.stderr)
        return 1
    client.save(args.key, content)
    print(f"  saved '{args.key}' ({len(content)} chars)")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    client, _ = _client_from_args(args)
    ok = client.delete(args.key)
    if not ok:
        print(f"openrecall: delete failed for '{args.key}'", file=sys.stderr)
        return 1
    print(f"  deleted '{args.key}'")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    client, _ = _client_from_args(args)
    keys = [k for k in client.list_keys() if args.query.lower() in k.lower()]
    body_hits = [k for k, _ in client.recall(args.query)]
    matches = list(dict.fromkeys(keys + body_hits))
    if args.json:
        print(json.dumps(matches, indent=2))
    else:
        for k in matches:
            print(k)
    return 0


def cmd_migrate_salt(args: argparse.Namespace) -> int:
    """Dry-run, apply, or roll back the salt-prefix migration."""
    if args.rollback:
        result = rollback_salt(args.rollback)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("verified") else 1

    client, _ = _client_from_args(args)
    result = client.migrate_salt(apply=args.apply, backup_path=args.backup)
    result["from_salt"] = LEGACY_SALT_PREFIX
    result["to_salt"] = SALT_PREFIX
    print(json.dumps(result, indent=2, sort_keys=True))
    if not args.apply:
        print(
            "dry run: nothing written. Re-run with --apply (a rollback file is "
            "written before the first upload).",
            file=sys.stderr,
        )
        return 0
    return 0 if result.get("verified") else 1


def cmd_config(_args: argparse.Namespace) -> int:
    cfg = _load_config_block()
    if not cfg:
        print("openrecall: no config block under memory.openrecall in config.yaml.")
        print(f"  defaults would be: url={DEFAULT_URL} namespace={DEFAULT_NAMESPACE}")
        return 0
    print(json.dumps(cfg, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------

def openrecall_command(args: argparse.Namespace) -> int:
    """Top-level dispatcher for ``hermes openrecall <sub>``."""
    sub = getattr(args, "openrecall_command", None)
    handler = _DISPATCH.get(sub)
    if handler is None:
        print(f"openrecall: unknown subcommand: {sub!r}. "
              f"Available: {', '.join(sorted(_DISPATCH))}", file=sys.stderr)
        return 2
    return handler(args)


_DISPATCH = {
    "status": cmd_status,
    "list": cmd_list,
    "get": cmd_get,
    "save": cmd_save,
    "delete": cmd_delete,
    "search": cmd_search,
    "config": cmd_config,
    "migrate-salt": cmd_migrate_salt,
}


def register_cli(subparser: argparse.ArgumentParser) -> None:
    """Build the argparse tree for ``hermes openrecall``.

    Called by ``hermes-agent/plugins/memory/__init__.py`` at argparse setup
    time, only when ``memory.provider == 'openrecall'`` is active. The
    ``openrecall_command`` function is the dispatcher; subparsers select
    which handler runs.
    """
    subparser.add_argument(
        "--namespace", metavar="NS", default=None,
        help="Override the memory namespace for this invocation",
    )

    subs = subparser.add_subparsers(dest="openrecall_command")

    subs.add_parser("status", help="Show config + server liveness")
    list_p = subs.add_parser("list", help="List all stored entry keys")
    list_p.add_argument("--json", action="store_true", help="Emit JSON array")
    get_p = subs.add_parser("get", help="Decrypt and print one entry")
    get_p.add_argument("key", help="Entry key to fetch")
    get_p.add_argument("--json", action="store_true", help="Emit JSON object")
    save_p = subs.add_parser("save", help="Write one entry (value or stdin)")
    save_p.add_argument("key", help="Entry key")
    save_p.add_argument("value", nargs="?", default=None,
                        help="Entry content (omit to read from stdin)")
    del_p = subs.add_parser("delete", help="Remove one entry")
    del_p.add_argument("key", help="Entry key to remove")
    search_p = subs.add_parser("search", help="Literal substring search")
    search_p.add_argument("query", help="Substring to match against keys + bodies")
    search_p.add_argument("--json", action="store_true", help="Emit JSON array")
    subs.add_parser("config", help="Show the current config block")
    mig = subs.add_parser(
        "migrate-salt",
        help="Re-encrypt entries from the legacy 'memlawb:' salt to 'openrecall:'",
    )
    mig.add_argument("--apply", action="store_true",
                     help="Write the migration (default: dry run, reads only)")
    mig.add_argument("--backup", default=None,
                     help="Rollback file path (default ~/.openrecall/salt-migration-<ts>.json)")
    mig.add_argument("--rollback", default=None, metavar="FILE",
                     help="Restore the original ciphertext from a backup file")

    subparser.set_defaults(func=openrecall_command)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config_block() -> Dict[str, Any]:
    """Read the ``memory.openrecall`` block from config.yaml. Empty dict if absent."""
    try:
        from hermes_cli.config import load_config  # type: ignore
        cfg = load_config()
    except Exception:
        return {}
    mem = cfg.get("memory") or {}
    if not isinstance(mem, dict):
        return {}
    block = mem.get("openrecall")
    return dict(block) if isinstance(block, dict) else {}


def _passphrase_source() -> str:
    """Return a human-readable label for where the passphrase came from."""
    if not read_passphrase():
        return "missing"
    import os as _os
    if _os.environ.get("OPENRECALL_PASSPHRASE"):
        return "env OPENRECALL_PASSPHRASE"
    if _os.path.isfile("/run/secrets/openrecall-passphrase"):
        return "/run/secrets/openrecall-passphrase"
    return "~/.openrecall-passphrase.txt"


def _client_from_args(args: argparse.Namespace) -> tuple[OpenRecallClient, Dict[str, Any]]:
    """Build a client from the active config block + optional --namespace override."""
    cfg = _load_config_block()
    ns = getattr(args, "namespace", None) or cfg.get("namespace", DEFAULT_NAMESPACE)
    url = cfg.get("url", DEFAULT_URL)
    api_key = cfg.get("api_key")
    pw = read_passphrase()
    if not pw:
        print("openrecall: passphrase not found. Set OPENRECALL_PASSPHRASE or "
              "create ~/.openrecall-passphrase.txt.", file=sys.stderr)
        sys.exit(1)
    return OpenRecallClient(url=url, namespace=ns, passphrase=pw, api_key=api_key), cfg
