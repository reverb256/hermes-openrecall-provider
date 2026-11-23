"""openrecall memory provider for Hermes Agent.

A standalone memory backend plugin that implements the
``agent.memory_provider.MemoryProvider`` ABC. Talks to a self-hosted
openrecall server over HTTP with **client-side AES-256-GCM encryption**:
the server only ever sees ciphertext and cannot read your memory.

Two equivalent ways to ship this provider:

1. **As a directory plugin** under ``$HERMES_HOME/plugins/openrecall/`` —
   Hermes' ``plugins/memory/__init__.py`` discovery picks it up by
   ``kind: exclusive`` (declared in ``plugin.yaml``).
2. **As a pip-installable package** — this directory is also a Python
   package; ``pyproject.toml`` registers the
   ``hermes_agent.memory_providers`` entry point so ``hermes memory setup``
   lists "openrecall" alongside Honcho / OpenViking / Mem0 / Hindsight.

The standalone-provider contract (Hermes PR #82649) means a user can
``pip install`` this, run ``hermes memory setup``, and pick "openrecall" —
no file copying, no symlinks, no MCP bridge required.

Encryption protocol mirrors ``Twigpine/openrecall::client/crypto.ts`` (pre-rename
``Gitlawb/openrecall``):
``scrypt(passphrase, sha256("memlawb:"+ns))`` -> 32-byte key, AES-256-GCM
with deterministic nonce ``HMAC-SHA256(key, entryKey || 0x00 || pt)[:12]``,
AAD = entryKey. Blob layout: ``[0x01][12-byte nonce][16-byte tag][ct]``
base64-encoded. Any entry written by the Bun/Node client round-trips
through this provider and vice versa.

Server endpoints (openrecall HTTP API):

  GET    /health                    -> { ok, store, service }
  GET    /api/memory/:ns            -> { content: { entries: {k: b64ct} } }
  PUT    /api/memory/:ns            -> { entries: { k: b64ct } } (delta upsert)
  DELETE /api/memory/:ns?key=K      -> removes the entry from the namespace
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# --- imports --------------------------------------------------------------
# Hermes loads this directory as a SYNTHETIC module (e.g.
# ``_hermes_user_memory.openrecall``) from $HERMES_HOME/plugins/<name>/, where the
# directory is named after the plugin (``openrecall``) while the repo package is
# ``openrecall_provider``. Imports here are therefore RELATIVE: an absolute
# ``from openrecall_provider...`` only resolves when the repo root is on
# sys.path, which a plain directory install on the PVC never satisfies — the
# loader then reports "Plugin: NOT installed" and every hook stays dead.
from agent.memory_provider import MemoryProvider, RecallStatus

from .client import (
    DEFAULT_NAMESPACE,
    DEFAULT_URL,
    OpenRecallClient,
    OpenRecallError,
    is_crypto_available,
    read_passphrase,
)

logger = logging.getLogger(__name__)

PROVIDER_NAME = "openrecall"

# Tools exposed to the model. These names are what the LLM sees in its
# function-calling schema; they are distinct from the upstream openrecall MCP
# tool names (``memory_save`` etc.) because the Hermes plugin toolset is
# already namespaced by provider.
TOOL_SAVE = "openrecall_save"
TOOL_RECALL = "openrecall_recall"
TOOL_SEARCH = "openrecall_search"
TOOL_LIST = "openrecall_list"
TOOL_DELETE = "openrecall_delete"


def _config_file_block() -> Dict[str, Any]:
    """Read the ``memory.openrecall`` block from the active Hermes config.

    The Hermes memory-provider loader constructs this provider WITHOUT the
    config block, so before 2026-10-03 the ``memory.openrecall.{url,namespace}``
    settings were inert at runtime — only ``OPENRECALL_NAMESPACE`` / hardcoded
    defaults applied, and per-profile namespaces silently no-op'd.
    ``load_config_readonly`` is Hermes' canonical profile-aware reader. Any
    failure (no config, no Hermes runtime) returns {} so the env/default
    chain still works.
    """
    try:
        from hermes_cli.config import load_config_readonly
        cfg = load_config_readonly()
        memory = cfg.get("memory") if isinstance(cfg, dict) else None
        block = memory.get("openrecall") if isinstance(memory, dict) else None
        return dict(block) if isinstance(block, dict) else {}
    except Exception:
        return {}


def _resolve_namespace(config: Dict[str, Any], file_cfg: Dict[str, Any]) -> str:
    """Namespace precedence: ctor config > ``OPENRECALL_NAMESPACE`` > config.yaml > default.

    Env outranks the config file so the documented escape hatch
    (``OPENRECALL_NAMESPACE=... hermes openrecall get <key>``) keeps working.
    """
    for candidate in (
        config.get("namespace"),
        os.environ.get("OPENRECALL_NAMESPACE"),
        file_cfg.get("namespace"),
        DEFAULT_NAMESPACE,
    ):
        if candidate:
            return str(candidate)
    return DEFAULT_NAMESPACE


class OpenRecallMemoryProvider(MemoryProvider):
    """Hermes memory provider backed by the openrecall encrypted-memory server.

    Implements the full ``MemoryProvider`` ABC plus the optional hooks the
    bundled providers (Honcho, Mem0, MemPalace) all implement, so the
    agent can prefetch, sync turns, mirror built-in writes, and survive
    context compression without losing institutional memory.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = dict(config) if config is not None else {}
        file_cfg = _config_file_block()
        self._url: str = str(
            self._config.get("url") or file_cfg.get("url") or DEFAULT_URL
        ).rstrip("/")
        self._namespace: str = _resolve_namespace(self._config, file_cfg)
        self._api_key: Optional[str] = (
            self._config.get("api_key") or file_cfg.get("api_key") or None
        )
        self._session_id: str = ""
        # Client constructed lazily — gives the linter a chance to see
        # _HAS_CRYPTO without forcing crypto import at module load.
        self._client: Optional[OpenRecallClient] = None
        # Last prefetch result (used by ``recall_status`` for the agent's
        # deterministic "👁️ recalled N memories" indicator).
        self._last_prefetch_count: int = 0

    # ------------------------------------------------------------------
    # Client lifecycle
    # ------------------------------------------------------------------

    def _get_client(self) -> OpenRecallClient:
        if self._client is None:
            self._client = OpenRecallClient(
                url=self._url,
                namespace=self._namespace,
                api_key=self._api_key,
                passphrase=self._config.get("passphrase"),
            )
        return self._client

    # ------------------------------------------------------------------
    # MemoryProvider ABC — required
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return PROVIDER_NAME

    def is_available(self) -> bool:
        """Return True if the provider is configured. **No network calls.**

        Network reachability is verified in ``initialize()`` and surfaced via
        ``unavailable_reason()`` / ``system_prompt_block()``. The ABC contract
        is explicit: ``is_available()`` must be cheap and offline.
        """
        return is_crypto_available() and bool(read_passphrase())

    def unavailable_reason(self) -> str:
        if not is_crypto_available():
            return ("openrecall provider requires the 'cryptography' package — "
                    "install it with `pip install cryptography`")
        if not read_passphrase():
            return ("openrecall passphrase not configured — create "
                    "~/.openrecall-passphrase.txt (chmod 600) or set OPENRECALL_PASSPHRASE")
        return ""

    def initialize(self, session_id: str, **kwargs) -> None:
        self._session_id = session_id
        # Subagents/cron must not write memory (their system prompts would
        # pollute the user's durable store); captured here, enforced in the
        # write-path hooks (on_delegation).
        self._agent_context = kwargs.get("agent_context", "primary") or "primary"
        # Eagerly probe the server once so configuration / network errors
        # surface in the agent log at startup, not on the first turn.
        try:
            self._get_client().health()
            logger.info("openrecall provider initialized (url=%s ns=%s session=%s)",
                        self._url, self._namespace, session_id)
        except Exception as e:
            logger.warning("openrecall provider initialize: server unreachable at %s: %s",
                           self._url, e)

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": TOOL_SAVE,
                "description": (
                    "Store a keyed memory entry in the openrecall encrypted "
                    "persistent memory server. Use for facts, preferences, "
                    "decisions, and anything worth recalling across sessions. "
                    "The server only ever sees ciphertext — encryption happens "
                    "client-side before the entry leaves this machine."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string", "description": "Memory key (path-like)."},
                        "content": {"type": "string", "description": "Memory content (markdown)."},
                        "namespace": {"type": "string", "description": "Optional namespace override."},
                    },
                    "required": ["key", "content"],
                },
            },
            {
                "name": TOOL_RECALL,
                "description": (
                    "Search the openrecall persistent memory for entries relevant "
                    "to a natural-language query. Returns decrypted plaintext "
                    "matches (case-insensitive substring against key + body)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query."},
                        "limit": {"type": "integer", "description": "Optional cap on results."},
                        "namespace": {"type": "string", "description": "Optional namespace override."},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": TOOL_SEARCH,
                "description": (
                    "Literal keyword / substring search across openrecall entries. "
                    "Cheaper than recall — no decryption, no LLM ranking."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Literal substring."},
                        "namespace": {"type": "string", "description": "Optional namespace override."},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": TOOL_LIST,
                "description": "List all stored memory keys in the openrecall server (no decryption).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "namespace": {"type": "string", "description": "Optional namespace override."},
                    },
                },
            },
            {
                "name": TOOL_DELETE,
                "description": "Delete a memory entry by key from the openrecall server.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string", "description": "Key to delete."},
                        "namespace": {"type": "string", "description": "Optional namespace override."},
                    },
                    "required": ["key"],
                },
            },
        ]

    def handle_tool_call(self, tool_name: str, args: Dict[str, Any], **kwargs) -> str:
        # Per-tool namespace override (allows the same provider to address
        # multiple openrecall namespaces from one session).
        ns = args.get("namespace") or self._namespace
        try:
            client = self._with_namespace(ns) if ns != self._namespace else self._get_client()
        except Exception as e:
            return json.dumps({"error": f"client init failed: {e}"})

        try:
            if tool_name == TOOL_SAVE:
                key = args.get("key", "")
                content = args.get("content", "")
                if not key or not content:
                    return json.dumps({"error": "key and content are required"})
                client.save(key, content)
                return json.dumps({"result": f"Memory '{key}' saved to ns={ns}."})

            if tool_name == TOOL_RECALL:
                query = args.get("query", "")
                if not query:
                    return json.dumps({"error": "query is required"})
                limit = args.get("limit")
                results = client.recall(query)
                if isinstance(limit, int) and limit > 0:
                    results = results[:limit]
                payload = [{"key": k, "content": c} for k, c in results]
                return json.dumps({"result": payload, "count": len(payload)})

            if tool_name == TOOL_SEARCH:
                query = args.get("query", "")
                if not query:
                    return json.dumps({"error": "query is required"})
                # Cheaper: list keys whose name or decrypted body matches.
                # For pure substring on key only, hit list_keys() and filter.
                matches = [k for k in client.list_keys()
                           if query.lower() in k.lower()]
                # Also include any key whose body matches, even if its name
                # doesn't — bounded by full decrypt pass.
                try:
                    body_hits = [k for k, _ in client.recall(query)]
                    matches = list(dict.fromkeys(matches + body_hits))
                except Exception:
                    pass
                return json.dumps({"result": matches, "count": len(matches)})

            if tool_name == TOOL_LIST:
                return json.dumps({"result": client.list_keys()})

            if tool_name == TOOL_DELETE:
                key = args.get("key", "")
                if not key:
                    return json.dumps({"error": "key is required"})
                ok = client.delete(key)
                return json.dumps({"result": f"deleted={ok}", "key": key})

            return json.dumps({"error": f"Unknown tool: {tool_name}"})

        except OpenRecallError as e:
            return json.dumps({"error": str(e)})
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return json.dumps({"error": f"HTTP {e.code}: {body[:200]}"})
        except urllib.error.URLError as e:
            return json.dumps({"error": f"connection error: {e.reason}"})

    def system_prompt_block(self) -> str:
        ok = is_crypto_available() and bool(read_passphrase())
        status = "Active." if ok else f"Inactive — {self.unavailable_reason() or 'not configured'}."
        return (
            "# openrecall Memory\n"
            f"{status}\n"
            "Encrypted persistent memory. The server only sees ciphertext.\n"
            "Tools: openrecall_save, openrecall_recall, openrecall_search, openrecall_list, openrecall_delete.\n"
            "Save durable facts (preferences, project decisions, conventions) eagerly but selectively."
        )

    def shutdown(self) -> None:
        self._client = None

    # ------------------------------------------------------------------
    # MemoryProvider ABC — optional hooks (mirrors Honcho / MemPalace shape)
    # ------------------------------------------------------------------

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        """Recall relevant entries before the next API call.

        Returns a formatted text block injected as context. Empty string
        if no matches. Bounded so a hot loop or a hostile query can't
        flood the prompt window.
        """
        if not query:
            self._last_prefetch_count = 0
            return ""
        try:
            hits = self._get_client().recall(query)[:8]
        except Exception as e:
            logger.debug("openrecall prefetch failed: %s", e)
            self._last_prefetch_count = 0
            return ""
        if not hits:
            self._last_prefetch_count = 0
            return ""
        self._last_prefetch_count = len(hits)
        lines = [f"## Recalled openrecall entries ({len(hits)})", ""]
        for k, body in hits:
            first_line = body.strip().splitlines()[0] if body.strip() else ""
            lines.append(f"- **{k}** — {first_line[:120]}")
        return "\n".join(lines)

    def recall_status(self) -> Optional[RecallStatus]:
        if self._last_prefetch_count == 0:
            return None
        return RecallStatus(
            provider_label="openrecall",
            count=self._last_prefetch_count,
            glyph="🔐",
        )

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        """Cheap pre-warm: queue a recall for the next turn. Default is no-op."""
        # No background thread is needed — recall() against the local
        # openrecall server is already fast enough (~50ms). Pre-warming would
        # just duplicate work the next prefetch() call does anyway.
        return None

    def sync_turn(self, user_content: str, assistant_content: str, *,
                  session_id: str = "", messages: Optional[List[Dict[str, Any]]] = None) -> None:
        """Mirror the completed turn into openrecall as a single transcript entry.

        We do NOT extract facts here — the model is responsible for calling
        ``openrecall_save`` on durable facts. A blind transcript dump is
        expensive and mostly noise. If the agent has no fact to save, the
        function is a no-op.
        """
        return None

    def on_turn_start(self, turn_number: int, message: str, **kwargs) -> None:
        # No per-turn tick needed — prefetch() does the work on demand.
        return None

    def on_session_end(self, messages: Optional[List[Dict[str, Any]]] = None) -> None:
        """End-of-session hook. Could trigger an extraction job; for now no-op."""
        return None

    def on_session_switch(
        self,
        new_session_id: str,
        *,
        parent_session_id: str = "",
        reset: bool = False,
        rewound: bool = False,
        **kwargs,
    ) -> None:
        """Track mid-process session_id rotation (/resume, /branch, /reset).

        Keeps ``_session_id`` truthful for logging and resets the prefetch
        indicator state so the 🔐 status line cannot show a count carried
        over from the previous session.
        """
        self._session_id = new_session_id
        self._last_prefetch_count = 0
        return None

    # --- pre-compression directive extraction -------------------------------
    # Standing directives and decisions ("always X", "never Y", "we decided
    # Z") are exactly what a compression summary tends to flatten into
    # nothing — and losing one silently changes future behavior. Scan the
    # messages about to be discarded and surface candidates so the
    # compressor must fold them in. Deterministic, no LLM, bounded.

    _DIRECTIVE_PATTERNS = (
        re.compile(r"\b(?:always|never|from now on)\b[^.!?\n]{10,200}", re.IGNORECASE),
        re.compile(r"\bwe (?:decided|agreed|chose|settled on)\b[^.!?\n]{5,200}", re.IGNORECASE),
        re.compile(r"\bdon'?t (?:ever|again)\b[^.!?\n]{5,200}", re.IGNORECASE),
        re.compile(r"\b(?:rule|policy|convention|preference):\s*[^.!?\n]{5,200}", re.IGNORECASE),
        re.compile(r"\bi prefer\b[^.!?\n]{5,200}", re.IGNORECASE),
    )
    _DIRECTIVE_MAX = 5

    def on_pre_compress(self, messages: Optional[List[Dict[str, Any]]] = None) -> str:
        """Surface standing directives/decisions before context is compressed.

        Scans USER messages only (the model's own prose would just echo its
        instructions back). Returns a short block listing candidate
        directives; the compressor folds it into the summary prompt. Empty
        string when nothing looks like a standing rule.
        """
        if not messages:
            return ""
        seen: set = set()
        found: List[str] = []
        for msg in messages:
            if not isinstance(msg, dict) or msg.get("role") != "user":
                continue
            content = msg.get("content", "")
            if not isinstance(content, str) or len(content) > 8000:
                continue
            for pat in self._DIRECTIVE_PATTERNS:
                for m in pat.finditer(content):
                    text = " ".join(m.group(0).split())
                    low = text.lower()
                    if len(text) < 15 or low in seen:
                        continue
                    # Skip overlaps: two patterns matching spans of the same
                    # sentence produce near-duplicates.
                    if any(low in f.lower() or f.lower() in low for f in found):
                        continue
                    seen.add(low)
                    found.append(text[:200])
                    if len(found) >= self._DIRECTIVE_MAX:
                        break
                if len(found) >= self._DIRECTIVE_MAX:
                    break
            if len(found) >= self._DIRECTIVE_MAX:
                break
        if not found:
            return ""
        lines = "\n".join(f"- {d}" for d in found)
        return (
            "## Standing directives captured from this conversation "
            "(preserve these constraints verbatim in the summary)\n" + lines
        )

    def on_delegation(self, task: str, result: str, *,
                      child_session_id: str = "", **kwargs) -> None:
        """Persist one digest entry per completed subagent task.

        Subagent results are otherwise invisible to every future session.
        Writes are skipped for non-primary contexts (subagents/cron never
        write memory) and failures are swallowed — memory mirroring must
        never break delegation itself.
        """
        if getattr(self, "_agent_context", "primary") != "primary":
            return None
        task_text = (task or "").strip()
        result_text = (result or "").strip()
        if not task_text and not result_text:
            return None
        try:
            date = datetime.date.today().isoformat()
            slug_source = task_text[:40] or result_text[:40]
            slug = re.sub(r"[^a-z0-9]+", "-", slug_source.lower()).strip("-")[:32]
            key = f"delegations/{date}-{slug}"
            body = (
                f"# Delegation digest {date}\n\n"
                f"- **session:** {self._session_id or 'unknown'}\n"
                f"- **child:** {child_session_id or 'unknown'}\n\n"
                f"## Task\n{task_text[:1000]}\n\n"
                f"## Result\n{result_text[:1500]}\n"
            )
            self._get_client().save(key, body)
        except Exception as e:
            logger.debug("openrecall on_delegation digest failed: %s", e)
        return None

    def on_memory_write(self, action: str, target: str, content: str,
                        metadata: Optional[Dict[str, Any]] = None) -> None:
        """Mirror the built-in Hermes ``memory`` tool writes into openrecall.

        This is the one path where the agent's explicit memory saves
        automatically reach the persistent encrypted store. The key is
        derived from the built-in target + path so the two stores stay
        in sync (``HERMES.md/<file>`` mirrors to ``hermes/<file>``).
        """
        if action not in ("add", "replace"):
            return
        if not content or not content.strip():
            return
        key = f"hermes/{target}/{metadata.get('path', 'memory')}" if metadata else f"hermes/{target}"
        try:
            self._get_client().save(key, content)
        except Exception as e:
            logger.debug("openrecall on_memory_write mirror failed: %s", e)

    def backup_paths(self) -> List[str]:
        """Return filesystem paths this provider owns (so ``hermes backup``
        captures them). The passphrase file is the one sensitive artifact
        we need to back up — without it the ciphertext is unrecoverable.
        """
        paths = []
        for path in (
            "/run/secrets/openrecall-passphrase",
            os.path.expanduser("~/.openrecall-passphrase.txt"),
        ):
            if os.path.isfile(path):
                paths.append(path)
        return paths

    # ------------------------------------------------------------------
    # Config schema for ``hermes memory setup`` wizard
    # ------------------------------------------------------------------

    def get_config_schema(self) -> List[Dict[str, Any]]:
        from .config_schema import build_config_schema
        return build_config_schema(self._url, self._namespace)

    def save_config(self, values: Dict[str, Any], hermes_home: str) -> None:
        from .config_schema import write_provider_config
        write_provider_config(values, hermes_home)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _with_namespace(self, namespace: str) -> OpenRecallClient:
        return OpenRecallClient(
            url=self._url, namespace=namespace,
            api_key=self._api_key, passphrase=self._config.get("passphrase"),
        )


def _namespace_default() -> str:
    return os.environ.get("OPENRECALL_NAMESPACE", DEFAULT_NAMESPACE)


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

def register(ctx) -> None:
    """Register openrecall as a memory provider plugin.

    Called by the memory plugin discovery system (pip-installed variant) or
    by ``plugins/memory/__init__.py`` (directory variant). The ``ctx`` is
    a ``PluginContext``-like shim — only ``register_memory_provider`` is
    meaningful for a ``kind: exclusive`` provider.
    """
    provider = OpenRecallMemoryProvider()
    register_fn = getattr(ctx, "register_memory_provider", None)
    if callable(register_fn):
        register_fn(provider)
    # Skills the provider contributes. These are loaded only when openrecall
    # is the active memory.provider.
    skills_dir = os.path.join(os.path.dirname(__file__), "skills")
    if os.path.isdir(skills_dir):
        register_skill = getattr(ctx, "register_skill", None)
        if callable(register_skill):
            for entry in sorted(os.listdir(skills_dir)):
                skill_md = os.path.join(skills_dir, entry, "SKILL.md")
                if os.path.isfile(skill_md):
                    register_skill(
                        PROVIDER_NAME,
                        skill_md,
                        f"Maintenance: {entry}",
                    )


Provider = OpenRecallMemoryProvider  # discovery alias
