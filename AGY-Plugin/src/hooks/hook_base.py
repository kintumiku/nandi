"""Base Hook Handler implementing Antigravity JSON Hook Protocol over stdin/stdout."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
import contextlib
import hashlib
import json
import os
import queue
import re
import stat
import sys
import tempfile
import threading
import time
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows runtime
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX runtime
    msvcrt = None  # type: ignore[assignment]

from src.file_guard.scanner import (
    BINARY_SNIFF_BYTES,
    FileScanConfig,
    FileScanner,
    MAX_PRE_READ_SCAN_CHARS,
    MAX_SCAN_BYTES_PER_VIEW,
    MAX_SCAN_LINES_PER_VIEW,
    MAX_SINGLE_SHOT_SCAN_BYTES,
    MIME_SNIFF_BYTES,
    MULTI_CHUNK_MAX_CHARS,
    MULTI_CHUNK_OVERLAP_CHARS,
    SCAN_CACHE_MAX_ENTRIES,
    SCAN_CACHE_TTL_SECONDS,
    ScanExtractionResult,
    ToolScanRequest,
    decode_file_uri,
)
from src.model_armor.client import ModelArmorClient, ModelArmorResponse

# Reverse JSONL reader block size (64 KiB) for O(1) tail lookups on transcripts.
_REVERSE_READ_CHUNK_BYTES: int = 65_536

# Ephemeral turn-block state expiration window in seconds (5 minutes).
_TURN_STATE_TTL_SECONDS: float = 300.0

# Default wall-clock budget (seconds) for multi-chunk Model Armor inspection,
# safely below Antigravity's 30s hook timeout so timeouts fail closed cleanly.
DEFAULT_MODEL_ARMOR_BUDGET_SECONDS: float = 24.0

# Bounded concurrency for multi-chunk Model Armor requests (<= 2 waves for 7 chunks).
MAX_MODEL_ARMOR_CHUNK_WORKERS: int = 4

READ_CACHE_FILENAME: str = "nandi_read_cache.json"
READ_CACHE_LOCK_FILENAME: str = "nandi_read_cache.json.lock"

_UTF8_BOM: bytes = b"\xef\xbb\xbf"
_ENFORCEMENT_MODE_RE = re.compile(
    r'^\s*enforcement_mode\s*:\s*["\']?([^"\'#\r\n]+)["\']?',
    re.MULTILINE,
)

_INITIALIZED_DIRS: set[str] = set()
_FILE_DIGEST_CACHE: dict[tuple[str, int], str] = {}


def _sha256_text(text: str) -> str:
    """Returns lowercase hex SHA-256 digest of UTF-8 `text`."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file_cached(file_path: str) -> str:
    """Returns memoized `(abspath, mtime_ns)` SHA-256 hex digest of `file_path`."""
    try:
        abs_p = os.path.abspath(file_path)
        st = os.stat(abs_p)
        cache_key = (abs_p, st.st_mtime_ns)
        cached = _FILE_DIGEST_CACHE.get(cache_key)
        if cached is not None:
            return cached
        hasher = hashlib.sha256()
        with open(abs_p, "rb") as fh:
            while True:
                block = fh.read(65_536)
                if not block:
                    break
                hasher.update(block)
        digest = hasher.hexdigest()
        _FILE_DIGEST_CACHE[cache_key] = digest
        return digest
    except OSError:
        return "missing"


def _ensure_private_dir(dir_path: str) -> str:
    """Creates `dir_path` with `0o700` permissions if not already initialized."""
    abs_dir = os.path.abspath(dir_path)
    if abs_dir not in _INITIALIZED_DIRS or not os.path.isdir(abs_dir):
        os.makedirs(abs_dir, mode=0o700, exist_ok=True)
        if os.name != "nt":
            try:
                os.chmod(abs_dir, 0o700)
            except OSError:  # pragma: no cover - OS filesystem fallback
                pass
        _INITIALIZED_DIRS.add(abs_dir)
    return abs_dir


@contextlib.contextmanager
def _companion_file_lock(lock_path: str) -> Iterator[bool]:
    """Acquires an exclusive byte-0 lock on companion `lock_path`.

    Uses a companion `.lock` file rather than locking `nandi_read_cache.json`
    directly so `os.replace(tmp_path, cache_path)` succeeds on Windows without
    raising `PermissionError: [WinError 32]`.
    """
    lock_fd: int | None = None
    locked = False
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        if os.name != "nt":
            try:
                os.fchmod(lock_fd, 0o600)
            except OSError:  # pragma: no cover - OS filesystem fallback
                pass
        if fcntl is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            locked = True
        elif msvcrt is not None:  # pragma: no cover - Windows runtime
            if os.fstat(lock_fd).st_size == 0:
                os.write(lock_fd, b"0")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
            locked = True
        else:  # pragma: no cover - exotic platform without fcntl/msvcrt
            locked = True
    except OSError:
        locked = False

    try:
        yield locked
    finally:
        if lock_fd is not None:
            if locked:  # pragma: no cover - false only if flock failed after open
                try:
                    if fcntl is not None:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    elif msvcrt is not None:  # pragma: no cover - Windows runtime
                        os.lseek(lock_fd, 0, os.SEEK_SET)
                        msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
                except OSError:  # pragma: no cover - OS unlock fallback
                    pass
            try:
                os.close(lock_fd)
            except OSError:  # pragma: no cover - OS close fallback
                pass


def _atomic_write_json(dir_path: str, target_path: str, payload: Mapping[str, Any]) -> None:
    """Atomically writes `payload` to `target_path` with `0o600` permissions."""
    fd, tmp_path = tempfile.mkstemp(
        prefix=".tmp_nandi_", suffix=".json", dir=dir_path
    )
    try:
        if os.name != "nt":
            try:
                os.fchmod(fd, 0o600)
            except OSError:  # pragma: no cover - OS filesystem fallback
                pass
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_fh:
            json.dump(payload, tmp_fh, separators=(",", ":"))
        os.replace(tmp_path, target_path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:  # pragma: no cover - best-effort temp cleanup
            pass
        raise


class ScanResultCache:
    """Cross-conversation LRU cache (`nandi_read_cache.json`) for clean scans.

    Stores keys `<guard>:<config_sha256>:<content_sha256>` with a strict
    `7,200` s non-sliding TTL (`created_at` is never extended on cache hit) and
    `<= 2,000` LRU entries synchronized via `nandi_read_cache.json.lock`.
    """

    def __init__(
        self,
        cache_dir: str,
        ttl_seconds: float = float(SCAN_CACHE_TTL_SECONDS),
        max_entries: int = SCAN_CACHE_MAX_ENTRIES,
    ) -> None:
        """Initializes the instance.

        Args:
            cache_dir: Directory (`0o700`) hosting `nandi_read_cache.json`.
            ttl_seconds: Strict non-sliding time-to-live in seconds.
            max_entries: Maximum entries retained before LRU eviction.
        """
        self.cache_dir = _ensure_private_dir(cache_dir)
        self.cache_path = os.path.join(self.cache_dir, READ_CACHE_FILENAME)
        self.lock_path = os.path.join(self.cache_dir, READ_CACHE_LOCK_FILENAME)
        self.ttl_seconds = float(ttl_seconds)
        self.max_entries = max(1, int(max_entries))

    def _load_entries_unlocked(self) -> dict[str, float]:
        """Loads ordered `{key: created_at}` map while holding companion lock."""
        if not os.path.exists(self.cache_path):
            return {}
        try:
            with open(self.cache_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, Mapping):
            return {}
        raw_entries = raw.get("entries")
        if not isinstance(raw_entries, Mapping):
            return {}
        parsed: dict[str, float] = {}
        for k, ts in raw_entries.items():
            if isinstance(k, str) and isinstance(ts, (int, float)) and not isinstance(ts, bool):
                parsed[k] = float(ts)
        return parsed

    def _prune_expired(
        self, entries: dict[str, float], now: float
    ) -> tuple[dict[str, float], bool]:
        """Removes entries whose non-sliding age is `< 0` or `>= ttl_seconds`."""
        kept: dict[str, float] = {}
        mutated = False
        for k, created_at in entries.items():
            age = now - created_at
            if 0.0 <= age < self.ttl_seconds:
                kept[k] = created_at
            else:
                mutated = True
        return kept, mutated

    def _save_entries_unlocked(self, entries: Mapping[str, float]) -> None:
        """Persists `{version: 1, entries: ...}` atomically under companion lock."""
        try:
            _atomic_write_json(
                self.cache_dir,
                self.cache_path,
                {"version": 1, "entries": dict(entries)},
            )
        except OSError:  # pragma: no cover - disk-full best-effort cache save
            pass

    def contains(self, key: str, now: float | None = None) -> bool:
        """Returns True if `key` is cached and within its non-sliding TTL.

        Refreshes LRU eviction position without altering `created_at`.
        """
        ts_now = time.time() if now is None else float(now)
        with _companion_file_lock(self.lock_path) as locked:
            if not locked:
                return False
            entries = self._load_entries_unlocked()
            entries, pruned = self._prune_expired(entries, ts_now)
            if key not in entries:
                if pruned:
                    self._save_entries_unlocked(entries)
                return False
            # Promote `key` to MRU tail while preserving original `created_at`.
            created_at = entries.pop(key)
            entries[key] = created_at
            self._save_entries_unlocked(entries)
            return True

    def record_clean(
        self, keys: Sequence[str], now: float | None = None
    ) -> None:
        """Records clean keys (`is_clean == True`), enforcing `<= max_entries` LRU."""
        valid_keys = [k for k in keys if k]
        if not valid_keys:
            return
        ts_now = time.time() if now is None else float(now)
        with _companion_file_lock(self.lock_path) as locked:
            if not locked:
                return
            entries = self._load_entries_unlocked()
            entries, _ = self._prune_expired(entries, ts_now)
            for k in valid_keys:
                if k in entries:
                    # Preserve original creation timestamp (strict non-sliding TTL).
                    orig_created = entries.pop(k)
                    entries[k] = orig_created
                else:
                    entries[k] = ts_now
            while len(entries) > self.max_entries:
                oldest_key = next(iter(entries))
                entries.pop(oldest_key, None)
            self._save_entries_unlocked(entries)


def _iter_jsonl_reverse(
    path: str, chunk_size: int = _REVERSE_READ_CHUNK_BYTES
) -> Iterator[dict[str, Any]]:
    """Streams JSONL records from EOF backwards in 64 KiB blocks."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        carry = b""
        while pos > 0:
            read_len = min(chunk_size, pos)
            pos -= read_len
            fh.seek(pos, os.SEEK_SET)
            chunk = fh.read(read_len) + carry
            lines = chunk.split(b"\n")
            carry = lines[0]
            for raw_line in reversed(lines[1:]):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped.decode("utf-8", errors="replace"))
                    if isinstance(obj, dict):
                        yield obj
                except ValueError:
                    continue
        if carry.strip():
            try:
                obj = json.loads(
                    carry.strip().decode("utf-8", errors="replace")
                )
                if isinstance(obj, dict):
                    yield obj
            except ValueError:
                pass


def _model_armor_chunk_worker(
    work_queue: queue.Queue[tuple[int, str]],
    result_queue: queue.Queue[tuple[int, Any, BaseException | None]],
    cancel_event: threading.Event,
    deadline_monotonic: float,
    client: Any,
    evaluator: Any,
) -> None:
    """Daemon worker executing `client.sanitize_user_prompt` on queued chunks."""
    deadline_cm = (
        client.deadline_scope(deadline_monotonic)
        if hasattr(client, "deadline_scope")
        else ModelArmorClient.deadline_scope(deadline_monotonic)
    )
    with deadline_cm:
        while not cancel_event.is_set():
            if time.monotonic() >= deadline_monotonic:
                return
            try:
                chunk_idx, chunk_text = work_queue.get_nowait()
            except queue.Empty:
                return
            try:
                response = client.sanitize_user_prompt(chunk_text)
                report = evaluator.evaluate(response)
                result_queue.put((chunk_idx, report, None))
                if not getattr(report, "is_allowed", True):
                    cancel_event.set()
                    return
            except BaseException as exc:  # pylint: disable=broad-except
                result_queue.put((chunk_idx, None, exc))
                cancel_event.set()
                return


class AntigravityHookBase:
    """Base class for parsing Antigravity hook payloads and emitting responses."""

    _MAX_SCAN_LINES: int = MAX_SCAN_LINES_PER_VIEW
    _MAX_SCAN_CHARS: int = MAX_SCAN_BYTES_PER_VIEW
    _BINARY_SNIFF_BYTES: int = BINARY_SNIFF_BYTES

    def __init__(
        self,
        hook_name: str,
        file_scan_config: FileScanConfig | None = None,
    ) -> None:
        """Initializes the instance.

        Args:
            hook_name: Guard identifier (e.g., `"fsi-model-armor-guard"`).
            file_scan_config: Optional explicit `FileScanConfig` override.
        """
        self.hook_name = hook_name
        self.payload: dict[str, Any] = {}
        self.conversation_id: str = "unknown"
        self.step_idx: int | None = None
        self.transcript_path: str | None = None
        self.tool_call: dict[str, Any] | None = None
        self.tool_name: str | None = None
        self.tool_args: dict[str, Any] = {}
        self.scanner = FileScanner(config=file_scan_config)
        self.file_scanner = self.scanner
        self._turn_state_cache: dict[str, Any] | None = None
        self._latest_user_step_idx: int | None = None
        self._last_extraction: ScanExtractionResult | None = None
        self._pending_cache_keys: tuple[str, ...] = ()
        self._active_guard_key: str = hook_name
        self._load_stdin()

    def _load_stdin(self) -> None:
        """Reads and parses the JSON payload sent by Antigravity on stdin."""
        if sys.stdin.isatty():
            return
        try:
            if hasattr(sys.stdin, "buffer"):
                raw = (
                    sys.stdin.buffer.read()
                    .decode("utf-8", errors="replace")
                    .strip()
                )
            else:
                raw = sys.stdin.read().strip()
            if raw:
                self.payload = json.loads(raw)
                self.conversation_id = self.payload.get(
                    "conversationId", "unknown"
                )
                self.step_idx = self.payload.get("stepIdx")
                self.transcript_path = self.payload.get("transcriptPath")
                self.tool_call = self.payload.get("toolCall")
                if self.tool_call:
                    self.tool_name = self.tool_call.get("name")
                    self.tool_args = self.tool_call.get("args", {})
        except Exception as exc:  # pylint: disable=broad-except
            sys.stderr.write(
                f"[{self.hook_name}] Error parsing stdin JSON: {exc}\n"
            )

    @property
    def workspace_paths(self) -> list[str]:
        """Returns workspace directory paths from the hook payload."""
        raw_ws = self.payload.get("workspacePaths")
        if isinstance(raw_ws, list):
            return [w.strip() for w in raw_ws if isinstance(w, str) and w.strip()]
        return []

    @staticmethod
    def _get_state_dir() -> str:
        """Returns and initializes a `0o700` directory for ephemeral turn state.

        Honors `NANDI_STATE_DIR` when set; otherwise uses `tempfile.gettempdir()`
        for ephemeral 300-second turn-block flags.
        """
        env_dir = os.environ.get("NANDI_STATE_DIR", "").strip()
        if env_dir:
            return _ensure_private_dir(env_dir)
        uid = getattr(os, "getuid", lambda: "win")()
        return _ensure_private_dir(
            os.path.join(tempfile.gettempdir(), f"nandi_state_{uid}")
        )

    @staticmethod
    def _get_cache_dir() -> str:
        """Returns and initializes `~/.gemini/nandi/state` (`0o700`) for LRU cache.

        Honors `NANDI_STATE_DIR` when set for hermetic testing or custom deployments.
        """
        env_dir = os.environ.get("NANDI_STATE_DIR", "").strip()
        if env_dir:
            return _ensure_private_dir(env_dir)
        return _ensure_private_dir(
            os.path.expanduser("~/.gemini/nandi/state")
        )

    def _get_read_cache(self) -> ScanResultCache:
        """Returns the content-addressed `ScanResultCache` instance."""
        return ScanResultCache(cache_dir=self._get_cache_dir())

    def _compute_config_sha256(self) -> str:
        """Computes `<config_sha256>` over `enforcement_mode`, configs, and env."""
        plugin_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        cfg_yaml_path = os.path.join(plugin_root, "config", "config.yaml")
        pii_json_path = os.path.join(plugin_root, "config", "pii_patterns.json")
        ma_json_path = os.path.join(
            plugin_root, "config", "model_armor_policy.json"
        )

        enforcement_mode = os.environ.get("NANDI_ENFORCEMENT_MODE", "").strip().upper()
        if not enforcement_mode:
            try:
                with open(cfg_yaml_path, "r", encoding="utf-8") as fh:
                    match = _ENFORCEMENT_MODE_RE.search(fh.read())
                    enforcement_mode = (
                        match.group(1).strip().upper() if match else "BLOCK"
                    )
            except OSError:
                enforcement_mode = "BLOCK"

        fingerprint_payload = {
            "enforcement_mode": enforcement_mode,
            "config_yaml_sha256": _sha256_file_cached(cfg_yaml_path),
            "pii_patterns_sha256": _sha256_file_cached(pii_json_path),
            "model_armor_policy_sha256": _sha256_file_cached(ma_json_path),
            "file_scan_config": self.scanner.config.to_dict(),
            "env": {
                env_key: os.environ.get(env_key, "")
                for env_key in (
                    "MODEL_ARMOR_PROJECT_ID",
                    "MODEL_ARMOR_LOCATION",
                    "MODEL_ARMOR_TEMPLATE_ID",
                    "MODEL_ARMOR_ENDPOINT",
                    "MODEL_ARMOR_NO_AUTH",
                )
            },
        }
        return _sha256_text(
            json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":"))
        )

    def _get_safe_conv_id(self) -> str:
        safe_id = "".join(
            ch for ch in self.conversation_id if ch.isalnum() or ch in "-_"
        )
        if not safe_id or safe_id == "unknown":
            return "default"
        return safe_id

    def _get_turn_state_path(self) -> str:
        return os.path.join(
            self._get_state_dir(), f"turn_{self._get_safe_conv_id()}.json"
        )

    def _get_block_flag_path(self) -> str:
        """Returns the ephemeral per-conversation turn state file path."""
        return self._get_turn_state_path()

    def _default_turn_state(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "timestamp": time.time(),
            "blocked": False,
            "reason": "",
            "step_idx": None,
            "blocked_inv_sig": None,
            "metadata": {},
            "hooks": {},
        }

    def _load_turn_state(self) -> dict[str, Any]:
        """Loads and memoizes ephemeral 300-second per-conversation turn state."""
        if self._turn_state_cache is not None:
            return self._turn_state_cache

        path = self._get_turn_state_path()
        state = self._default_turn_state()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    age = time.time() - float(loaded.get("timestamp", 0))
                    if 0.0 <= age < _TURN_STATE_TTL_SECONDS:
                        state.update(loaded)
                        if not isinstance(state.get("hooks"), dict):
                            state["hooks"] = {}
                    else:
                        try:
                            os.remove(path)
                        except OSError:  # pragma: no cover - concurrent unlink
                            pass
            except (OSError, ValueError, TypeError):  # pragma: no cover - corrupt state race
                pass
        self._turn_state_cache = state
        return state

    def _save_turn_state(self, state: dict[str, Any]) -> None:
        """Atomically writes ephemeral turn state with `0o600` permissions."""
        state["conversation_id"] = self.conversation_id
        state["timestamp"] = time.time()
        self._turn_state_cache = state
        try:
            state_dir = self._get_state_dir()
            target_path = self._get_turn_state_path()
            _atomic_write_json(state_dir, target_path, state)
        except OSError as exc:  # pragma: no cover - disk-full best-effort state save
            sys.stderr.write(
                f"[{self.hook_name}] Warning: failed to persist turn state: {exc}\n"
            )

    def _get_hook_scoped_state(self, guard_key: str) -> dict[str, Any]:
        state = self._load_turn_state()
        hooks_map = state.setdefault("hooks", {})
        scoped = hooks_map.get(guard_key)
        if not isinstance(scoped, dict):
            scoped = {"last_user_step_idx": None}
            hooks_map[guard_key] = scoped
        return scoped

    def _current_invocation_sig(self) -> str | None:
        inv_num = self.payload.get("invocationNum")
        step_val = self.step_idx
        if inv_num is not None or step_val is not None:
            return f"inv:{inv_num}|step:{step_val}"
        return None

    def mark_turn_blocked(
        self, reason: str, metadata: dict[str, Any] | None = None
    ) -> None:
        """Flags the current turn as blocked so subsequent tools & PostInvocation halt."""
        state = self._load_turn_state()
        state["blocked"] = True
        state["reason"] = reason
        state["step_idx"] = self.step_idx
        state["blocked_inv_sig"] = self._current_invocation_sig()
        state["metadata"] = metadata or {}
        self._save_turn_state(state)

    def is_turn_blocked(self) -> tuple[bool, str]:
        """Checks whether the current conversation turn is flagged as blocked."""
        state = self._load_turn_state()
        if state.get("blocked") is True:
            return True, str(state.get("reason", "Policy violation"))
        return False, ""

    def clear_turn_blocked(self) -> None:
        """Clears the blocked flag while retaining invocation deduplication state."""
        state = self._load_turn_state()
        if state.get("blocked"):
            state["blocked"] = False
            state["reason"] = ""
            state["blocked_inv_sig"] = None
            self._save_turn_state(state)

    def clear_turn_blocked_for_new_invocation(self) -> None:
        """Resets stale block flags when a new user prompt starts a fresh invocation."""
        state = self._load_turn_state()
        if not state.get("blocked"):
            return
        inv_num = self.payload.get("invocationNum", 0)
        cur_sig = self._current_invocation_sig()
        prev_sig = state.get("blocked_inv_sig")
        if inv_num == 0 and (prev_sig is None or cur_sig != prev_sig):
            state["blocked"] = False
            state["reason"] = ""
            state["blocked_inv_sig"] = None
            self._save_turn_state(state)

    def record_passed_scan(self, guard_key: str | None = None) -> None:
        """Commits clean cache keys to `nandi_read_cache.json` and step dedup state."""
        key = guard_key or self._active_guard_key or self.hook_name
        if self._pending_cache_keys:
            self._get_read_cache().record_clean(self._pending_cache_keys)
            self._pending_cache_keys = ()

        if self._latest_user_step_idx is not None and self._latest_user_step_idx >= 0:
            state = self._load_turn_state()
            scoped = self._get_hook_scoped_state(key)
            if scoped.get("last_user_step_idx") != self._latest_user_step_idx:
                scoped["last_user_step_idx"] = self._latest_user_step_idx
                self._save_turn_state(state)

    def _extract_latest_user_step_record(
        self, transcript_path: str
    ) -> tuple[int | None, str, list[dict[str, Any]]]:
        """Reads the latest `USER_INPUT` step, resolving `transcript_full.jsonl` if truncated."""
        try:
            abs_transcript = os.path.abspath(transcript_path)
            transcript_dir = os.path.dirname(abs_transcript)
            compact_candidate = os.path.join(transcript_dir, "transcript.jsonl")
            full_candidate = os.path.join(
                transcript_dir, "transcript_full.jsonl"
            )
            scan_path = (
                compact_candidate
                if os.path.basename(abs_transcript) == "transcript_full.jsonl"
                and os.path.exists(compact_candidate)
                else abs_transcript
            )

            for step in _iter_jsonl_reverse(scan_path):
                s_type = step.get("type", "")
                source = step.get("source", "")
                if s_type == "USER_INPUT" or source == "USER_EXPLICIT":
                    step_idx = step.get("step_index")
                    idx_val = (
                        int(step_idx)
                        if isinstance(step_idx, int)
                        and not isinstance(step_idx, bool)
                        else -1
                    )
                    resolved_step = step
                    truncated = step.get("truncated_fields") or []
                    if truncated and os.path.exists(full_candidate):
                        for full_step in _iter_jsonl_reverse(full_candidate):
                            if full_step.get("step_index") == step_idx and (
                                full_step.get("type") == "USER_INPUT"
                                or full_step.get("source") == "USER_EXPLICIT"
                            ):
                                resolved_step = full_step
                                break

                    content = str(resolved_step.get("content") or "")
                    raw_media = resolved_step.get("media")
                    media_items = (
                        [m for m in raw_media if isinstance(m, dict)]
                        if isinstance(raw_media, list)
                        else []
                    )
                    return idx_val, content, media_items
        except OSError as exc:
            sys.stderr.write(
                f"[{self.hook_name}] Error reading transcript: {exc}\n"
            )
        return None, "", []

    def _extract_latest_user_prompt_from_transcript(
        self, transcript_path: str
    ) -> str | None:
        """Returns the content string of the latest `USER_INPUT` step, or None."""
        idx_val, content, _ = self._extract_latest_user_step_record(
            transcript_path
        )
        if idx_val is None or not content:
            return None
        return content

    def _resolve_media_uri_path(
        self, raw_uri: str, transcript_dir: str | None
    ) -> str | None:
        """Resolves a `USER_INPUT.media[].uri` against transcript/logs or workspace."""
        if not raw_uri or not raw_uri.strip():
            return None
        extra_roots: list[str] = []
        if transcript_dir:
            extra_roots.append(transcript_dir)
            extra_roots.append(os.path.dirname(transcript_dir))
        extra_roots.extend(self.workspace_paths)
        return self.scanner.resolve_candidate_path(raw_uri, extra_roots)

    def _inspect_prompt_media_items(
        self,
        media_items: Sequence[Mapping[str, Any]],
        transcript_dir: str | None,
    ) -> tuple[str | None, list[str]]:
        """Inspects `USER_INPUT.media` for unscannable binaries vs `text/*` & SVG.

        Returns:
            Tuple `(block_reason_or_none, extracted_text_segments)`.
        """
        block_unscannable = self.scanner.config.on_unscannable_media == "BLOCK"
        text_segments: list[str] = []

        for item in media_items:
            raw_mime = str(
                item.get("mime_type") or item.get("mimeType") or ""
            ).strip()
            norm_mime = raw_mime.split(";", 1)[0].strip().lower()
            raw_uri = str(item.get("uri") or "").strip()

            if norm_mime.startswith("text/") or norm_mime == "image/svg+xml":
                resolved = self._resolve_media_uri_path(raw_uri, transcript_dir)
                if not resolved:
                    if block_unscannable:
                        return (
                            f"Unreadable prompt media attachment ({norm_mime}) "
                            "blocked under payload.on_unscannable_media=BLOCK.",
                            [],
                        )
                    continue

                try:
                    st = os.stat(resolved)
                    if st.st_size > MAX_PRE_READ_SCAN_CHARS * 4:
                        return (
                            f"Prompt media attachment '{os.path.basename(resolved)}' "
                            f"exceeds {MAX_PRE_READ_SCAN_CHARS}-character scan limit.",
                            [],
                        )
                    with open(resolved, "rb") as fh:
                        raw_bytes = fh.read(MAX_PRE_READ_SCAN_CHARS * 4 + 1)
                except OSError:
                    if block_unscannable:
                        return (
                            f"Unreadable prompt media attachment ({norm_mime}) "
                            "blocked under payload.on_unscannable_media=BLOCK.",
                            [],
                        )
                    continue

                if raw_bytes.startswith(_UTF8_BOM):
                    raw_bytes = raw_bytes[len(_UTF8_BOM) :]
                head_512 = raw_bytes[:MIME_SNIFF_BYTES]
                if head_512.startswith(b"%PDF-") or b"\x00" in raw_bytes:
                    if block_unscannable:
                        return (
                            f"Binary payload disguised as {norm_mime} in prompt "
                            "media blocked under payload.on_unscannable_media=BLOCK.",
                            [],
                        )
                    continue
                try:
                    decoded = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    if block_unscannable:
                        return (
                            f"Invalid UTF-8 payload in {norm_mime} prompt media "
                            "blocked under payload.on_unscannable_media=BLOCK.",
                            [],
                        )
                    continue

                if len(decoded) > MAX_PRE_READ_SCAN_CHARS:
                    return (
                        f"Prompt media attachment '{os.path.basename(resolved)}' "
                        f"({len(decoded)} chars) exceeds "
                        f"{MAX_PRE_READ_SCAN_CHARS}-character scan limit.",
                        [],
                    )
                if decoded.strip():
                    decoded_name = os.path.basename(decode_file_uri(raw_uri)) or "media"
                    text_segments.append(f"[Media: {decoded_name}]\n{decoded}")
                continue

            # Non-text / non-SVG media attachment (image/png, application/pdf, audio/*, video/*, etc.)
            if block_unscannable:
                label = norm_mime or "binary"
                return (
                    f"Unscannable multimodal prompt attachment ({label}) "
                    "blocked under payload.on_unscannable_media=BLOCK.",
                    [],
                )

        return None, text_segments

    def _apply_tool_cache_lookup(
        self, guard_key: str, res: ScanExtractionResult
    ) -> ScanExtractionResult:
        """Evaluates `nandi_read_cache.json` for full or slice-only cache hits."""
        if res.action != "SCAN" or not res.text_to_scan.strip():
            self._pending_cache_keys = ()
            return res

        cache = self._get_read_cache()
        cfg_sha = self._compute_config_sha256()
        full_key = f"{guard_key}:{cfg_sha}:{_sha256_text(res.text_to_scan)}"
        if cache.contains(full_key):
            self._pending_cache_keys = ()
            return ScanExtractionResult(
                action="SKIP_CACHED",
                source=f"cache_hit:{res.source}",
            )

        if res.slice_text:
            slice_key = f"{guard_key}:{cfg_sha}:{_sha256_text(res.slice_text)}"
            args_key = f"{guard_key}:{cfg_sha}:{_sha256_text(res.args_text)}"
            if cache.contains(slice_key):
                if cache.contains(args_key):
                    self._pending_cache_keys = ()
                    return ScanExtractionResult(
                        action="SKIP_CACHED",
                        source=f"cache_hit:{res.source}",
                    )
                # File slice is already cached clean, but toolCall.args changed:
                # scan ONLY the uncached `args_text` so modified args cannot bypass!
                self._pending_cache_keys = (args_key, full_key)
                return ScanExtractionResult(
                    action="SCAN",
                    text_to_scan=res.args_text,
                    source=f"tool_args_uncached:{self.tool_name}",
                    args_text=res.args_text,
                )

            self._pending_cache_keys = (slice_key, full_key, args_key)
            return res

        self._pending_cache_keys = (full_key,)
        return res

    def _build_pre_invocation_target(
        self,
        guard_key: str,
        prompt_text: str,
        media_items: Sequence[Mapping[str, Any]],
        source_tag: str,
        transcript_dir: str | None = None,
    ) -> ScanExtractionResult:
        """Builds and cache-checks the `PreInvocation` scan target."""
        if media_items:
            block_err, media_texts = self._inspect_prompt_media_items(
                media_items, transcript_dir
            )
            if block_err is not None:
                self._pending_cache_keys = ()
                return ScanExtractionResult(
                    action="BLOCK_POLICY",
                    block_reason=block_err,
                    source=f"{source_tag}:media_block",
                )
        else:
            media_texts = []

        segments = [seg for seg in (prompt_text, *media_texts) if seg and seg.strip()]
        if not segments:
            self._pending_cache_keys = ()
            return ScanExtractionResult(
                action="NO_ACTIONABLE_TEXT", source=source_tag
            )

        combined_prompt = "\n\n".join(segments)
        if len(combined_prompt) > MAX_PRE_READ_SCAN_CHARS:
            self._pending_cache_keys = ()
            return ScanExtractionResult(
                action="BLOCK_POLICY",
                block_reason=(
                    f"User prompt payload ({len(combined_prompt)} chars) exceeds "
                    f"{MAX_PRE_READ_SCAN_CHARS}-character scan limit."
                ),
                source=f"{source_tag}:oversize",
            )

        cache = self._get_read_cache()
        cfg_sha = self._compute_config_sha256()
        prompt_key = f"{guard_key}:{cfg_sha}:{_sha256_text(combined_prompt)}"
        if cache.contains(prompt_key):
            self._pending_cache_keys = ()
            if (
                self._latest_user_step_idx is not None
                and self._latest_user_step_idx >= 0
            ):
                state = self._load_turn_state()
                scoped = self._get_hook_scoped_state(guard_key)
                if scoped.get("last_user_step_idx") != self._latest_user_step_idx:
                    scoped["last_user_step_idx"] = self._latest_user_step_idx
                    self._save_turn_state(state)
            return ScanExtractionResult(
                action="SKIP_CACHED",
                source=f"cache_hit:{source_tag}",
            )

        self._pending_cache_keys = (prompt_key,)
        return ScanExtractionResult(
            action="SCAN",
            text_to_scan=combined_prompt,
            source=source_tag,
        )

    def extract_scan_target(
        self, guard_key: str | None = None
    ) -> ScanExtractionResult:
        """Extracts actionable scan target with `nandi_read_cache.json` lookup."""
        key = guard_key or self.hook_name
        self._active_guard_key = key
        self._pending_cache_keys = ()

        # 1. PreToolUse inspection
        if self.tool_call and self.tool_args is not None:
            request = ToolScanRequest(
                tool_name=self.tool_name or "",
                tool_args=self.tool_args,
                workspace_paths=self.workspace_paths,
            )
            raw_res = self.scanner.extract_tool_scan_target(request)
            res = self._apply_tool_cache_lookup(key, raw_res)
            self._last_extraction = res
            return res

        # 2. PreInvocation inspection (prompt text + USER_INPUT.media ONLY; zero @file disk reads)
        self.clear_turn_blocked_for_new_invocation()
        is_blocked_now, block_reason_now = self.is_turn_blocked()
        if is_blocked_now:
            res = ScanExtractionResult(
                action="BLOCK_POLICY",
                block_reason=block_reason_now,
                source="turn:already_blocked",
            )
            self._last_extraction = res
            return res

        inv_num = self.payload.get("invocationNum", 0)
        h_state = self._get_hook_scoped_state(key)

        if self.transcript_path and os.path.exists(self.transcript_path):
            step_idx, latest_prompt, step_media = (
                self._extract_latest_user_step_record(self.transcript_path)
            )
            self._latest_user_step_idx = step_idx
            if (
                isinstance(inv_num, int)
                and not isinstance(inv_num, bool)
                and inv_num > 0
                and step_idx is not None
                and h_state.get("last_user_step_idx") == step_idx
            ):
                res = ScanExtractionResult(
                    action="SKIP_CACHED",
                    source="transcript:invocation_dedup",
                )
                self._last_extraction = res
                return res

            if step_idx is not None and (latest_prompt or step_media):
                transcript_dir = os.path.dirname(
                    os.path.abspath(self.transcript_path)
                )
                res = self._build_pre_invocation_target(
                    guard_key=key,
                    prompt_text=latest_prompt,
                    media_items=step_media,
                    source_tag="transcript:user_input",
                    transcript_dir=transcript_dir,
                )
                self._last_extraction = res
                return res

        payload_media_raw = self.payload.get("media")
        payload_media = (
            [m for m in payload_media_raw if isinstance(m, dict)]
            if isinstance(payload_media_raw, list)
            else []
        )

        for direct_key in (
            "prompt",
            "userPrompt",
            "content",
            "userMessage",
            "lastUserInput",
        ):
            if direct_key in self.payload:
                prompt_val = str(self.payload[direct_key] or "")
                self._latest_user_step_idx = -1
                res = self._build_pre_invocation_target(
                    guard_key=key,
                    prompt_text=prompt_val,
                    media_items=payload_media,
                    source_tag=f"payload:{direct_key}",
                )
                self._last_extraction = res
                return res

        if payload_media:
            self._latest_user_step_idx = -1
            res = self._build_pre_invocation_target(
                guard_key=key,
                prompt_text="",
                media_items=payload_media,
                source_tag="payload:media",
            )
            self._last_extraction = res
            return res

        res = ScanExtractionResult(action="NO_ACTIONABLE_TEXT")
        self._last_extraction = res
        return res

    def extract_text_to_scan(self) -> tuple[str, str]:
        """Legacy tuple interface returning `(text_to_scan, source)`."""
        res = self.extract_scan_target()
        if res.action == "SCAN":
            return res.text_to_scan, res.source
        return "", res.source

    def evaluate_model_armor(
        self,
        client: Any,
        evaluator: Any,
        text_to_scan: str,
        budget_seconds: float = DEFAULT_MODEL_ARMOR_BUDGET_SECONDS,
    ) -> Any:
        """Evaluates `text_to_scan` in 1 RPC (`<= 49,152` B) or parallel chunks.

        Payloads exceeding `MAX_SINGLE_SHOT_SCAN_BYTES` (`49,152` B) are split
        into `40,000`-char chunks with `4,096`-char overlap and evaluated across
        up to `4` `daemon=True` threads under a monotonic wall-clock deadline so
        stalled sockets fail closed before Antigravity's 30 s `SIGKILL`.
        """
        start_perf = time.perf_counter()
        deadline = time.monotonic() + max(0.05, float(budget_seconds))

        if len(text_to_scan.encode("utf-8")) <= MAX_SINGLE_SHOT_SCAN_BYTES:
            deadline_cm = (
                client.deadline_scope(deadline)
                if hasattr(client, "deadline_scope")
                else ModelArmorClient.deadline_scope(deadline)
            )
            with deadline_cm:
                response = client.sanitize_user_prompt(text_to_scan)
            return evaluator.evaluate(response)

        chunks = self.scanner.split_char_chunks(
            text_to_scan,
            chunk_chars=MULTI_CHUNK_MAX_CHARS,
            overlap_chars=MULTI_CHUNK_OVERLAP_CHARS,
        )

        work_queue: queue.Queue[tuple[int, str]] = queue.Queue()
        for idx, chunk in enumerate(chunks):
            work_queue.put((idx, chunk))

        result_queue: queue.Queue[tuple[int, Any, BaseException | None]] = (
            queue.Queue()
        )
        cancel_event = threading.Event()
        num_workers = min(MAX_MODEL_ARMOR_CHUNK_WORKERS, len(chunks))

        for worker_idx in range(num_workers):
            worker = threading.Thread(
                target=_model_armor_chunk_worker,
                args=(
                    work_queue,
                    result_queue,
                    cancel_event,
                    deadline,
                    client,
                    evaluator,
                ),
                name=f"nandi-ma-chunk-{worker_idx}",
                daemon=True,
            )
            worker.start()

        reports_by_idx: dict[int, Any] = {}
        while len(reports_by_idx) < len(chunks):
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0.0:
                    raise queue.Empty
                idx, report, worker_err = result_queue.get(timeout=remaining)
            except queue.Empty:
                cancel_event.set()
                elapsed_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
                timeout_resp = ModelArmorResponse(
                    success=False,
                    raw_response={},
                    filter_match_state="NO_MATCH_FOUND",
                    invocation_result="FAILURE",
                    filter_results={},
                    error_message=(
                        f"Model Armor multi-chunk scan exceeded "
                        f"{budget_seconds:.1f}s wall-clock deadline."
                    ),
                    latency_ms=elapsed_ms,
                )
                return evaluator.evaluate(timeout_resp)

            if worker_err is not None:
                cancel_event.set()
                elapsed_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
                err_resp = ModelArmorResponse(
                    success=False,
                    raw_response={},
                    filter_match_state="NO_MATCH_FOUND",
                    invocation_result="FAILURE",
                    filter_results={},
                    error_message=f"Model Armor chunk worker error: {worker_err}",
                    latency_ms=elapsed_ms,
                )
                return evaluator.evaluate(err_resp)

            reports_by_idx[idx] = report
            if not getattr(report, "is_allowed", True):
                cancel_event.set()
                report.latency_ms = round(
                    (time.perf_counter() - start_perf) * 1000.0, 2
                )
                return report

        ordered_reports = [reports_by_idx[i] for i in range(len(chunks))]
        final_report = ordered_reports[-1]
        final_report.latency_ms = round(
            (time.perf_counter() - start_perf) * 1000.0, 2
        )
        final_report.is_clean = all(
            bool(getattr(rep, "is_clean", False)) for rep in ordered_reports
        )
        merged_violations: list[str] = []
        for rep in ordered_reports:
            for viol in getattr(rep, "violations_detected", ()):
                if viol not in merged_violations:
                    merged_violations.append(viol)
        if merged_violations:
            final_report.violations_detected = merged_violations
        return final_report

    def get_event_type(self) -> str:
        """Determines the current hook event type from CLI flags or stdin payload."""
        for arg in sys.argv[1:]:
            if arg.startswith("--event="):
                return arg.split("=", 1)[1].strip().lower()

        if self.tool_call is not None or "toolCall" in self.payload:
            return "pre_tool_use"
        if (
            "invocationNum" in self.payload
            and "stepIdx" not in self.payload
            and not self.transcript_path
            and not any(
                k in self.payload
                for k in (
                    "prompt",
                    "userPrompt",
                    "content",
                    "userMessage",
                    "lastUserInput",
                    "media",
                )
            )
        ):
            return "post_invocation"
        return "pre_invocation"

    def reply_allow(
        self, reason: str = "Passed security checks", *, is_clean: bool = True
    ) -> None:
        """Emits an `allow` decision for `PreToolUse` and exits cleanly."""
        if is_clean:
            self.record_passed_scan()
        resp = {"decision": "allow", "reason": reason}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_deny(self, reason: str) -> None:
        """Emits a `deny` decision for `PreToolUse` and exits cleanly."""
        resp = {"decision": "deny", "reason": reason}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_force_ask(self, reason: str) -> None:
        """Emits a `force_ask` decision for `PreToolUse` and exits cleanly."""
        resp = {"decision": "force_ask", "reason": reason}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_pre_invocation(
        self,
        inject_message: str | None = None,
        *,
        is_clean: bool = True,
    ) -> None:
        """Emits a valid `PreInvocation` JSON response and exits cleanly."""
        if is_clean:
            self.record_passed_scan()
        if inject_message:
            resp: dict[str, Any] = {
                "injectSteps": [{"ephemeralMessage": inject_message}]
            }
        else:
            resp = {}

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_block_pre_invocation(self, reason: str) -> None:
        """Blocks a `PreInvocation` turn via `mark_turn_blocked` + `injectSteps`."""
        self.mark_turn_blocked(reason)
        resp = {
            "injectSteps": [
                {
                    "ephemeralMessage": (
                        "🛡️ [NANDI SECURITY GATEWAY]: Security Policy Violation "
                        f"Detected.\n{reason}\nThis request has been blocked and "
                        "will not be processed."
                    )
                },
                {
                    "systemMessage": {
                        "systemMessage": (
                            f"CRITICAL SECURITY POLICY OVERRIDE: {reason}. You MUST "
                            "NOT call any tools or execute any commands. Immediately "
                            "output a direct refusal stating that this prompt was "
                            "blocked by the security gateway and stop."
                        )
                    }
                },
            ]
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_post_invocation(self, terminate: bool = False) -> None:
        """Emits a valid `PostInvocation` response."""
        resp = {
            "injectSteps": [],
            "terminationBehavior": "terminate" if terminate else "",
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)
