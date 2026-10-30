"""Base Hook Handler implementing Antigravity JSON Hook Protocol over stdin/stdout."""

import json
import os
import stat
import sys
import tempfile
import time
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from src.file_guard.scanner import (
    BINARY_SNIFF_BYTES,
    CachedSliceRecord,
    FileScanConfig,
    FileScanner,
    MAX_SCAN_BYTES_PER_VIEW,
    MAX_SCAN_LINES_PER_VIEW,
    ScanExtractionResult,
    ToolScanRequest,
)

# Reverse JSONL reader block size (64 KiB) for O(1) tail lookups on large transcripts.
_REVERSE_READ_CHUNK_BYTES: int = 65_536

# Turn state expiration window in seconds (5 minutes).
_TURN_STATE_TTL_SECONDS: float = 300.0
_INITIALIZED_STATE_DIRS: Set[str] = set()


def _iter_jsonl_reverse(
    path: str, chunk_size: int = _REVERSE_READ_CHUNK_BYTES
) -> Iterator[Dict[str, Any]]:
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
                except Exception:
                    continue
        if carry.strip():
            try:
                obj = json.loads(
                    carry.strip().decode("utf-8", errors="replace")
                )
                if isinstance(obj, dict):
                    yield obj
            except Exception:
                pass


class AntigravityHookBase:
    """Base class for parsing Antigravity hook payloads and emitting protocol responses."""

    _MAX_SCAN_LINES: int = MAX_SCAN_LINES_PER_VIEW
    _MAX_SCAN_CHARS: int = MAX_SCAN_BYTES_PER_VIEW
    _BINARY_SNIFF_BYTES: int = BINARY_SNIFF_BYTES

    def __init__(
        self, hook_name: str, file_scan_config: Optional[FileScanConfig] = None
    ) -> None:
        self.hook_name = hook_name
        self.payload: Dict[str, Any] = {}
        self.conversation_id: str = "unknown"
        self.step_idx: Optional[int] = None
        self.transcript_path: Optional[str] = None
        self.tool_call: Optional[Dict[str, Any]] = None
        self.tool_name: Optional[str] = None
        self.tool_args: Dict[str, Any] = {}
        self.scanner = FileScanner(config=file_scan_config)
        self.file_scanner = self.scanner
        self._turn_state_cache: Optional[Dict[str, Any]] = None
        self._latest_user_step_idx: Optional[int] = None
        self._last_extraction: Optional[ScanExtractionResult] = None
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
        except Exception as exc:
            sys.stderr.write(
                f"[{self.hook_name}] Error parsing stdin JSON: {exc}\n"
            )

    @property
    def workspace_paths(self) -> List[str]:
        """Returns workspace directory paths from the hook payload."""
        raw_ws = self.payload.get("workspacePaths")
        if isinstance(raw_ws, list):
            return [w.strip() for w in raw_ws if isinstance(w, str) and w.strip()]
        return []

    @staticmethod
    def _get_state_dir() -> str:
        """Returns and initializes a 0o700 per-user directory for turn state files."""
        env_dir = os.environ.get("NANDI_STATE_DIR", "").strip()
        if env_dir:
            state_dir = os.path.abspath(env_dir)
        else:
            uid = getattr(os, "getuid", lambda: "win")()
            state_dir = os.path.join(
                tempfile.gettempdir(), f"nandi_state_{uid}"
            )
        if state_dir not in _INITIALIZED_STATE_DIRS or not os.path.isdir(state_dir):
            os.makedirs(state_dir, mode=0o700, exist_ok=True)
            if os.name != "nt":
                try:
                    os.chmod(state_dir, 0o700)
                except OSError:
                    pass
            _INITIALIZED_STATE_DIRS.add(state_dir)
        return state_dir

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
        """Backward-compatible alias returning the per-conversation turn state file path."""
        return self._get_turn_state_path()

    def _default_turn_state(self) -> Dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "timestamp": time.time(),
            "blocked": False,
            "reason": "",
            "step_idx": None,
            "blocked_inv_sig": None,
            "metadata": {},
            "prompt_files": [],
            "hooks": {},
        }

    def _load_turn_state(self) -> Dict[str, Any]:
        """Loads and memoizes per-conversation state with configurable state_ttl_seconds."""
        if self._turn_state_cache is not None:
            return self._turn_state_cache

        path = self._get_turn_state_path()
        state = self._default_turn_state()
        state_ttl = float(
            getattr(self.scanner.config, "state_ttl_seconds", 86_400)
        )
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    age = time.time() - float(loaded.get("timestamp", 0))
                    if age < state_ttl:
                        state.update(loaded)
                        if not isinstance(state.get("hooks"), dict):
                            state["hooks"] = {}
                        if state.get("blocked") and age >= _TURN_STATE_TTL_SECONDS:
                            state["blocked"] = False
                            state["reason"] = ""
                            state["blocked_inv_sig"] = None
                    else:
                        try:
                            os.remove(path)
                        except OSError:
                            pass
            except Exception:
                pass
        self._turn_state_cache = state
        return state

    def _save_turn_state(self, state: Dict[str, Any]) -> None:
        """Atomically writes turn state with 0o600 permissions."""
        state["conversation_id"] = self.conversation_id
        state["timestamp"] = time.time()
        self._turn_state_cache = state
        try:
            state_dir = self._get_state_dir()
            target_path = self._get_turn_state_path()
            fd, tmp_path = tempfile.mkstemp(dir=state_dir, prefix=".tmp_turn_")
            if os.name != "nt":
                try:
                    os.chmod(tmp_path, 0o600)
                except OSError:
                    pass
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
            os.replace(tmp_path, target_path)
        except Exception as exc:
            sys.stderr.write(
                f"[{self.hook_name}] Error saving turn state: {exc}\n"
            )

    def _get_hook_scoped_state(self, guard_key: Optional[str] = None) -> Dict[str, Any]:
        """Returns the state sub-dictionary isolated to a specific hook (`guard_key`)."""
        key = guard_key or self.hook_name
        state = self._load_turn_state()
        hooks_map = state.setdefault("hooks", {})
        return hooks_map.setdefault(
            key, {"last_user_step_idx": None, "cached_slices": []}
        )

    def get_cached_slices(
        self, guard_key: Optional[str] = None
    ) -> List[CachedSliceRecord]:
        """Returns verified clean file slices cached for `guard_key` in the active turn."""
        h_state = self._get_hook_scoped_state(guard_key)
        raw_list = h_state.get("cached_slices", [])
        records: List[CachedSliceRecord] = []
        if isinstance(raw_list, list):
            for item in raw_list:
                rec = CachedSliceRecord.from_list(item)
                if rec is not None:
                    records.append(rec)
        return records

    def record_passed_scan(
        self,
        extraction: Optional[ScanExtractionResult] = None,
        guard_key: Optional[str] = None,
    ) -> None:
        """Commits clean file slice records and user step index after a hook scan passes."""
        ext = extraction or self._last_extraction
        state = self._load_turn_state()
        h_state = self._get_hook_scoped_state(guard_key)
        dirty = False

        if self._latest_user_step_idx is not None:
            if h_state.get("last_user_step_idx") != self._latest_user_step_idx:
                h_state["last_user_step_idx"] = self._latest_user_step_idx
                dirty = True

        if ext is not None:
            if ext.prompt_files:
                existing_pf = set(state.get("prompt_files", []))
                new_pf = list(existing_pf.union(ext.prompt_files))
                if len(new_pf) != len(existing_pf):
                    state["prompt_files"] = new_pf
                    dirty = True
            if ext.scanned_slices:
                raw_slices = h_state.setdefault("cached_slices", [])
                for rec in ext.scanned_slices:
                    serialized = rec.to_list()
                    if serialized not in raw_slices:
                        raw_slices.append(serialized)
                        dirty = True

        if dirty:
            self._save_turn_state(state)

    def record_prompt_files(self, file_paths: Sequence[str]) -> None:
        """Persists resolved file paths referenced in the current user prompt."""
        state = self._load_turn_state()
        state["prompt_files"] = [p for p in file_paths if isinstance(p, str) and p]
        self._save_turn_state(state)

    def get_prompt_files(self) -> Set[str]:
        """Returns resolved file paths referenced in the user's prompt for the active turn."""
        state = self._load_turn_state()
        files: Set[str] = {
            item
            for item in state.get("prompt_files", [])
            if isinstance(item, str) and item
        }
        if self.transcript_path and os.path.exists(self.transcript_path):
            _, latest_prompt = self._extract_latest_user_step(self.transcript_path)
            if latest_prompt:
                files.update(
                    self.scanner.extract_prompt_file_paths(
                        latest_prompt, self.workspace_paths
                    )
                )
        for direct_key in (
            "prompt",
            "userPrompt",
            "content",
            "userMessage",
            "lastUserInput",
        ):
            if direct_key in self.payload and isinstance(
                self.payload[direct_key], str
            ):
                files.update(
                    self.scanner.extract_prompt_file_paths(
                        str(self.payload[direct_key]), self.workspace_paths
                    )
                )
        return files

    def _current_invocation_sig(self) -> str:
        inv_num = self.payload.get("invocationNum", 0)
        init_steps = self.payload.get("initialNumSteps", 0)
        return f"{init_steps}:{inv_num}"

    def mark_turn_blocked(
        self, reason: str, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Flags the current turn as blocked by security policy."""
        state = self._load_turn_state()
        state["blocked"] = True
        state["reason"] = reason
        state["step_idx"] = self.step_idx
        state["blocked_inv_sig"] = self._current_invocation_sig()
        state["metadata"] = metadata or {}
        self._save_turn_state(state)

    def is_turn_blocked(self) -> Tuple[bool, str]:
        """Checks if the current turn was flagged as blocked."""
        state = self._load_turn_state()
        if state.get("blocked"):
            return True, str(
                state.get("reason") or "Security policy violation detected."
            )
        return False, ""

    def clear_turn_blocked(self) -> None:
        """Clears the blocked turn flag."""
        state = self._load_turn_state()
        if state.get("blocked"):
            state["blocked"] = False
            state["reason"] = ""
            state["blocked_inv_sig"] = None
            self._save_turn_state(state)

    def clear_turn_blocked_for_new_invocation(self) -> None:
        """Clears stale turn-block state from an earlier invocation without erasing a peer hook's block."""
        state = self._load_turn_state()
        if state.get("blocked"):
            if state.get("blocked_inv_sig") != self._current_invocation_sig():
                state["blocked"] = False
                state["reason"] = ""
                state["blocked_inv_sig"] = None
                self._save_turn_state(state)

    def _extract_latest_user_step(
        self, transcript_path: str
    ) -> Tuple[Optional[int], Optional[str]]:
        """Reads the latest USER_INPUT step in O(1) tail blocks, preferring compact transcript.jsonl."""
        try:
            compact_path = transcript_path
            if transcript_path.endswith("transcript_full.jsonl"):
                candidate_compact = os.path.join(
                    os.path.dirname(transcript_path), "transcript.jsonl"
                )
                if os.path.exists(candidate_compact):
                    compact_path = candidate_compact

            for step in _iter_jsonl_reverse(compact_path):
                s_type = step.get("type", "")
                source = step.get("source", "")
                if s_type == "USER_INPUT" or source == "USER_EXPLICIT":
                    step_idx = step.get("step_index")
                    idx_val = int(step_idx) if isinstance(step_idx, int) else -1
                    truncated = step.get("truncated_fields") or []
                    if (
                        "content" in truncated
                        and compact_path != transcript_path
                        and os.path.exists(transcript_path)
                    ):
                        for full_step in _iter_jsonl_reverse(transcript_path):
                            if full_step.get("step_index") == step_idx and (
                                full_step.get("type") == "USER_INPUT"
                                or full_step.get("source") == "USER_EXPLICIT"
                            ):
                                content_full = full_step.get("content", "")
                                if content_full:
                                    return idx_val, str(content_full)
                                break
                    content = step.get("content", "")
                    if content:
                        return idx_val, str(content)
        except Exception as exc:
            sys.stderr.write(
                f"[{self.hook_name}] Error reading transcript: {exc}\n"
            )
        return None, None

    def _extract_latest_user_prompt_from_transcript(
        self, transcript_path: str
    ) -> Optional[str]:
        """Returns the content string of the latest USER_INPUT step."""
        _, content = self._extract_latest_user_step(transcript_path)
        return content

    def _read_file_slice(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        byte_offset: int = 0,
    ) -> Optional[str]:
        """Reads a bounded UTF-8 slice from a regular file via FileScanner."""
        paged = self.scanner.read_paged_slice(
            file_path,
            start_line=start_line,
            end_line=end_line,
            byte_offset=byte_offset,
            workspace_paths=self.workspace_paths,
        )
        return paged[0] if paged is not None else None

    @staticmethod
    def _is_git_tracked_file(resolved_path: str) -> bool:
        """Returns True if resolved_path is a clean, non-ignored Git-tracked file."""
        real_p = os.path.realpath(os.path.abspath(resolved_path))
        parent = os.path.dirname(real_p)
        scanner = FileScanner(config=FileScanConfig(mode="untrusted_and_prompt"))
        return not scanner.should_scan_tool_file(real_p, [parent], set())

    def extract_scan_target(
        self, guard_key: Optional[str] = None
    ) -> ScanExtractionResult:
        """Extracts actionable scan target with clean-slice caching and invocationNum dedup."""
        key = guard_key or self.hook_name

        # 1. PreToolUse inspection
        if self.tool_call and self.tool_args is not None:
            request = ToolScanRequest(
                tool_name=self.tool_name or "",
                tool_args=self.tool_args,
                workspace_paths=self.workspace_paths,
                prompt_files=self.get_prompt_files(),
                cached_slices=self.get_cached_slices(key),
            )
            res = self.scanner.extract_tool_scan_target(request)
            self._last_extraction = res
            return res

        # 2. PreInvocation inspection
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
            step_idx, latest_prompt = self._extract_latest_user_step(
                self.transcript_path
            )
            self._latest_user_step_idx = step_idx
            if (
                isinstance(inv_num, int)
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

            if latest_prompt:
                res = self.scanner.extract_prompt_scan_target(
                    latest_prompt, "transcript:user_input", self.workspace_paths
                )
                if res.prompt_files:
                    self.record_prompt_files(res.prompt_files)
                self._last_extraction = res
                return res

        for direct_key in (
            "prompt",
            "userPrompt",
            "content",
            "userMessage",
            "lastUserInput",
        ):
            if direct_key in self.payload:
                prompt_val = str(self.payload[direct_key])
                self._latest_user_step_idx = -1
                res = self.scanner.extract_prompt_scan_target(
                    prompt_val, f"payload:{direct_key}", self.workspace_paths
                )
                if res.prompt_files:
                    self.record_prompt_files(res.prompt_files)
                self._last_extraction = res
                return res

        res = ScanExtractionResult(action="NO_ACTIONABLE_TEXT")
        self._last_extraction = res
        return res

    def extract_text_to_scan(self) -> Tuple[str, str]:
        """Legacy tuple interface returning (text_to_scan, source)."""
        res = self.extract_scan_target()
        if res.action == "SCAN":
            return res.text_to_scan, res.source
        return "", res.source

    def evaluate_model_armor(
        self, client: Any, evaluator: Any, text_to_scan: str
    ) -> Any:
        """Evaluates text_to_scan via Model Armor in single-request or 45 KiB chunked mode."""
        if getattr(self.scanner.config, "unpaged_scan_mode", "single") != "chunk":
            response = client.sanitize_user_prompt(text_to_scan)
            return evaluator.evaluate(response)

        chunks = self.scanner.split_utf8_chunks(
            text_to_scan,
            chunk_bytes=MAX_SCAN_BYTES_PER_VIEW,
        )
        if not chunks:
            chunks = [text_to_scan]
        last_report = None
        total_latency_ms = 0.0
        for chunk in chunks:
            response = client.sanitize_user_prompt(chunk)
            eval_report = evaluator.evaluate(response)
            total_latency_ms += float(getattr(eval_report, "latency_ms", 0.0))
            last_report = eval_report
            if not eval_report.is_allowed:
                eval_report.latency_ms = round(total_latency_ms, 2)
                return eval_report
        if last_report is not None:
            last_report.latency_ms = round(total_latency_ms, 2)
        return last_report

    def get_event_type(self) -> str:
        """Determines the current hook event type from CLI flags or stdin payload."""
        for arg in sys.argv[1:]:
            if arg.startswith("--event="):
                return arg.split("=", 1)[1].strip().lower()

        if self.tool_call is not None or "toolCall" in self.payload:
            return "pre_tool_use"
        if "invocationNum" in self.payload and "stepIdx" not in self.payload and not self.transcript_path:
            return "post_invocation"
        return "pre_invocation"

    def reply_allow(self, reason: str = "Passed security checks") -> None:
        """Emits an allow decision for PreToolUse and exits cleanly."""
        self.record_passed_scan()
        resp = {"decision": "allow", "reason": reason}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_deny(self, reason: str) -> None:
        """Emits a deny decision for PreToolUse and exits cleanly."""
        resp = {"decision": "deny", "reason": reason}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_force_ask(self, reason: str) -> None:
        """Emits a force_ask decision for PreToolUse and exits cleanly."""
        resp = {"decision": "force_ask", "reason": reason}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_pre_invocation(self, inject_message: Optional[str] = None) -> None:
        """Emits a valid PreInvocation JSON response."""
        self.record_passed_scan()
        if inject_message:
            resp = {
                "injectSteps": [
                    {
                        "ephemeralMessage": inject_message
                    }
                ]
            }
        else:
            resp = {}

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_block_pre_invocation(self, reason: str) -> None:
        """Deterministic block for PreInvocation.

        Persists the block flag, emits injectSteps with an ephemeral notification and a
        system-level security override directive, and exits cleanly (code 0) so the prompt
        is rejected without continuing to normal LLM execution or tool invocation.
        """
        self.mark_turn_blocked(reason)
        resp = {
            "injectSteps": [
                {
                    "ephemeralMessage": f"🛡️ [NANDI SECURITY GATEWAY]: Security Policy Violation Detected.\n{reason}\nThis request has been blocked and will not be processed."
                },
                {
                    "systemMessage": {
                        "systemMessage": f"CRITICAL SECURITY POLICY OVERRIDE: {reason}. You MUST NOT call any tools or execute any commands. Immediately output a direct refusal stating that this prompt was blocked by the security gateway and stop."
                    }
                }
            ]
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    def reply_post_invocation(self, terminate: bool = False) -> None:
        """Emits a valid PostInvocation response."""
        resp = {
            "injectSteps": [],
            "terminationBehavior": "terminate" if terminate else ""
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        sys.exit(0)
