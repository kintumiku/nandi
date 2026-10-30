"""Policy-driven file slice reader and Git workspace trust evaluator.

This module isolates all filesystem, Git status, shell argument extraction, and
line/byte-slicing logic from the Antigravity hook wire protocol (`src.hooks`)
so both lifecycle hooks and the administrative CLI (`src.cli.grc_admin`) share
a single, zero-dependency implementation.
"""

import dataclasses
import json
import os
import re
import shlex
import stat
import subprocess
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# File-Scanning & Slicing Constants (Aligned with Antigravity ReadFileTool)
# ---------------------------------------------------------------------------

# Matches Antigravity's ReadFileTool per-view line cap (MaxLinesPerView = 800
# in cortex/config/defaults.go) so a single paged read inspects the exact line
# window returned to the model.
MAX_SCAN_LINES_PER_VIEW: int = 800

# Matches Antigravity's ReadFileTool per-view byte ceiling (MaxBytesPerView =
# 45 * 1024 = 46,080 bytes in cortex/config/defaults.go), eliminating any blind
# spot between 40,000 characters and 46,080 bytes while staying below Cloud
# DLP's 50 KB single-request inspection threshold.
MAX_SCAN_BYTES_PER_VIEW: int = 46_080

# Matches Antigravity's ReadFileTool maximum file size (MaxFileSizeBytes =
# 100 * 1024 * 1024 = 100 MiB in cortex/config/defaults.go) for streaming
# line-paged reads (read_file / view_file).
MAX_PAGED_FILE_SIZE_BYTES: int = 104_857_600

# Default 2 MiB ceiling for unpaginated tool reads (grep_search, notebook_edit,
# run_command file dumps) where the entire file could otherwise be ingested at
# once without line pagination.
DEFAULT_MAX_UNPAGED_FILE_BYTES: int = 2_097_152
DEFAULT_UNPAGED_MAX_FILE_BYTES: int = DEFAULT_MAX_UNPAGED_FILE_BYTES

# Customer-configurable bounds for max_file_size_bytes ([45 KiB, 4 MiB]) so
# policies cannot be set smaller than one read_file page or large enough to
# exhaust hook execution timeouts.
MIN_CONFIGURABLE_UNPAGED_BYTES: int = 46_080
MAX_CONFIGURABLE_UNPAGED_BYTES: int = 4_194_304

# Matches standard OS 4 KiB memory page size and Git's binary-buffer sniff
# window: after checking for UTF-16LE/BE BOMs (\xff\xfe / \xfe\xff), any NUL
# byte (\x00) in the first 4,096 bytes classifies the file as binary.
BINARY_SNIFF_BYTES: int = 4_096

# Backward UTF-8-aligned byte overlap applied when ByteOffset > 0 so multi-char
# Indian PII tokens (12-digit Aadhaar, 16-digit card numbers, 15-char GSTIN)
# straddling a 46,080-byte page boundary remain intact on the continuation page.
BYTE_OFFSET_OVERLAP_BYTES: int = 128

# Subprocess timeout for batched `git status --porcelain=v1` checks, bounded
# well inside the 15-second hook timeout and failing closed (untrusted) on error.
GIT_STATUS_TIMEOUT_SECONDS: float = 3.0

VALID_SCAN_MODES: Tuple[str, ...] = (
    "untrusted_and_prompt",
    "all",
    "prompt_only",
)
VALID_OVERSIZE_ACTIONS: Tuple[str, ...] = ("BLOCK", "TRUNCATE")
VALID_UNPAGED_SCAN_MODES: Tuple[str, ...] = ("single", "chunk", "block")
DEFAULT_STATE_TTL_SECONDS: int = 86_400
MIN_STATE_TTL_SECONDS: int = 300
MAX_STATE_TTL_SECONDS: int = 604_800
MAX_DIR_EXPANSION_FILES: int = 64

SHELL_SEARCH_COMMANDS: Set[str] = {
    "rg",
    "grep",
    "egrep",
    "fgrep",
    "findstr",
    "select-string",
}

FILE_READ_TOOLS: Set[str] = {
    "read_file",
    "view_file",
    "view_file_outline",
    "view_code_item",
}

SHELL_READ_COMMANDS: Set[str] = {
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "bat",
    "nl",
    "get-content",
    "gc",
    "type",
    "awk",
    "gawk",
    "mawk",
    "sed",
    "jq",
    "yq",
    "rg",
    "grep",
    "egrep",
    "fgrep",
    "findstr",
    "select-string",
    "strings",
    "base64",
    "xxd",
    "hexdump",
    "od",
    "sort",
    "uniq",
    "cut",
    "wc",
    "diff",
    "comm",
    "paste",
    "join",
    "curl",
    "wget",
    "python",
    "python3",
    "py",
    "node",
    "perl",
    "ruby",
    "sh",
    "bash",
    "zsh",
    "pwsh",
    "powershell",
}

INLINE_TEXT_KEYS: Tuple[str, ...] = (
    "CommandLine",
    "CodeContent",
    "Content",
    "TargetContent",
    "ReplacementContent",
    "Target",
    "Replacement",
    "Query",
    "Message",
    "Prompt",
)

_TRANSCRIPT_FILE_RE = re.compile(
    r"@\[[^\]]+\]\s+is\s+a\s+\[File\]:\s*\r?\n([^\r\n<]+)"
)
_TRANSCRIPT_CODE_ITEM_RE = re.compile(
    r"@\[[^\]]+\]\s+is\s+a\s+\[Code Item\]:\s*\r?\n(\{[^\r\n]+\})"
)
_AT_MENTION_RE = re.compile(
    r'(?:^|[\s(\[{"\'])@(?:(?:"([^"]+)")|(?:\'([^\']+)\')|(?:\[([^\]]+)\])|([^\s)\]}",;<>]+))'
)
_PATH_TOKEN_RE = re.compile(
    r'(?:"([^"\r\n]+)"|\'([^\'\r\n]+)\'|([^\s"\'`()\[\]{}<>,;]+))'
)
_FILE_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9]{1,10}$")
_PROSE_ABBREV_RE = re.compile(
    r"^(?:v?\d+(?:\.\d+)+|e\.g|i\.e|etc|vs|cf|viz|fig|sec|para|no|mr|mrs|ms|dr|prof|sr|jr|st|lt|col|gen|inc|ltd|co|corp|[A-Z0-9]{2,6}/[A-Z0-9]{2,6})$",
    re.IGNORECASE,
)
_INLINE_FILE_LITERAL_RE = re.compile(
    r"""(?:open|read_text|read_bytes|readFileSync|read_csv|read_json|read_excel|load)\s*\(\s*[rRbBuU]?['"]([^'"\r\n]+)['"]"""
)


def _parse_bool(raw_val: Any, default: bool) -> bool:
    """Parses a boolean from YAML or environment string representations."""
    if isinstance(raw_val, bool):
        return raw_val
    if isinstance(raw_val, str):
        lowered = raw_val.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    return default


def _parse_yaml_section(yaml_text: str, section_name: str) -> Dict[str, str]:
    """Extracts key-value pairs scoped strictly to a top-level YAML mapping block.

    Used when PyYAML is not installed in the runtime so `file_scanning.enabled`
    never collides with `pii_guard.enabled` or `model_armor.enabled`.
    """
    result: Dict[str, str] = {}
    in_section = False
    section_indent: Optional[int] = None

    for raw_line in yaml_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if not in_section:
            if indent == 0 and re.match(
                rf"^{re.escape(section_name)}\s*:\s*(?:#.*)?$", stripped
            ):
                in_section = True
                section_indent = None
            continue

        if indent == 0:
            break
        if section_indent is None:
            section_indent = indent
        if indent != section_indent:
            continue

        kv_match = re.match(r"^([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$", stripped)
        if not kv_match:
            continue
        key = kv_match.group(1)
        val_part = kv_match.group(2)
        val_no_comment = re.sub(r"\s+#.*$", "", val_part).strip()
        if (
            len(val_no_comment) >= 2
            and val_no_comment[0] == val_no_comment[-1]
            and val_no_comment[0] in {"'", '"'}
        ):
            val_no_comment = val_no_comment[1:-1]
        result[key] = val_no_comment
    return result


def _is_prose_non_path_token(token: str) -> bool:
    """Returns True if token is a prose abbreviation, version number, or slash acronym."""
    if not token or len(token) < 3:
        return True
    if _PROSE_ABBREV_RE.match(token):
        return True
    if "/" in token and not token.startswith(("/", "./", "../", "~/")):
        parts = token.split("/")
        if len(parts) == 2 and all(
            (part.isupper() and len(part) <= 6) or part.isdigit()
            for part in parts
            if part
        ):
            return True
    return False


def _split_shell_segments(cmd_line: str) -> List[str]:
    """Splits a shell command string on unquoted |, ||, &&, ;, and newline tokens."""
    segments: List[str] = []
    buf: List[str] = []
    in_single = False
    in_double = False
    escaped = False
    idx = 0
    length = len(cmd_line)

    while idx < length:
        ch = cmd_line[idx]
        if escaped:
            buf.append(ch)
            escaped = False
            idx += 1
            continue
        if ch == "\\" and not in_single:
            escaped = True
            buf.append(ch)
            idx += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            idx += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            idx += 1
            continue
        if not in_single and not in_double:
            if cmd_line[idx : idx + 2] in ("&&", "||"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                idx += 2
                continue
            if ch in "|;\n":
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                idx += 1
                continue
        buf.append(ch)
        idx += 1

    tail_seg = "".join(buf).strip()
    if tail_seg:
        segments.append(tail_seg)
    return segments


def _decode_raw_bytes(
    raw_bytes: bytes, sniff_window: bytes
) -> Optional[str]:
    """Decodes raw file bytes as UTF-16 (if BOM present) or UTF-8, skipping binary files."""
    if sniff_window.startswith(b"\xff\xfe"):
        body = raw_bytes[2:] if raw_bytes.startswith(b"\xff\xfe") else raw_bytes
        return body.decode("utf-16-le", errors="replace")
    if sniff_window.startswith(b"\xfe\xff"):
        body = raw_bytes[2:] if raw_bytes.startswith(b"\xfe\xff") else raw_bytes
        return body.decode("utf-16-be", errors="replace")
    if b"\x00" in sniff_window:
        return None
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raw_bytes = raw_bytes[3:]
    return raw_bytes.decode("utf-8", errors="replace")


_YAML_SECTION_CACHE: Dict[Tuple[str, int], Dict[str, Any]] = {}


@dataclasses.dataclass(frozen=True)
class FileScanConfig:
    """Customer-configurable file scanning policy resolved from config.yaml and env vars."""

    enabled: bool = True
    mode: str = "prompt_only"
    max_file_size_bytes: int = DEFAULT_MAX_UNPAGED_FILE_BYTES
    oversize_action: str = "TRUNCATE"
    unpaged_scan_mode: str = "single"
    state_ttl_seconds: int = DEFAULT_STATE_TTL_SECONDS

    @property
    def effective_mode(self) -> str:
        """Returns the active scan mode, or 'disabled' when enabled is False."""
        return self.mode if self.enabled else "disabled"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the active file scanning configuration for CLI and JSON output."""
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "effective_mode": self.effective_mode,
            "max_file_size_bytes": self.max_file_size_bytes,
            "oversize_action": self.oversize_action,
            "unpaged_scan_mode": self.unpaged_scan_mode,
            "state_ttl_seconds": self.state_ttl_seconds,
        }

    @classmethod
    def from_config(
        cls,
        config_path: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        force_stdlib_parser: bool = False,
    ) -> "FileScanConfig":
        """Loads FileScanConfig with precedence: env vars > config.yaml > defaults."""
        del force_stdlib_parser  # Unused; _parse_yaml_section is always fast and zero-dep.
        env_map: Mapping[str, str] = env if env is not None else os.environ
        if not config_path:
            plugin_root = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            config_path = os.path.join(plugin_root, "config", "config.yaml")

        raw_sec: Dict[str, Any] = {}
        if config_path:
            try:
                st = os.stat(config_path)
                cache_key = (os.path.abspath(config_path), st.st_mtime_ns)
                cached = _YAML_SECTION_CACHE.get(cache_key)
                if cached is not None:
                    raw_sec = cached
                else:
                    with open(config_path, "r", encoding="utf-8") as cfg_file:
                        yaml_text = cfg_file.read()
                    raw_sec = _parse_yaml_section(yaml_text, "file_scanning")
                    _YAML_SECTION_CACHE[cache_key] = raw_sec
            except OSError:
                pass

        enabled = _parse_bool(raw_sec.get("enabled"), True)
        if env_map.get("NANDI_FILE_SCAN_ENABLED", "").strip():
            enabled = _parse_bool(env_map["NANDI_FILE_SCAN_ENABLED"], enabled)

        mode = str(raw_sec.get("mode", "prompt_only")).strip().lower()
        if env_map.get("NANDI_FILE_SCAN_MODE", "").strip():
            mode = env_map["NANDI_FILE_SCAN_MODE"].strip().lower()
        if mode not in VALID_SCAN_MODES:
            mode = "prompt_only"

        try:
            max_bytes = int(
                env_map.get("NANDI_FILE_SCAN_MAX_BYTES", "").strip()
                or env_map.get("NANDI_MAX_FILE_SIZE_BYTES", "").strip()
                or raw_sec.get("max_file_size_bytes", DEFAULT_MAX_UNPAGED_FILE_BYTES)
            )
        except (TypeError, ValueError):
            max_bytes = DEFAULT_MAX_UNPAGED_FILE_BYTES
        max_bytes = max(
            MIN_CONFIGURABLE_UNPAGED_BYTES,
            min(max_bytes, MAX_CONFIGURABLE_UNPAGED_BYTES),
        )

        oversize = str(
            env_map.get("NANDI_FILE_SCAN_OVERSIZE_ACTION", "").strip()
            or env_map.get("NANDI_OVERSIZE_FILE_ACTION", "").strip()
            or raw_sec.get("oversize_action", "TRUNCATE")
        ).strip().upper()
        if oversize not in VALID_OVERSIZE_ACTIONS:
            oversize = "TRUNCATE"

        unpaged_mode = str(
            env_map.get("NANDI_FILE_SCAN_UNPAGED_MODE", "").strip()
            or raw_sec.get("unpaged_scan_mode", "single")
        ).strip().lower()
        if unpaged_mode not in VALID_UNPAGED_SCAN_MODES:
            unpaged_mode = "single"

        try:
            state_ttl = int(
                env_map.get("NANDI_STATE_TTL_SECONDS", "").strip()
                or env_map.get("NANDI_FILE_SCAN_STATE_TTL_SECONDS", "").strip()
                or raw_sec.get("state_ttl_seconds", DEFAULT_STATE_TTL_SECONDS)
            )
        except (TypeError, ValueError):
            state_ttl = DEFAULT_STATE_TTL_SECONDS
        state_ttl = max(
            MIN_STATE_TTL_SECONDS,
            min(state_ttl, MAX_STATE_TTL_SECONDS),
        )

        return cls(
            enabled=enabled,
            mode=mode,
            max_file_size_bytes=max_bytes,
            oversize_action=oversize,
            unpaged_scan_mode=unpaged_mode,
            state_ttl_seconds=state_ttl,
        )


@dataclasses.dataclass(frozen=True)
class CachedSliceRecord:
    """Represents a file slice that passed security inspection in the active turn."""

    real_path: str
    mtime_ns: int
    size: int
    start_line: int
    end_line: int
    byte_start: int
    byte_end: int

    def covers(
        self,
        real_path: str,
        mtime_ns: int,
        size: int,
        start_line: int,
        end_line: int,
        byte_start: int,
        byte_end: int,
    ) -> bool:
        """Returns True if this cached record covers the requested slice on an unchanged file."""
        return (
            self.real_path == real_path
            and self.mtime_ns == mtime_ns
            and self.size == size
            and self.start_line <= start_line
            and self.end_line >= end_line
            and self.byte_start <= byte_start
            and self.byte_end >= byte_end
        )

    def to_list(self) -> List[Any]:
        """Serializes record into a compact JSON-compatible list."""
        return [
            self.real_path,
            self.mtime_ns,
            self.size,
            self.start_line,
            self.end_line,
            self.byte_start,
            self.byte_end,
        ]

    @classmethod
    def from_list(cls, data: Sequence[Any]) -> Optional["CachedSliceRecord"]:
        """Deserializes a CachedSliceRecord from a JSON list."""
        if not isinstance(data, (list, tuple)) or len(data) != 7:
            return None
        try:
            return cls(
                real_path=str(data[0]),
                mtime_ns=int(data[1]),
                size=int(data[2]),
                start_line=int(data[3]),
                end_line=int(data[4]),
                byte_start=int(data[5]),
                byte_end=int(data[6]),
            )
        except (TypeError, ValueError):
            return None


@dataclasses.dataclass(frozen=True)
class ToolScanRequest:
    """Value object encapsulating a PreToolUse inspection request."""

    tool_name: str
    tool_args: Dict[str, Any]
    workspace_paths: List[str]
    prompt_files: Set[str]
    cached_slices: Sequence[CachedSliceRecord] = ()


@dataclasses.dataclass(frozen=True)
class ScanExtractionResult:
    """Outcome of extracting actionable text or file slices for hook inspection."""

    action: str  # "SCAN" | "SKIP_CACHED" | "NO_ACTIONABLE_TEXT" | "BLOCK_POLICY"
    text_to_scan: str = ""
    source: str = "empty"
    block_reason: str = ""
    scanned_slices: Tuple[CachedSliceRecord, ...] = ()
    prompt_files: Tuple[str, ...] = ()


class FileScanner:
    """Streams bounded file slices and evaluates Git workspace trust for hook inspection."""

    def __init__(
        self,
        config: Optional[FileScanConfig] = None,
        plugin_root: Optional[str] = None,
    ) -> None:
        self.plugin_root = plugin_root or os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        self.config = config or FileScanConfig.from_config(
            os.path.join(self.plugin_root, "config", "config.yaml")
        )
        self._git_repo_cache: Dict[str, Optional[str]] = {}

    def resolve_candidate_path(
        self,
        raw_path: str,
        workspace_paths: Sequence[str] = (),
        cwd: Optional[str] = None,
    ) -> Optional[str]:
        """Resolves a candidate file path against workspacePaths or cwd if it is a regular file."""
        if not raw_path or not isinstance(raw_path, str):
            return None
        cleaned = raw_path.strip().strip("\"'`[]()")
        if cleaned.startswith("file://"):
            cleaned = cleaned[len("file://") :]
        cleaned = re.sub(
            r"(?:#L?\d+(?:-L?\d+)?|:L?\d+(?:[-:]L?\d+)?)$", "", cleaned
        )
        if not cleaned:
            return None

        variants = [cleaned]
        stripped_punct = cleaned.rstrip(".,;:!?")
        if stripped_punct and stripped_punct != cleaned:
            variants.append(stripped_punct)

        valid_ws = [
            ws_dir.strip()
            for ws_dir in workspace_paths
            if isinstance(ws_dir, str) and ws_dir.strip()
        ]
        fallback_dirs: List[str] = []
        if cwd and isinstance(cwd, str) and cwd.strip():
            fallback_dirs.append(cwd.strip())
        elif not valid_ws:
            fallback_dirs.append(os.getcwd())
        env_pwd = os.environ.get("PWD", "").strip()
        if env_pwd and os.path.isdir(env_pwd) and env_pwd not in fallback_dirs:
            fallback_dirs.append(env_pwd)

        for variant in variants:
            expanded = os.path.expanduser(variant)
            candidates: List[str] = []
            if os.path.isabs(expanded):
                candidates.append(expanded)
            else:
                for ws_dir in valid_ws:
                    candidates.append(os.path.join(ws_dir, expanded))
                for fb_dir in fallback_dirs:
                    candidates.append(os.path.abspath(os.path.join(fb_dir, expanded)))

            for candidate_path in candidates:
                try:
                    stat_result = os.stat(candidate_path)
                    if stat.S_ISREG(stat_result.st_mode):
                        return os.path.abspath(candidate_path)
                except OSError:
                    continue
        return None

    @staticmethod
    def split_utf8_chunks(
        text: str,
        chunk_bytes: int = MAX_SCAN_BYTES_PER_VIEW,
        overlap_bytes: int = BYTE_OFFSET_OVERLAP_BYTES,
    ) -> List[str]:
        """Splits text into UTF-8 byte-bounded chunks with boundary overlap."""
        if not text:
            return []
        raw = text.encode("utf-8")
        if len(raw) <= chunk_bytes:
            return [text]
        chunks: List[str] = []
        start = 0
        total = len(raw)
        safe_overlap = max(0, overlap_bytes)
        while start < total:
            end = min(total, start + chunk_bytes)
            if end < total:
                while end > start and (raw[end] & 0xC0) == 0x80:
                    end -= 1
            chunk_str = raw[start:end].decode("utf-8", errors="replace")
            if chunk_str:
                chunks.append(chunk_str)
            if end >= total:
                break
            next_start = end - safe_overlap
            while next_start < end and (raw[next_start] & 0xC0) == 0x80:
                next_start += 1
            if next_start <= start:
                next_start = end
            start = next_start
        return chunks

    def resolve_candidate_directory(
        self,
        raw_path: str,
        workspace_paths: Sequence[str] = (),
        cwd: Optional[str] = None,
    ) -> Optional[str]:
        """Resolves a candidate directory path against workspacePaths or cwd if it is a directory."""
        if not raw_path or not isinstance(raw_path, str):
            return None
        cleaned = raw_path.strip().strip("\"'`[]()")
        if cleaned.startswith("file://"):
            cleaned = cleaned[len("file://") :]
        if not cleaned:
            return None

        variants = [cleaned]
        stripped_punct = cleaned.rstrip(".,;:!?")
        if stripped_punct and stripped_punct != cleaned:
            variants.append(stripped_punct)

        valid_ws = [
            ws_dir.strip()
            for ws_dir in workspace_paths
            if isinstance(ws_dir, str) and ws_dir.strip()
        ]
        fallback_dirs: List[str] = []
        if cwd and isinstance(cwd, str) and cwd.strip():
            fallback_dirs.append(cwd.strip())
        elif not valid_ws:
            fallback_dirs.append(os.getcwd())
        env_pwd = os.environ.get("PWD", "").strip()
        if env_pwd and os.path.isdir(env_pwd) and env_pwd not in fallback_dirs:
            fallback_dirs.append(env_pwd)

        for variant in variants:
            expanded = os.path.expanduser(variant)
            candidates: List[str] = []
            if os.path.isabs(expanded):
                candidates.append(expanded)
            else:
                for ws_dir in valid_ws:
                    candidates.append(os.path.join(ws_dir, expanded))
                for fb_dir in fallback_dirs:
                    candidates.append(os.path.abspath(os.path.join(fb_dir, expanded)))

            for candidate_path in candidates:
                try:
                    stat_result = os.stat(candidate_path)
                    if stat.S_ISDIR(stat_result.st_mode):
                        return os.path.abspath(candidate_path)
                except OSError:
                    continue
        return None

    @staticmethod
    def _append_regular_file_under_dir(
        cand_path: str,
        real_dir: str,
        seen_real: Set[str],
        expanded: List[str],
    ) -> None:
        """Appends cand_path to expanded if it is an unseen regular file inside real_dir."""
        if len(expanded) >= MAX_DIR_EXPANSION_FILES:
            return
        try:
            st_cand = os.stat(cand_path)
            if not stat.S_ISREG(st_cand.st_mode):
                return
            real_cand = os.path.realpath(cand_path)
            if real_cand in seen_real:
                return
            if os.path.commonpath([real_cand, real_dir]) != real_dir:
                return
            seen_real.add(real_cand)
            expanded.append(os.path.abspath(cand_path))
        except (OSError, ValueError):
            return

    @classmethod
    def _walk_directory_bounded(
        cls,
        root_dir: str,
        real_dir: str,
        seen_real: Set[str],
        expanded: List[str],
    ) -> None:
        """Walks root_dir deterministically up to MAX_DIR_EXPANSION_FILES regular files."""
        for walk_root, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if d not in {".git", "__pycache__", "node_modules"}
            ]
            for fname in sorted(filenames):
                if len(expanded) >= MAX_DIR_EXPANSION_FILES:
                    return
                cls._append_regular_file_under_dir(
                    os.path.join(walk_root, fname),
                    real_dir,
                    seen_real,
                    expanded,
                )

    def expand_directory_targets(
        self,
        dir_path: str,
        workspace_paths: Sequence[str],
        prompt_files: Set[str],
    ) -> List[str]:
        """Expands a directory target into prompt-referenced and untrusted regular files."""
        if not self.config.enabled:
            return []
        try:
            real_dir = os.path.realpath(os.path.abspath(dir_path))
            if not os.path.isdir(real_dir):
                return []
        except OSError:
            return []

        expanded: List[str] = []
        seen_real: Set[str] = set()

        # 1. Always include prompt-referenced files residing under real_dir.
        for pf in sorted(prompt_files):
            resolved_pf = self.resolve_candidate_path(pf, workspace_paths)
            if resolved_pf:
                self._append_regular_file_under_dir(
                    resolved_pf, real_dir, seen_real, expanded
                )

        if self.config.mode == "prompt_only":
            return expanded

        if self.config.mode == "all":
            self._walk_directory_bounded(real_dir, real_dir, seen_real, expanded)
            return expanded

        # 2. In untrusted_and_prompt mode, enumerate dirty/untracked/ignored files via Git status
        # when inside a Git workspace, or walk the directory when outside a Git workspace.
        repo_root = (
            self._find_git_repo_root(real_dir)
            if self.is_within_workspace_paths(real_dir, workspace_paths)
            else None
        )
        if not repo_root:
            self._walk_directory_bounded(real_dir, real_dir, seen_real, expanded)
            return expanded

        rel_dir = os.path.relpath(real_dir, repo_root).replace(os.sep, "/")
        git_cmd = [
            "git",
            "-C",
            repo_root,
            "status",
            "--porcelain=v1",
            "--ignored=matching",
            "-z",
            "--untracked-files=all",
        ]
        if rel_dir and rel_dir != ".":
            git_cmd.extend(["--", rel_dir])
        try:
            proc = subprocess.run(
                git_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=GIT_STATUS_TIMEOUT_SECONDS,
                check=False,
            )
            if proc.returncode != 0:
                self._walk_directory_bounded(real_dir, real_dir, seen_real, expanded)
                return expanded

            tokens = proc.stdout.decode("utf-8", errors="replace").split("\x00")
            idx = 0
            while idx < len(tokens):
                entry = tokens[idx]
                if len(entry) >= 4 and entry[2] == " ":
                    xy = entry[:2]
                    entry_path = entry[3:]
                    abs_entry = os.path.join(repo_root, entry_path.rstrip("/"))
                    if entry_path.endswith("/") or os.path.isdir(abs_entry):
                        self._walk_directory_bounded(
                            abs_entry, real_dir, seen_real, expanded
                        )
                    else:
                        self._append_regular_file_under_dir(
                            abs_entry, real_dir, seen_real, expanded
                        )
                    if xy[0] in {"R", "C"} or xy[1] in {"R", "C"}:
                        idx += 1
                idx += 1
        except (OSError, subprocess.SubprocessError):
            self._walk_directory_bounded(real_dir, real_dir, seen_real, expanded)

        return expanded

    @staticmethod
    def is_within_workspace_paths(
        resolved_path: str, workspace_paths: Sequence[str]
    ) -> bool:
        """Returns True if resolved_path resides inside one of workspace_paths."""
        if not workspace_paths:
            return False
        normalized_target = os.path.realpath(os.path.abspath(resolved_path))
        target_drive = os.path.splitdrive(normalized_target)[0].lower()
        for workspace_dir in workspace_paths:
            if not isinstance(workspace_dir, str) or not workspace_dir.strip():
                continue
            normalized_ws = os.path.realpath(os.path.abspath(workspace_dir.strip()))
            if os.path.splitdrive(normalized_ws)[0].lower() != target_drive:
                continue
            try:
                if (
                    os.path.commonpath([normalized_target, normalized_ws])
                    == normalized_ws
                ):
                    return True
            except ValueError:
                continue
        return False

    def _find_git_repo_root(self, dir_path: str) -> Optional[str]:
        """Finds the enclosing Git repository root by walking parent directories."""
        real_dir = os.path.realpath(os.path.abspath(dir_path))
        if real_dir in self._git_repo_cache:
            return self._git_repo_cache[real_dir]

        cur = real_dir
        visited: List[str] = []
        found_root: Optional[str] = None
        while True:
            visited.append(cur)
            if cur in self._git_repo_cache:
                found_root = self._git_repo_cache[cur]
                break
            if os.path.exists(os.path.join(cur, ".git")):
                found_root = cur
                break
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent

        for path_item in visited:
            self._git_repo_cache[path_item] = found_root
        return found_root

    def batch_check_should_scan(
        self,
        resolved_paths: Sequence[str],
        workspace_paths: Sequence[str],
        prompt_files: Set[str],
    ) -> Dict[str, bool]:
        """Evaluates which files require scanning using 1 batched `git status` per repo.

        A file is treated as trusted (skipping autonomous PreToolUse scan in
        `untrusted_and_prompt` mode) if and only if:
          1. It was NOT explicitly referenced in the user's prompt (`prompt_files`),
          2. It resides inside `workspace_paths`, AND
          3. `git status --porcelain=v1 --ignored=matching -z --untracked-files=normal`
             exits with code 0 and reports neither the file nor any parent directory
             prefix (meaning the file is tracked, clean in the working tree/index,
             and not gitignored).
        """
        decisions: Dict[str, bool] = {}
        if not resolved_paths:
            return decisions

        real_prompt_files = {
            os.path.realpath(os.path.abspath(p)) for p in prompt_files if p
        }
        by_repo: Dict[str, List[Tuple[str, str]]] = {}

        for raw_p in resolved_paths:
            real_p = os.path.realpath(os.path.abspath(raw_p))
            if not self.config.enabled:
                decisions[real_p] = False
                continue
            if self.config.mode == "all":
                decisions[real_p] = True
                continue
            if real_p in real_prompt_files:
                decisions[real_p] = True
                continue
            if self.config.mode == "prompt_only":
                decisions[real_p] = False
                continue
            if not self.is_within_workspace_paths(real_p, workspace_paths):
                decisions[real_p] = True
                continue

            repo_root = self._find_git_repo_root(os.path.dirname(real_p))
            if not repo_root:
                decisions[real_p] = True
                continue

            rel_path = os.path.relpath(real_p, repo_root).replace(os.sep, "/")
            by_repo.setdefault(repo_root, []).append((real_p, rel_path))

        for repo_root, items in by_repo.items():
            rel_list = [rel for _, rel in items]
            try:
                proc = subprocess.run(
                    [
                        "git",
                        "-C",
                        repo_root,
                        "status",
                        "--porcelain=v1",
                        "--ignored=matching",
                        "-z",
                        "--untracked-files=normal",
                        "--",
                        *rel_list,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=GIT_STATUS_TIMEOUT_SECONDS,
                    check=False,
                )
                if proc.returncode != 0:
                    for real_p, _ in items:
                        decisions[real_p] = True
                    continue

                untrusted_exact: Set[str] = set()
                untrusted_prefixes: List[str] = []
                tokens = proc.stdout.decode("utf-8", errors="replace").split("\x00")
                idx = 0
                while idx < len(tokens):
                    entry = tokens[idx]
                    if len(entry) >= 4 and entry[2] == " ":
                        xy = entry[:2]
                        entry_path = entry[3:]
                        if entry_path.endswith("/"):
                            untrusted_prefixes.append(entry_path)
                        else:
                            untrusted_exact.add(entry_path)
                        # In porcelain=v1 -z format, rename (R) and copy (C) entries
                        # emit the origin path in the immediately following NUL token.
                        if xy[0] in {"R", "C"} or xy[1] in {"R", "C"}:
                            idx += 1
                    idx += 1

                for real_p, rel_p in items:
                    is_flagged = rel_p in untrusted_exact or any(
                        rel_p.startswith(prefix) for prefix in untrusted_prefixes
                    )
                    decisions[real_p] = is_flagged
            except (OSError, subprocess.SubprocessError):
                for real_p, _ in items:
                    decisions[real_p] = True

        return decisions

    def should_scan_tool_file(
        self,
        resolved_path: str,
        workspace_paths: Sequence[str],
        prompt_files: Set[str],
    ) -> bool:
        """Single-file convenience wrapper around batch_check_should_scan."""
        real_p = os.path.realpath(os.path.abspath(resolved_path))
        res = self.batch_check_should_scan([real_p], workspace_paths, prompt_files)
        return res.get(real_p, True)

    def read_paged_slice(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        byte_offset: int = 0,
        workspace_paths: Sequence[str] = (),
    ) -> Optional[Tuple[str, CachedSliceRecord]]:
        """Streams a bounded line/byte slice aligned with Antigravity's ReadFileTool.

        Supports files up to 100 MiB without loading unselected lines into memory,
        clamps StartLine past EOF to the final line, preserves CRLF byte lengths,
        and applies a 128-byte overlap + formatted line-number coordinate union
        when ByteOffset > 0.
        """
        resolved = self.resolve_candidate_path(file_path, workspace_paths)
        if not resolved:
            return None
        try:
            st = os.stat(resolved)
            if st.st_size == 0 or st.st_size > MAX_PAGED_FILE_SIZE_BYTES:
                return None

            with open(resolved, "rb") as fh:
                sniff = fh.read(BINARY_SNIFF_BYTES)
                if not sniff:
                    return None
                is_utf16 = sniff.startswith((b"\xff\xfe", b"\xfe\xff"))
                if not is_utf16 and b"\x00" in sniff:
                    return None

                s_line = (
                    int(start_line)
                    if isinstance(start_line, int)
                    and not isinstance(start_line, bool)
                    and start_line >= 1
                    else None
                )
                e_line = (
                    int(end_line)
                    if isinstance(end_line, int)
                    and not isinstance(end_line, bool)
                    and end_line >= 1
                    else None
                )
                offset = (
                    max(0, int(byte_offset))
                    if isinstance(byte_offset, int)
                    and not isinstance(byte_offset, bool)
                    else 0
                )

                if is_utf16:
                    if st.st_size > self.config.max_file_size_bytes:
                        return None
                    fh.seek(0)
                    full_text = _decode_raw_bytes(fh.read(), sniff)
                    if not full_text:
                        return None
                    all_lines = [
                        ln.encode("utf-8") for ln in full_text.splitlines(keepends=True)
                    ]
                    if not all_lines:
                        return None
                    total_lines = len(all_lines)
                    if s_line is None and e_line is None:
                        s_idx, e_idx = 0, min(total_lines, MAX_SCAN_LINES_PER_VIEW)
                    elif s_line is not None and e_line is None:
                        s_idx = min(s_line - 1, total_lines - 1)
                        e_idx = min(total_lines, s_idx + MAX_SCAN_LINES_PER_VIEW)
                    elif s_line is None and e_line is not None:
                        e_idx = min(e_line, total_lines)
                        s_idx = max(0, e_idx - MAX_SCAN_LINES_PER_VIEW)
                    else:
                        assert s_line is not None and e_line is not None
                        s_idx = min(s_line - 1, total_lines - 1)
                        e_idx = min(
                            total_lines, min(e_line, s_idx + MAX_SCAN_LINES_PER_VIEW)
                        )
                    selected = all_lines[s_idx:e_idx]
                    s_line_1 = s_idx + 1
                    e_line_1 = s_idx + len(selected)
                else:
                    fh.seek(0)
                    if s_line is None and e_line is not None:
                        target_end = e_line
                        target_start = max(1, target_end - MAX_SCAN_LINES_PER_VIEW + 1)
                    else:
                        target_start = s_line if s_line is not None else 1
                        target_end = (
                            min(e_line, target_start + MAX_SCAN_LINES_PER_VIEW - 1)
                            if e_line is not None
                            else target_start + MAX_SCAN_LINES_PER_VIEW - 1
                        )

                    selected = []
                    last_line_seen: Optional[bytes] = None
                    last_line_num = 0
                    for line_idx, raw_line in enumerate(fh, start=1):
                        if line_idx == 1 and raw_line.startswith(b"\xef\xbb\xbf"):
                            raw_line = raw_line[3:]
                        last_line_seen = raw_line
                        last_line_num = line_idx
                        if line_idx < target_start:
                            continue
                        if line_idx > target_end:
                            break
                        selected.append(raw_line)

                    if not selected:
                        if last_line_seen is None:
                            return None
                        selected = [last_line_seen]
                        s_line_1 = last_line_num
                        e_line_1 = last_line_num
                    else:
                        s_line_1 = target_start
                        e_line_1 = target_start + len(selected) - 1

            raw_joined = b"".join(selected)
            if offset == 0:
                if (
                    s_line is None
                    and e_line is not None
                    and len(raw_joined) > MAX_SCAN_BYTES_PER_VIEW
                ):
                    b_end = len(raw_joined)
                    b_start = max(0, b_end - MAX_SCAN_BYTES_PER_VIEW)
                    while (
                        b_start < len(raw_joined)
                        and (raw_joined[b_start] & 0xC0) == 0x80
                    ):
                        b_start += 1
                else:
                    b_start = 0
                    b_end = min(len(raw_joined), MAX_SCAN_BYTES_PER_VIEW)
            else:
                # Account for Antigravity's IncludeLineNumbers=true formatting
                # ("%d: " prefixes) so ByteOffset > 0 covers both formatted and
                # unformatted coordinate spaces without injecting prefixes.
                raw_pos = 0
                fmt_pos = 0
                raw_start_for_fmt: Optional[int] = None
                for idx_sel, raw_line in enumerate(selected):
                    line_num = s_line_1 + idx_sel
                    prefix_len = len(f"{line_num}: ")
                    line_fmt_len = prefix_len + len(raw_line)
                    if fmt_pos + line_fmt_len > offset:
                        within_fmt = max(0, offset - fmt_pos - prefix_len)
                        raw_start_for_fmt = raw_pos + min(within_fmt, len(raw_line))
                        break
                    raw_pos += len(raw_line)
                    fmt_pos += line_fmt_len

                if raw_start_for_fmt is None:
                    raw_start_for_fmt = len(raw_joined)

                raw_start_unformatted = min(offset, len(raw_joined))
                earliest_start = min(raw_start_for_fmt, raw_start_unformatted)
                if earliest_start >= len(raw_joined) and raw_start_for_fmt >= len(
                    raw_joined
                ):
                    return None

                b_start = max(0, earliest_start - BYTE_OFFSET_OVERLAP_BYTES)
                while (
                    b_start < len(raw_joined)
                    and (raw_joined[b_start] & 0xC0) == 0x80
                ):
                    b_start += 1
                b_end = min(len(raw_joined), offset + MAX_SCAN_BYTES_PER_VIEW)

            window = raw_joined[b_start:b_end]
            decoded = window.decode("utf-8", errors="replace").strip()
            if not decoded:
                return None

            record = CachedSliceRecord(
                real_path=os.path.realpath(resolved),
                mtime_ns=st.st_mtime_ns,
                size=st.st_size,
                start_line=s_line_1,
                end_line=e_line_1,
                byte_start=b_start,
                byte_end=b_end,
            )
            return decoded, record
        except OSError:
            return None

    def read_tail_slice(
        self,
        file_path: str,
        workspace_paths: Sequence[str] = (),
        max_bytes: int = MAX_SCAN_BYTES_PER_VIEW,
    ) -> Optional[Tuple[str, CachedSliceRecord]]:
        """Reads the trailing slice of a file from SEEK_END for shell `tail` commands."""
        resolved = self.resolve_candidate_path(file_path, workspace_paths)
        if not resolved:
            return None
        try:
            st = os.stat(resolved)
            if st.st_size == 0:
                return None
            with open(resolved, "rb") as fh:
                sniff = fh.read(BINARY_SNIFF_BYTES)
                if not sniff:
                    return None
                is_utf16 = sniff.startswith((b"\xff\xfe", b"\xfe\xff"))
                if not is_utf16 and b"\x00" in sniff:
                    return None
                seek_pos = max(0, st.st_size - max_bytes)
                fh.seek(seek_pos, os.SEEK_SET)
                tail_bytes = fh.read(max_bytes)

            if is_utf16:
                decoded = _decode_raw_bytes(tail_bytes, sniff)
            else:
                start_trim = 0
                while (
                    start_trim < len(tail_bytes)
                    and (tail_bytes[start_trim] & 0xC0) == 0x80
                ):
                    start_trim += 1
                decoded = tail_bytes[start_trim:].decode("utf-8", errors="replace")

            if not decoded or not decoded.strip():
                return None
            record = CachedSliceRecord(
                real_path=os.path.realpath(resolved),
                mtime_ns=st.st_mtime_ns,
                size=st.st_size,
                start_line=1,
                end_line=MAX_SCAN_LINES_PER_VIEW,
                byte_start=max(0, st.st_size - max_bytes),
                byte_end=st.st_size,
            )
            return decoded.strip(), record
        except OSError:
            return None

    def read_unpaged_slice(
        self,
        file_path: str,
        workspace_paths: Sequence[str] = (),
        max_bytes_override: Optional[int] = None,
    ) -> Tuple[str, Optional[str], Optional[CachedSliceRecord]]:
        """Reads an unpaginated file (`grep_search`, `notebook_edit`, `cat`) under policy caps.

        Returns:
            Tuple of (action, text_or_reason, slice_record) where action is:
              - "SCAN": text_or_reason contains the decoded file text to inspect.
              - "BLOCK_POLICY": file exceeds max_file_size_bytes and oversize_action is BLOCK.
              - "SKIP": file does not exist, is empty, or is binary.
        """
        resolved = self.resolve_candidate_path(file_path, workspace_paths)
        if not resolved:
            return "SKIP", None, None
        max_allowed = (
            max_bytes_override
            if max_bytes_override is not None
            else self.config.max_file_size_bytes
        )
        try:
            st = os.stat(resolved)
            if st.st_size == 0:
                return "SKIP", None, None
            with open(resolved, "rb") as fh:
                sniff = fh.read(BINARY_SNIFF_BYTES)
                if not sniff:
                    return "SKIP", None, None
                is_utf16 = sniff.startswith((b"\xff\xfe", b"\xfe\xff"))
                if not is_utf16 and b"\x00" in sniff:
                    return "SKIP", None, None

                if (
                    self.config.unpaged_scan_mode == "block"
                    and st.st_size > MAX_SCAN_BYTES_PER_VIEW
                ):
                    return (
                        "BLOCK_POLICY",
                        (
                            f"File '{os.path.basename(resolved)}' ({st.st_size:,} bytes) "
                            f"exceeds single-view scan limit ({MAX_SCAN_BYTES_PER_VIEW:,} bytes) "
                            "under unpaged_scan_mode='block'. Use read_file with StartLine/EndLine pagination."
                        ),
                        None,
                    )

                if st.st_size > max_allowed:
                    if self.config.oversize_action == "BLOCK":
                        return (
                            "BLOCK_POLICY",
                            (
                                f"File '{os.path.basename(resolved)}' ({st.st_size:,} bytes) "
                                f"exceeds max_file_size_bytes ({self.config.max_file_size_bytes:,} bytes) "
                                "for unpaginated inspection. Use read_file with StartLine/EndLine pagination."
                            ),
                            None,
                        )
                    half = MAX_SCAN_BYTES_PER_VIEW // 2
                    fh.seek(0)
                    head_b = fh.read(half)
                    fh.seek(max(0, st.st_size - half), os.SEEK_SET)
                    tail_b = fh.read(half)
                    combined = (
                        head_b.decode("utf-8", errors="replace")
                        + "\n...\n"
                        + tail_b.decode("utf-8", errors="replace")
                    ).strip()
                    return ("SCAN", combined, None) if combined else ("SKIP", None, None)

                fh.seek(0)
                raw = fh.read(max_allowed)
            decoded = _decode_raw_bytes(raw, sniff)
            if not decoded or not decoded.strip():
                return "SKIP", None, None
            record = CachedSliceRecord(
                real_path=os.path.realpath(resolved),
                mtime_ns=st.st_mtime_ns,
                size=st.st_size,
                start_line=1,
                end_line=1_000_000_000,
                byte_start=0,
                byte_end=st.st_size,
            )
            return "SCAN", decoded.strip(), record
        except OSError:
            return "SKIP", None, None

    def extract_prompt_file_paths(
        self, prompt_text: str, workspace_paths: Sequence[str] = ()
    ) -> List[str]:
        """Extracts deduplicated, resolved file paths from @file mentions and inline paths."""
        if not prompt_text:
            return []
        raw_candidates: List[str] = []

        for match in _TRANSCRIPT_FILE_RE.finditer(prompt_text):
            raw_candidates.append(match.group(1).strip())
        for match in _TRANSCRIPT_CODE_ITEM_RE.finditer(prompt_text):
            try:
                meta = json.loads(match.group(1))
                if isinstance(meta, dict) and isinstance(meta.get("File"), str):
                    raw_candidates.append(meta["File"])
            except Exception:
                pass
        for match in _AT_MENTION_RE.finditer(prompt_text):
            token = next((group for group in match.groups() if group), "")
            if token:
                raw_candidates.append(token)
        for match in _PATH_TOKEN_RE.finditer(prompt_text):
            token = next((group for group in match.groups() if group), "")
            if not token:
                continue
            cleaned_token = token.rstrip(".,;:!?")
            if (
                cleaned_token.startswith(("http://", "https://"))
                or "@" in cleaned_token
                or _is_prose_non_path_token(cleaned_token)
            ):
                continue
            if (
                "/" in cleaned_token
                or "\\" in cleaned_token
                or bool(_FILE_EXTENSION_RE.search(cleaned_token))
            ):
                raw_candidates.append(cleaned_token)

        seen_raw: Set[str] = set()
        seen_real: Set[str] = set()
        resolved_paths: List[str] = []
        for raw_path in raw_candidates:
            norm_key = raw_path.strip().strip("\"'`[]()").rstrip(".,;:!?")
            if not norm_key or norm_key in seen_raw:
                continue
            seen_raw.add(norm_key)

            resolved = self.resolve_candidate_path(norm_key, workspace_paths)
            if not resolved:
                continue
            real_path = os.path.realpath(resolved)
            if real_path in seen_real:
                continue
            seen_real.add(real_path)
            resolved_paths.append(resolved)
        return resolved_paths

    def extract_prompt_scan_target(
        self,
        prompt_text: str,
        source_prefix: str,
        workspace_paths: Sequence[str] = (),
    ) -> ScanExtractionResult:
        """Extracts prompt text plus any referenced file slices for PreInvocation scanning."""
        if not prompt_text or not prompt_text.strip():
            return ScanExtractionResult(action="NO_ACTIONABLE_TEXT")

        if not self.config.enabled:
            return ScanExtractionResult(
                action="SCAN",
                text_to_scan=prompt_text,
                source=source_prefix,
            )

        resolved_paths = self.extract_prompt_file_paths(
            prompt_text, workspace_paths
        )
        snippets: List[str] = []
        slice_records: List[CachedSliceRecord] = []
        for resolved in resolved_paths:
            paged = self.read_paged_slice(
                resolved, start_line=1, end_line=MAX_SCAN_LINES_PER_VIEW, byte_offset=0, workspace_paths=workspace_paths
            )
            if paged is not None:
                content, record = paged
                snippets.append(f"[File: {resolved}]\n{content}")
                slice_records.append(record)

        if snippets:
            combined = f"{prompt_text}\n\n" + "\n\n".join(snippets)
            return ScanExtractionResult(
                action="SCAN",
                text_to_scan=combined,
                source=f"{source_prefix}+files",
                scanned_slices=tuple(slice_records),
                prompt_files=tuple(resolved_paths),
            )
        return ScanExtractionResult(
            action="SCAN",
            text_to_scan=prompt_text,
            source=source_prefix,
            prompt_files=tuple(resolved_paths),
        )

    def _extract_shell_candidates(
        self,
        cmd_line: str,
        workspace_paths: Sequence[str],
        prompt_files: Optional[Set[str]] = None,
    ) -> List[Tuple[str, bool]]:
        """Extracts deduplicated (resolved_path, is_tail) pairs from shell read commands."""
        found: List[Tuple[str, bool]] = []
        seen_real: Set[str] = set()

        for segment in _split_shell_segments(cmd_line):
            try:
                tokens = shlex.split(segment, posix=(os.name != "nt"))
            except ValueError:
                tokens = segment.split()
            if not tokens:
                continue

            idx = 0
            while idx < len(tokens) and (
                "=" in tokens[idx]
                or tokens[idx]
                in {"sudo", "env", "command", "nohup", "time", "nice"}
            ):
                idx += 1
            if idx >= len(tokens):
                continue

            cmd_base = os.path.basename(tokens[idx]).lower()
            if cmd_base.endswith(".exe"):
                cmd_base = cmd_base[:-4]
            if cmd_base not in SHELL_READ_COMMANDS:
                continue

            is_tail = cmd_base == "tail"
            raw_args: List[str] = []
            for arg in tokens[idx + 1 :]:
                if arg.startswith("-"):
                    if "=" in arg:
                        _, rhs = arg.split("=", 1)
                        if rhs:
                            raw_args.append(rhs.lstrip("@"))
                    elif len(arg) > 2 and arg[2:].startswith("@"):
                        raw_args.append(arg[3:])
                    continue
                if arg.startswith("@") and len(arg) > 1:
                    raw_args.append(arg[1:])
                else:
                    raw_args.append(arg)
                for inline_match in _INLINE_FILE_LITERAL_RE.finditer(arg):
                    raw_args.append(inline_match.group(1))

            segment_matched = False
            active_prompt_files = prompt_files or set()
            for candidate in raw_args:
                resolved = self.resolve_candidate_path(candidate, workspace_paths)
                if resolved:
                    segment_matched = True
                    real_p = os.path.realpath(resolved)
                    if real_p not in seen_real:
                        seen_real.add(real_p)
                        found.append((resolved, is_tail))
                    continue
                if cmd_base in SHELL_SEARCH_COMMANDS:
                    resolved_dir = self.resolve_candidate_directory(
                        candidate, workspace_paths
                    )
                    if resolved_dir:
                        segment_matched = True
                        for exp_file in self.expand_directory_targets(
                            resolved_dir, workspace_paths, active_prompt_files
                        ):
                            real_exp = os.path.realpath(exp_file)
                            if real_exp not in seen_real:
                                seen_real.add(real_exp)
                                found.append((exp_file, False))

            if cmd_base in SHELL_SEARCH_COMMANDS and not segment_matched:
                default_dirs = list(workspace_paths) if workspace_paths else ["."]
                for def_dir in default_dirs:
                    resolved_dir = self.resolve_candidate_directory(
                        def_dir, workspace_paths
                    )
                    if resolved_dir:
                        for exp_file in self.expand_directory_targets(
                            resolved_dir, workspace_paths, active_prompt_files
                        ):
                            real_exp = os.path.realpath(exp_file)
                            if real_exp not in seen_real:
                                seen_real.add(real_exp)
                                found.append((exp_file, False))
        return found

    @staticmethod
    def _is_covered_by_cache(
        record: CachedSliceRecord, cached_slices: Sequence[CachedSliceRecord]
    ) -> bool:
        """Returns True if record's file version and range are already covered in cached_slices."""
        return any(
            existing.covers(
                record.real_path,
                record.mtime_ns,
                record.size,
                record.start_line,
                record.end_line,
                record.byte_start,
                record.byte_end,
            )
            for existing in cached_slices
        )

    @classmethod
    def _collect_nested_strings(cls, value: Any) -> List[str]:
        """Recursively collects string and numeric values from nested dicts and lists."""
        collected: List[str] = []
        if isinstance(value, str):
            if value.strip():
                collected.append(value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            collected.append(str(value))
        elif isinstance(value, dict):
            for nested_val in value.values():
                collected.extend(cls._collect_nested_strings(nested_val))
        elif isinstance(value, (list, tuple)):
            for item in value:
                collected.extend(cls._collect_nested_strings(item))
        return collected

    def extract_tool_scan_target(
        self, request: ToolScanRequest
    ) -> ScanExtractionResult:
        """Evaluates a PreToolUse request for readable file slices and inline arguments."""
        tool = (request.tool_name or "").strip()
        args = request.tool_args or {}
        ws_paths = request.workspace_paths or []

        # 1. Inspect file-reading tools when file scanning is enabled.
        if self.config.enabled:
            if tool in FILE_READ_TOOLS:
                raw_path = (
                    args.get("Path")
                    or args.get("AbsolutePath")
                    or args.get("File")
                )
                if isinstance(raw_path, str) and raw_path.strip():
                    resolved = self.resolve_candidate_path(raw_path, ws_paths)
                    if resolved and self.should_scan_tool_file(
                        resolved, ws_paths, request.prompt_files
                    ):
                        start_line = args.get("StartLine")
                        end_line = args.get("EndLine")
                        byte_offset = (
                            args.get("ByteOffset")
                            or args.get("ContentOffset")
                            or 0
                        )
                        paged = self.read_paged_slice(
                            resolved,
                            start_line=start_line,
                            end_line=end_line,
                            byte_offset=byte_offset,
                            workspace_paths=ws_paths,
                        )
                        if paged is not None:
                            content, record = paged
                            if self._is_covered_by_cache(
                                record, request.cached_slices
                            ):
                                return ScanExtractionResult(
                                    action="SKIP_CACHED",
                                    source=f"tool_file_cached:{tool}",
                                )
                            return ScanExtractionResult(
                                action="SCAN",
                                text_to_scan=f"{raw_path}\n{content}",
                                source=f"tool_file_content:{tool}",
                                scanned_slices=(record,),
                            )

            elif tool == "notebook_edit":
                action = str(args.get("Action") or "list").lower()
                nb_path = args.get("NotebookPath")
                if action in {"list", "get", "get_with_outputs"} and isinstance(
                    nb_path, str
                ):
                    resolved = self.resolve_candidate_path(nb_path, ws_paths)
                    if resolved and self.should_scan_tool_file(
                        resolved, ws_paths, request.prompt_files
                    ):
                        act, text_or_err, record = self.read_unpaged_slice(
                            resolved, ws_paths
                        )
                        if act == "BLOCK_POLICY":
                            return ScanExtractionResult(
                                action="BLOCK_POLICY",
                                block_reason=text_or_err or "Oversize notebook blocked.",
                                source="tool_file_oversize:notebook_edit",
                            )
                        if act == "SCAN" and text_or_err:
                            if record and self._is_covered_by_cache(
                                record, request.cached_slices
                            ):
                                return ScanExtractionResult(
                                    action="SKIP_CACHED",
                                    source="tool_file_cached:notebook_edit",
                                )
                            return ScanExtractionResult(
                                action="SCAN",
                                text_to_scan=f"{nb_path}\n{text_or_err}",
                                source="tool_file_content:notebook_edit",
                                scanned_slices=(record,) if record else (),
                            )

            elif tool == "grep_search":
                search_path = args.get("SearchPath")
                if isinstance(search_path, str) and search_path.strip():
                    resolved = self.resolve_candidate_path(search_path, ws_paths)
                    if resolved and self.should_scan_tool_file(
                        resolved, ws_paths, request.prompt_files
                    ):
                        act, text_or_err, record = self.read_unpaged_slice(
                            resolved, ws_paths
                        )
                        if act == "BLOCK_POLICY":
                            return ScanExtractionResult(
                                action="BLOCK_POLICY",
                                block_reason=text_or_err or "Oversize file blocked.",
                                source="tool_file_oversize:grep_search",
                            )
                        if act == "SCAN" and text_or_err:
                            query = str(args.get("Query") or "")
                            if record and self._is_covered_by_cache(
                                record, request.cached_slices
                            ):
                                if query.strip():
                                    return ScanExtractionResult(
                                        action="SCAN",
                                        text_to_scan=f"{query}\n{search_path}",
                                        source="tool_args:grep_search",
                                    )
                                return ScanExtractionResult(
                                    action="SKIP_CACHED",
                                    source="tool_file_cached:grep_search",
                                )
                            return ScanExtractionResult(
                                action="SCAN",
                                text_to_scan=f"{query}\n{search_path}\n{text_or_err}",
                                source="tool_file_content:grep_search",
                                scanned_slices=(record,) if record else (),
                            )
                    elif not resolved:
                        resolved_dir = self.resolve_candidate_directory(
                            search_path, ws_paths
                        )
                        if resolved_dir:
                            dir_targets = self.expand_directory_targets(
                                resolved_dir, ws_paths, request.prompt_files
                            )
                            if dir_targets:
                                query = str(args.get("Query") or "")
                                dir_snippets: List[str] = []
                                new_records: List[CachedSliceRecord] = []
                                remaining_budget = self.config.max_file_size_bytes
                                for target_file in dir_targets:
                                    act, text_or_err, record = self.read_unpaged_slice(
                                        target_file,
                                        ws_paths,
                                        max_bytes_override=max(0, remaining_budget),
                                    )
                                    if act == "BLOCK_POLICY":
                                        return ScanExtractionResult(
                                            action="BLOCK_POLICY",
                                            block_reason=text_or_err
                                            or "Oversize file in directory grep_search blocked.",
                                            source="tool_file_oversize:grep_search",
                                        )
                                    if act == "SCAN" and text_or_err:
                                        try:
                                            remaining_budget -= os.path.getsize(target_file)
                                        except OSError:
                                            pass
                                        if record and self._is_covered_by_cache(
                                            record, request.cached_slices
                                        ):
                                            continue
                                        dir_snippets.append(
                                            f"[File: {target_file}]\n{text_or_err}"
                                        )
                                        if record:
                                            new_records.append(record)
                                if dir_snippets:
                                    header = f"{query}\n{search_path}".strip()
                                    combined = (
                                        "\n\n".join([header, *dir_snippets])
                                        if header
                                        else "\n\n".join(dir_snippets)
                                    )
                                    return ScanExtractionResult(
                                        action="SCAN",
                                        text_to_scan=combined,
                                        source="tool_file_content:grep_search",
                                        scanned_slices=tuple(new_records),
                                    )

            elif tool == "run_command":
                cmd_line = args.get("CommandLine")
                if isinstance(cmd_line, str) and cmd_line.strip():
                    candidates = self._extract_shell_candidates(
                        cmd_line, ws_paths, request.prompt_files
                    )
                    if candidates:
                        cand_paths = [p for p, _ in candidates]
                        trust_map = self.batch_check_should_scan(
                            cand_paths, ws_paths, request.prompt_files
                        )
                        shell_snippets: List[str] = []
                        new_records: List[CachedSliceRecord] = []
                        remaining_budget = self.config.max_file_size_bytes

                        for resolved, is_tail in candidates:
                            real_p = os.path.realpath(resolved)
                            if not trust_map.get(real_p, True):
                                continue
                            if is_tail:
                                tail_res = self.read_tail_slice(resolved, ws_paths)
                                if tail_res is not None:
                                    content, record = tail_res
                                    if not self._is_covered_by_cache(
                                        record, request.cached_slices
                                    ):
                                        shell_snippets.append(content)
                                        new_records.append(record)
                                continue

                            act, text_or_err, record = self.read_unpaged_slice(
                                resolved,
                                ws_paths,
                                max_bytes_override=max(0, remaining_budget),
                            )
                            if act == "BLOCK_POLICY":
                                return ScanExtractionResult(
                                    action="BLOCK_POLICY",
                                    block_reason=text_or_err
                                    or "Command file read exceeds max_file_size_bytes.",
                                    source="tool_file_oversize:run_command",
                                )
                            if act == "SCAN" and text_or_err:
                                try:
                                    remaining_budget -= os.path.getsize(resolved)
                                except OSError:
                                    pass
                                if record and self._is_covered_by_cache(
                                    record, request.cached_slices
                                ):
                                    continue
                                shell_snippets.append(text_or_err)
                                if record:
                                    new_records.append(record)

                        if shell_snippets:
                            combined = "\n\n".join([cmd_line, *shell_snippets])
                            return ScanExtractionResult(
                                action="SCAN",
                                text_to_scan=combined,
                                source="tool_file_content:run_command",
                                scanned_slices=tuple(new_records),
                            )

        # 2. Fallback: inspect inline string arguments on the tool call.
        parts: List[str] = []
        for key in INLINE_TEXT_KEYS:
            val = args.get(key)
            if val and isinstance(val, str):
                parts.append(val)
        if parts:
            return ScanExtractionResult(
                action="SCAN",
                text_to_scan="\n".join(parts),
                source=f"tool_args:{tool}",
            )

        all_str_vals = self._collect_nested_strings(args)
        if all_str_vals:
            return ScanExtractionResult(
                action="SCAN",
                text_to_scan=" ".join(all_str_vals),
                source=f"tool_args_all:{tool}",
            )

        return ScanExtractionResult(action="NO_ACTIONABLE_TEXT")
