"""Policy-driven pre-read file slice extractor and multimodal media classifier.

Isolates filesystem URI resolution, streaming UTF-8/binary classification,
paged line/byte window slicing (`read_file` and `view_file`), and structured
Jupyter notebook cell extraction (`notebook_edit`) from the Antigravity hook
wire protocol (`src.hooks`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import dataclasses
import json
import os
import re
import stat
from typing import Any
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# File-Scanning & Slicing Constants (Aligned with Antigravity & Nandi v2)
# ---------------------------------------------------------------------------

# Matches Antigravity's per-view line cap (MaxLinesPerView = 800).
MAX_SCAN_LINES_PER_VIEW: int = 800

# Matches Antigravity's per-view byte ceiling (45 * 1024 = 46,080 bytes).
MAX_SCAN_BYTES_PER_VIEW: int = 46_080

# Backward UTF-8-aligned byte overlap applied when ByteOffset/ContentOffset > 0
# so multi-byte tokens straddling a 46,080-byte boundary remain intact.
BYTE_OFFSET_OVERLAP_BYTES: int = 512

# Single-request UTF-8 byte ceiling (48 KiB): fits 46,080 B + 512 B overlap +
# normal toolCall.args in 1 Model Armor RPC while staying under Cloud DLP's
# ~50 KB single-request inspection window.
MAX_SINGLE_SHOT_SCAN_BYTES: int = 49_152

# Maximum characters inspected in a single PreToolUse / PreInvocation scan
# (<= 7 chunks of 40,000 chars with 4,096-char overlap).
MAX_PRE_READ_SCAN_CHARS: int = 250_000

# Multi-chunk character window and overlap for oversized notebook/prompt scans.
MULTI_CHUNK_MAX_CHARS: int = 40_000
MULTI_CHUNK_OVERLAP_CHARS: int = 4_096

# Maximum .ipynb file size (10 MiB) parsed in PreToolUse before failing closed.
NOTEBOOK_MAX_FILE_BYTES: int = 10_485_760

# Matches Antigravity's maximum file size (100 MiB) for read_file / view_file.
MAX_PAGED_FILE_SIZE_BYTES: int = 104_857_600

# Header sniff window matching Go net/http.DetectContentType (512 bytes).
MIME_SNIFF_BYTES: int = 512
BINARY_SNIFF_BYTES: int = MIME_SNIFF_BYTES

# Streaming chunk size (64 KiB) for O(1)-memory UTF-8 and NUL-byte validation.
STREAM_CHUNK_BYTES: int = 65_536

# Content-addressed LRU cache retention and capacity constants.
SCAN_CACHE_TTL_SECONDS: int = 7_200
SCAN_CACHE_MAX_ENTRIES: int = 2_000

PAGED_FILE_READ_TOOLS: frozenset[str] = frozenset({"read_file", "view_file"})
NOTEBOOK_READ_ACTIONS: frozenset[str] = frozenset(
    {"list", "get", "get_with_outputs"}
)
VALID_UNSCANNABLE_MEDIA_ACTIONS: tuple[str, ...] = ("BLOCK", "ALLOW")

_UTF8_BOM: bytes = b"\xef\xbb\xbf"
_ZIP_MAGICS: tuple[bytes, ...] = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_OLE2_MAGIC: bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_OFFICE_AND_ODF_MIMES: Mapping[str, str] = {
    ".doc": "application/msword",
    ".docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ),
    ".xls": "application/vnd.ms-excel",
    ".xlsx": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    ),
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    ),
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
}

_EXTENSION_MULTIMODAL_MIMES: Mapping[str, str] = {
    **_OFFICE_AND_ODF_MIMES,
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".ico": "image/x-icon",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".avif": "image/avif",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".oga": "audio/ogg",
    ".opus": "audio/opus",
    ".spx": "audio/ogg",
    ".flac": "audio/flac",
    ".aac": "audio/aac",
    ".m4a": "audio/mp4",
    ".aiff": "audio/aiff",
    ".aif": "audio/aiff",
    ".wma": "audio/x-ms-wma",
    ".mid": "audio/midi",
    ".midi": "audio/midi",
    ".mp4": "video/mp4",
    ".m4v": "video/mp4",
    ".mov": "video/quicktime",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".avi": "video/avi",
    ".ogv": "video/ogg",
    ".flv": "video/x-flv",
    ".wmv": "video/x-ms-wmv",
    ".3gp": "video/3gpp",
    ".mpeg": "video/mpeg",
    ".mpg": "video/mpeg",
}

_UNSCANNABLE_OUTPUT_MIMES: frozenset[str] = frozenset(
    set(_OFFICE_AND_ODF_MIMES.values()) | {"application/pdf"}
)

_LINE_FRAGMENT_SUFFIX_RE = re.compile(r"#L\d+(?:-L?\d+)?$", re.IGNORECASE)
_POSIX_WINDOWS_DRIVE_RE = re.compile(r"^/([A-Za-z]:/.*)$")

_YAML_CONFIG_CACHE: dict[tuple[str, int], dict[str, dict[str, str]]] = {}


def _parse_bool(raw_val: Any, default: bool) -> bool:
    """Parses a boolean from YAML or Python primitives."""
    if isinstance(raw_val, bool):
        return raw_val
    if isinstance(raw_val, str):
        lowered = raw_val.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    return default


def _parse_non_bool_int(raw_val: Any) -> int | None:
    """Coerces an integer or numeric string while rejecting booleans."""
    if raw_val is None or isinstance(raw_val, bool):
        return None
    if isinstance(raw_val, int):
        return raw_val
    if isinstance(raw_val, float):
        return int(raw_val) if raw_val.is_integer() else None
    if isinstance(raw_val, str):
        stripped = raw_val.strip()
        if stripped and (
            stripped.isdigit()
            or (stripped.startswith("-") and stripped[1:].isdigit())
        ):
            return int(stripped)
    return None


def _parse_yaml_section(yaml_text: str, section_name: str) -> dict[str, str]:
    """Extracts key-value pairs scoped strictly to a top-level YAML block.

    Args:
        yaml_text: Raw UTF-8 contents of `config.yaml`.
        section_name: Top-level YAML mapping name (e.g. `"hooks"`, `"payload"`).

    Returns:
        Flat string key-value dictionary parsed from that top-level section.
    """
    result: dict[str, str] = {}
    in_section = False
    section_indent: int | None = None
    header_re = re.compile(rf"^{re.escape(section_name)}\s*:\s*(?:#.*)?$")
    kv_re = re.compile(r"^([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$")

    for raw_line in yaml_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if not in_section:
            if indent == 0 and header_re.match(stripped):
                in_section = True
                section_indent = None
            continue

        if indent == 0:
            break
        if section_indent is None:
            section_indent = indent
        if indent != section_indent:
            continue

        kv_match = kv_re.match(stripped)
        if not kv_match:
            continue
        key = kv_match.group(1)
        val_no_comment = re.sub(r"\s+#.*$", "", kv_match.group(2)).strip()
        if (
            len(val_no_comment) >= 2
            and val_no_comment[0] == val_no_comment[-1]
            and val_no_comment[0] in {"'", '"'}
        ):
            val_no_comment = val_no_comment[1:-1]
        result[key] = val_no_comment
    return result


def decode_file_uri(raw_path: str) -> str:
    """Decodes a `file://` URI into a local filesystem path, or returns `raw_path`.

    Uses `urllib.parse.urlparse` + `urllib.request.url2pathname` so percent
    escapes (`%20`, `%23`), URI `#fragment` suffixes, Windows drive URIs
    (`file:///C:/...`), and UNC hosts (`file://server/share/...`) decode cleanly
    without corrupting literal `#` characters in plain filesystem paths.

    Args:
        raw_path: Raw path or `file://` URI string.

    Returns:
        Decoded filesystem path string.
    """
    cleaned = raw_path.strip()
    if (
        len(cleaned) >= 2
        and cleaned[0] == cleaned[-1]
        and cleaned[0] in {"'", '"'}
    ):
        cleaned = cleaned[1:-1].strip()

    if not cleaned.lower().startswith("file:"):
        return cleaned

    parsed = urllib.parse.urlparse(cleaned)
    netloc = parsed.netloc
    if netloc and netloc.lower() != "localhost":
        url_path = f"//{netloc}{parsed.path}"
    else:
        url_path = parsed.path

    decoded = urllib.request.url2pathname(url_path)
    if os.name != "nt":
        win_match = _POSIX_WINDOWS_DRIVE_RE.match(decoded)
        if win_match:
            return win_match.group(1)
    return decoded


def detect_multimodal_mime(file_path: str, head_bytes: bytes) -> str | None:
    """Detects multimodal binary MIME type from 512-byte header magic or extension.

    Mirrors Antigravity's `mediautil.DetectMimeType` + `detectViewFileMimeType`.
    Note that callers MUST combine this with binaryness validation (`%PDF-`, NUL
    byte, or invalid UTF-8) before classifying a file as binary media so valid
    UTF-8 text files starting with `"BM..."`, `"GIF89a..."`, `"ID3..."`, or
    ending in `.svg` are scanned as text rather than blocked.

    Args:
        file_path: Resolved path of the file (used for extension disambiguation).
        head_bytes: Up to 512 initial bytes after stripping any UTF-8 BOM.

    Returns:
        Canonical multimodal MIME string if recognized, or None for non-media
        types (such as `.svg`, plain `.zip`, executables, or source files).
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".svg":
        return None
    if head_bytes.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")):
        return None

    if head_bytes.startswith(b"%PDF-"):
        return "application/pdf"
    if head_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head_bytes.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head_bytes) >= 12 and head_bytes[:4] == b"RIFF":
        fourcc = head_bytes[8:12]
        if fourcc == b"WEBP":
            return "image/webp"
        if fourcc == b"WAVE":
            return "audio/wav"
        if fourcc == b"AVI ":
            return "video/avi"
    if (
        len(head_bytes) >= 12
        and head_bytes[:4] == b"FORM"
        and head_bytes[8:12] in (b"AIFF", b"AIFC")
    ):
        return "audio/aiff"
    if head_bytes.startswith(b"BM"):
        return "image/bmp"
    if head_bytes.startswith((b"\x00\x00\x01\x00", b"\x00\x00\x02\x00")):
        return "image/x-icon"
    if head_bytes.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    if len(head_bytes) >= 12 and head_bytes[4:8] == b"ftyp":
        brand = head_bytes[8:12]
        if brand in (b"avif", b"avis"):
            return "image/avif"
        if brand in (b"heic", b"heix", b"mif1", b"msf1"):
            return "image/heic"
        if brand in (b"M4A ", b"M4B "):
            return "audio/mp4"
        return "video/mp4"
    if head_bytes.startswith(b"OggS"):
        return "video/ogg" if ext == ".ogv" else "audio/ogg"
    if head_bytes.startswith(b"fLaC"):
        return "audio/flac"
    if head_bytes.startswith(b"MThd"):
        return "audio/midi"
    if head_bytes.startswith(b"ID3") or (
        len(head_bytes) >= 2
        and head_bytes[0] == 0xFF
        and (head_bytes[1] & 0xE0) == 0xE0
    ):
        return "audio/mpeg"
    if head_bytes.startswith(b"\x1a\x45\xdf\xa3"):
        return "video/webm"
    if head_bytes.startswith(b"FLV\x01"):
        return "video/x-flv"

    if head_bytes.startswith(_ZIP_MAGICS) or head_bytes.startswith(_OLE2_MAGIC):
        return _OFFICE_AND_ODF_MIMES.get(ext)

    return _EXTENSION_MULTIMODAL_MIMES.get(ext)


def is_unscannable_multimodal_mime(mime_type: str | None) -> bool:
    """Returns True if `mime_type` is a non-text multimodal binary media type."""
    if not mime_type:
        return False
    normalized = mime_type.split(";", 1)[0].strip().lower()
    if not normalized or normalized == "image/svg+xml" or normalized.startswith("text/"):
        return False
    if normalized.startswith(("image/", "audio/", "video/")):
        return True
    return normalized in _UNSCANNABLE_OUTPUT_MIMES


def _split_incomplete_utf8_tail(buf: bytes) -> tuple[bytes, bytes]:
    """Splits a byte chunk at its last complete UTF-8 sequence boundary.

    Called only when more bytes remain in the file (`not at_eof`) so a 64 KiB
    read boundary landing inside a 2-, 3-, or 4-byte UTF-8 rune carries the
    1-3 trailing bytes into the next read without raising a false decode error.

    Args:
        buf: Raw bytes read from the stream prior to EOF.

    Returns:
        Tuple `(complete_prefix, trailing_carry)` where `len(trailing_carry) <= 3`.
    """
    length = len(buf)
    # Inspect up to the last 3 bytes for an unfinished multi-byte lead byte.
    max_back = min(3, length)
    for back in range(1, max_back + 1):
        byte_val = buf[length - back]
        if byte_val < 0x80:
            return buf, b""
        if (byte_val & 0xC0) == 0x80:
            continue
        # Found a lead byte at index `length - back`.
        if (byte_val & 0xE0) == 0xC0:
            expected_len = 2
        elif (byte_val & 0xF0) == 0xE0:
            expected_len = 3
        elif (byte_val & 0xF8) == 0xF0:
            expected_len = 4
        else:
            # Invalid UTF-8 lead byte (>= 0xF8); keep in complete_prefix so strict
            # UTF-8 validation rejects it immediately.
            return buf, b""
        if back < expected_len:
            cut = length - back
            return buf[:cut], buf[cut:]
        return buf, b""
    return buf, b""


def _trim_slice_utf8_boundaries(
    raw_slice: bytes, excluded_next_byte: int | None
) -> bytes:
    """Trims split UTF-8 continuation bytes at `b_start` and `b_end`.

    At `b_start`, advances past leading continuation bytes (`0x80..0xBF`).
    At `b_end`, inspects `excluded_next_byte` (`buf[b_end]`): if it is a
    continuation byte (`0x80..0xBF`), backs up across any trailing continuation
    bytes and the split lead byte, preserving complete trailing multi-byte runes.

    Args:
        raw_slice: Candidate raw UTF-8 slice `[b_start:b_end]`.
        excluded_next_byte: First excluded byte `buf[b_end]` from the same line
            when truncated by `win_end`, or None if `b_end` reached line/file end.

    Returns:
        Rune-aligned UTF-8 byte slice.
    """
    if not raw_slice:
        return b""

    end_idx = len(raw_slice)
    next_byte = excluded_next_byte
    while end_idx > 0 and next_byte is not None and (next_byte & 0xC0) == 0x80:
        end_idx -= 1
        next_byte = raw_slice[end_idx]

    start_idx = 0
    while start_idx < end_idx and (raw_slice[start_idx] & 0xC0) == 0x80:
        start_idx += 1

    return raw_slice[start_idx:end_idx]


class _BoundedByteWindow:
    """Collects raw bytes overlapping `[win_start, win_end)` plus 1 lookahead byte."""

    def __init__(self, win_start: int, win_end: int) -> None:
        """Initializes the instance.

        Args:
            win_start: Inclusive start offset (formatted or raw).
            win_end: Exclusive end offset (formatted or raw).
        """
        self._win_start = max(0, win_start)
        self._win_end = max(self._win_start, win_end)
        self._pos = 0
        self._parts: list[bytes] = []
        self._excluded_next_byte: int | None = None

    def advance_virtual(self, count: int) -> None:
        """Advances coordinate position for virtual prefixes (`"%d: "`)."""
        self._pos += count

    def append_segment(self, segment: bytes) -> None:
        """Appends any overlap of `segment` with `[win_start, win_end)`."""
        seg_len = len(segment)
        seg_start = self._pos
        seg_end = seg_start + seg_len
        self._pos = seg_end

        if seg_end <= self._win_start or seg_start > self._win_end:
            return

        if seg_start < self._win_end:
            clip_start = max(0, self._win_start - seg_start)
            clip_end = min(seg_len, self._win_end - seg_start)
            self._parts.append(segment[clip_start:clip_end])

        if seg_start <= self._win_end < seg_end:
            self._excluded_next_byte = segment[self._win_end - seg_start]

    def decode_utf8(self) -> str:
        """Aligns UTF-8 boundaries and decodes the retained slice."""
        joined = b"".join(self._parts)
        aligned = _trim_slice_utf8_boundaries(joined, self._excluded_next_byte)
        return aligned.decode("utf-8")


def _flatten_notebook_source(raw_source: Any) -> str:
    """Flattens an `.ipynb` cell `source` field (`str` or `list[str]`)."""
    if isinstance(raw_source, str):
        return raw_source
    if isinstance(raw_source, list):
        return "".join(part for part in raw_source if isinstance(part, str))
    return ""


def _has_non_empty_output_payload(payload_val: Any) -> bool:
    """Returns True if an `.ipynb` `outputs[].data[mime]` entry has content."""
    if isinstance(payload_val, str):
        return bool(payload_val.strip())
    if isinstance(payload_val, list):
        return any(
            isinstance(item, str) and bool(item.strip()) for item in payload_val
        )
    if isinstance(payload_val, Mapping):
        return bool(payload_val)
    return payload_val is not None


@dataclasses.dataclass(frozen=True)
class FileScanConfig:
    """v2-compatible pre-read scan and unscannable-media configuration.

    Attributes:
        pre_read_scan: Whether `PreToolUse` pre-reads `read_file`, `view_file`,
            and `notebook_edit` slices (`hooks.pre_read_scan` in `config.yaml`).
        on_unscannable_media: Policy (`"BLOCK"` or `"ALLOW"`) applied to binary
            multimodal media (`payload.on_unscannable_media` in `config.yaml`).
    """

    pre_read_scan: bool = True
    on_unscannable_media: str = "BLOCK"

    def __post_init__(self) -> None:
        coerced_scan = _parse_bool(self.pre_read_scan, True)
        object.__setattr__(self, "pre_read_scan", coerced_scan)
        raw_media = str(self.on_unscannable_media or "BLOCK").strip().upper()
        if raw_media not in VALID_UNSCANNABLE_MEDIA_ACTIONS:
            raw_media = "BLOCK"
        object.__setattr__(self, "on_unscannable_media", raw_media)

    def to_dict(self) -> dict[str, Any]:
        """Serializes configuration fields to a dictionary."""
        return {
            "pre_read_scan": self.pre_read_scan,
            "on_unscannable_media": self.on_unscannable_media,
        }

    @classmethod
    def from_config(
        cls,
        config_source: str | os.PathLike[str] | Mapping[str, Any] | None = None,
    ) -> FileScanConfig:
        """Loads `FileScanConfig` from a mapping or `config.yaml` file path.

        Args:
            config_source: Optional parsed config mapping (`{"hooks": ...,
                "payload": ...}`), path to `config.yaml`, or None to load the
                default `AGY-Plugin/config/config.yaml`.

        Returns:
            Validated `FileScanConfig` instance.
        """
        if isinstance(config_source, Mapping):
            hooks_sec = config_source.get("hooks")
            payload_sec = config_source.get("payload")
            raw_pre = (
                hooks_sec.get("pre_read_scan")
                if isinstance(hooks_sec, Mapping)
                else config_source.get("pre_read_scan", True)
            )
            raw_media = (
                payload_sec.get("on_unscannable_media")
                if isinstance(payload_sec, Mapping)
                else config_source.get("on_unscannable_media", "BLOCK")
            )
            return cls(
                pre_read_scan=_parse_bool(raw_pre, True),
                on_unscannable_media=(
                    str(raw_media) if raw_media is not None else "BLOCK"
                ),
            )

        if config_source is None or config_source == "":
            plugin_root = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            resolved_path = os.path.join(plugin_root, "config", "config.yaml")
        else:
            resolved_path = os.fspath(config_source)

        sections: dict[str, dict[str, str]] = {"hooks": {}, "payload": {}}
        try:
            st = os.stat(resolved_path)
            cache_key = (os.path.abspath(resolved_path), st.st_mtime_ns)
            cached = _YAML_CONFIG_CACHE.get(cache_key)
            if cached is not None:
                sections = cached
            else:
                with open(resolved_path, "r", encoding="utf-8") as cfg_file:
                    yaml_text = cfg_file.read()
                sections = {
                    "hooks": _parse_yaml_section(yaml_text, "hooks"),
                    "payload": _parse_yaml_section(yaml_text, "payload"),
                }
                _YAML_CONFIG_CACHE[cache_key] = sections
        except OSError:
            # Missing or unreadable config.yaml falls back to fail-closed defaults.
            pass

        pre_read = _parse_bool(sections["hooks"].get("pre_read_scan"), True)
        media_policy = sections["payload"].get("on_unscannable_media", "BLOCK")
        return cls(
            pre_read_scan=pre_read,
            on_unscannable_media=media_policy,
        )


@dataclasses.dataclass(frozen=True)
class PagedSliceResult:
    """Outcome of reading a bounded paged file view or notebook cell view.

    Attributes:
        status: `"SCAN"`, `"BLOCK_MEDIA"`, `"BLOCK_OVERSIZE"`, or `"SKIP"`.
        content: Extracted UTF-8 slice text when `status == "SCAN"`.
        reason: Policy denial message when `status` starts with `"BLOCK_"`.
    """

    status: str
    content: str = ""
    reason: str = ""


@dataclasses.dataclass(frozen=True)
class ToolScanRequest:
    """Input envelope for `FileScanner.extract_tool_scan_target`.

    Attributes:
        tool_name: Name of the Antigravity tool in `PreToolUse`.
        tool_args: Tool call arguments dictionary.
        workspace_paths: Active workspace root directories from hook payload.
    """

    tool_name: str
    tool_args: Mapping[str, Any]
    workspace_paths: Sequence[str] = ()


@dataclasses.dataclass(frozen=True)
class ScanExtractionResult:
    """Actionable scan payload produced for `PreInvocation` or `PreToolUse`.

    Attributes:
        action: `"SCAN"`, `"SKIP_CACHED"`, `"NO_ACTIONABLE_TEXT"`, or
            `"BLOCK_POLICY"`.
        text_to_scan: Full text payload to inspect when `action == "SCAN"`.
        source: Diagnostic source tag recorded in audit metadata.
        block_reason: Policy refusal reason when `action == "BLOCK_POLICY"`.
        slice_text: Extracted file or notebook view text alone (for partial
            cache lookup when only `args_text` varies).
        args_text: Extracted `_collect_nested_strings(tool_args)` text.
    """

    action: str
    text_to_scan: str = ""
    source: str = ""
    block_reason: str = ""
    slice_text: str = ""
    args_text: str = ""


class FileScanner:
    """Extracts paged text slices, `.ipynb` cells, and multimodal media verdicts."""

    def __init__(self, config: FileScanConfig | None = None) -> None:
        """Initializes the instance.

        Args:
            config: Optional explicit `FileScanConfig`; loads `config.yaml` when
                None.
        """
        self.config: FileScanConfig = (
            config if config is not None else FileScanConfig.from_config()
        )

    @staticmethod
    def split_char_chunks(
        text: str,
        chunk_chars: int = MULTI_CHUNK_MAX_CHARS,
        overlap_chars: int = MULTI_CHUNK_OVERLAP_CHARS,
    ) -> list[str]:
        """Splits `text` into overlapping character windows (`40,000` / `4,096`).

        Args:
            text: Full string to partition.
            chunk_chars: Maximum characters per chunk (`> 0`).
            overlap_chars: Characters repeated between consecutive chunks.

        Returns:
            Ordered list of overlapping character chunks (`[]` if `text` is empty).
        """
        if not text:
            return []
        eff_chunk = max(1, chunk_chars)
        eff_overlap = max(0, min(overlap_chars, eff_chunk - 1))
        if len(text) <= eff_chunk:
            return [text]

        stride = eff_chunk - eff_overlap
        chunks: list[str] = []
        pos = 0
        total_len = len(text)
        while pos < total_len:
            end = min(total_len, pos + eff_chunk)
            chunks.append(text[pos:end])
            if end >= total_len:
                break
            pos += stride
        return chunks

    def resolve_candidate_path(
        self, candidate: str, workspace_paths: Sequence[str] = ()
    ) -> str | None:
        """Resolves a local path or `file://` URI to an existing regular file.

        Args:
            candidate: Raw path or `file://` URI from tool arguments or media.
            workspace_paths: Ordered workspace directories for relative lookup.

        Returns:
            Canonical `realpath` to a regular file, or None if missing or
            non-regular (directory, FIFO, socket, or device node).
        """
        if not candidate or not candidate.strip():
            return None

        was_file_uri = candidate.strip().lower().startswith("file:")
        decoded = os.path.expanduser(decode_file_uri(candidate))
        if not decoded:
            return None

        candidates_to_try = [decoded]
        if not was_file_uri and "#" in decoded:
            stripped_frag = _LINE_FRAGMENT_SUFFIX_RE.sub("", decoded)
            if stripped_frag and stripped_frag != decoded:
                candidates_to_try.append(stripped_frag)

        search_roots = [w for w in workspace_paths if w] + [os.getcwd()]
        for path_item in candidates_to_try:
            probe_paths = (
                [path_item]
                if os.path.isabs(path_item)
                else [os.path.join(root, path_item) for root in search_roots]
            )
            for probe in probe_paths:
                try:
                    real_p = os.path.realpath(os.path.abspath(probe))
                    st = os.stat(real_p)
                    if stat.S_ISREG(st.st_mode):
                        return real_p
                except OSError:
                    continue
        return None

    @staticmethod
    def _resolve_pagination_args(
        tool_name: str, args: Mapping[str, Any]
    ) -> tuple[int | None, int | None, int, bool]:
        """Extracts `(start_line, end_line, byte_offset, offset_is_formatted)`.

        Reads nested `args["TextOptions"]` first (used by `view_file`) with
        per-field fallback to top-level `StartLine`, `EndLine`, `ContentOffset`,
        and `ByteOffset`.
        """
        text_opts = args.get("TextOptions")
        opts_map: Mapping[str, Any] = (
            text_opts if isinstance(text_opts, Mapping) else {}
        )

        start_line = _parse_non_bool_int(opts_map.get("StartLine"))
        if start_line is None:
            start_line = _parse_non_bool_int(args.get("StartLine"))

        end_line = _parse_non_bool_int(opts_map.get("EndLine"))
        if end_line is None:
            end_line = _parse_non_bool_int(args.get("EndLine"))

        content_offset = _parse_non_bool_int(opts_map.get("ContentOffset"))
        if content_offset is None:
            content_offset = _parse_non_bool_int(args.get("ContentOffset"))

        byte_offset = _parse_non_bool_int(opts_map.get("ByteOffset"))
        if byte_offset is None:
            byte_offset = _parse_non_bool_int(args.get("ByteOffset"))

        if tool_name == "view_file":
            raw_off = content_offset if content_offset is not None else byte_offset
            return start_line, end_line, max(0, raw_off or 0), False

        if byte_offset is not None:
            return start_line, end_line, max(0, byte_offset), True
        if content_offset is not None:
            return start_line, end_line, max(0, content_offset), False
        return start_line, end_line, 0, True

    def _classify_binary_action(self, real_path: str, head_bytes: bytes) -> PagedSliceResult:
        """Maps a confirmed binary file to `BLOCK_MEDIA` or `SKIP`."""
        mime_type = detect_multimodal_mime(real_path, head_bytes)
        if (
            self.config.on_unscannable_media == "BLOCK"
            and is_unscannable_multimodal_mime(mime_type)
        ):
            base_name = os.path.basename(real_path)
            return PagedSliceResult(
                status="BLOCK_MEDIA",
                reason=(
                    f"Unscannable multimodal binary media '{base_name}' "
                    f"({mime_type}) blocked under payload.on_unscannable_media=BLOCK."
                ),
            )
        return PagedSliceResult(status="SKIP")

    def read_paged_slice(
        self,
        file_path: str,
        start_line: int | None = None,
        end_line: int | None = None,
        byte_offset: int = 0,
        workspace_paths: Sequence[str] = (),
        *,
        tool_name: str = "read_file",
        offset_is_formatted: bool | None = None,
    ) -> PagedSliceResult:
        """Streams a bounded UTF-8 slice or classifies binary/multimodal files.

        Strips an optional UTF-8 BOM at byte 0, sniffs MIME from the first 512
        bytes, validates NUL-free strict UTF-8 across streamed 64 KiB rune-aligned
        chunks, and slices `[max(0, offset - 512), offset + 46,080]` with exact
        UTF-8 rune-boundary trimming at both ends.

        Args:
            file_path: Target path or `file://` URI.
            start_line: Optional 1-indexed inclusive start line.
            end_line: Optional 1-indexed inclusive end line.
            byte_offset: Non-negative byte offset (`ByteOffset` or `ContentOffset`).
            workspace_paths: Workspace roots for relative path resolution.
            tool_name: `"read_file"` or `"view_file"` (controls `EndLine`-only
                range semantics and default offset coordinate space).
            offset_is_formatted: Explicit override for whether `byte_offset`
                indexes `"%d: "` formatted bytes (`True`) or raw bytes (`False`).

        Returns:
            `PagedSliceResult` with `status` in `{"SCAN", "BLOCK_MEDIA", "SKIP"}`.
        """
        real_path = self.resolve_candidate_path(file_path, workspace_paths)
        if not real_path:
            return PagedSliceResult(status="SKIP")

        try:
            st = os.stat(real_path)
        except OSError:  # pragma: no cover - race after resolve_candidate_path
            return PagedSliceResult(status="SKIP")

        if st.st_size <= 0 or st.st_size > MAX_PAGED_FILE_SIZE_BYTES:
            return PagedSliceResult(status="SKIP")

        if tool_name == "view_file" and start_line is None and end_line is not None:
            eff_end = max(1, end_line)
            eff_start = max(1, eff_end - MAX_SCAN_LINES_PER_VIEW + 1)
        else:
            eff_start = max(1, start_line if start_line is not None else 1)
            raw_end = (
                max(eff_start, end_line)
                if end_line is not None
                else eff_start + MAX_SCAN_LINES_PER_VIEW - 1
            )
            eff_end = min(raw_end, eff_start + MAX_SCAN_LINES_PER_VIEW - 1)

        eff_offset = max(0, byte_offset)
        use_formatted = (
            offset_is_formatted
            if offset_is_formatted is not None
            else (tool_name == "read_file" and eff_offset > 0)
        )
        if eff_offset == 0:
            use_formatted = False

        win_start = (
            max(0, eff_offset - BYTE_OFFSET_OVERLAP_BYTES) if eff_offset > 0 else 0
        )
        win_end = eff_offset + MAX_SCAN_BYTES_PER_VIEW

        window = _BoundedByteWindow(win_start, win_end)
        last_line_window = _BoundedByteWindow(win_start, win_end)

        try:
            with open(real_path, "rb") as fh:
                first_raw = fh.read(STREAM_CHUNK_BYTES)
                if first_raw.startswith(_UTF8_BOM):
                    first_raw = first_raw[len(_UTF8_BOM) :]
                if not first_raw:
                    return PagedSliceResult(status="SKIP")

                head_512 = first_raw[:MIME_SNIFF_BYTES]
                if head_512.startswith(b"%PDF-"):
                    return self._classify_binary_action(real_path, head_512)

                carry = b""
                cur_raw = first_raw
                current_line = 0
                at_line_start = True
                matched_any_line = False
                lines_done = False

                while True:
                    raw_buf = carry + cur_raw
                    next_probe = fh.read(STREAM_CHUNK_BYTES)
                    at_eof = len(next_probe) == 0
                    if not at_eof:
                        chunk, carry = _split_incomplete_utf8_tail(raw_buf)
                    else:
                        chunk, carry = raw_buf, b""

                    if b"\x00" in chunk:
                        return self._classify_binary_action(real_path, head_512)
                    try:
                        chunk.decode("utf-8")
                    except UnicodeDecodeError:
                        return self._classify_binary_action(real_path, head_512)

                    if not lines_done:
                        pos = 0
                        chunk_len = len(chunk)
                        while pos < chunk_len:
                            nl_idx = chunk.find(b"\n", pos)
                            has_nl = nl_idx != -1
                            seg_end = (nl_idx + 1) if has_nl else chunk_len
                            seg = chunk[pos:seg_end]
                            line_started_here = at_line_start
                            if at_line_start:
                                current_line += 1
                            at_line_start = has_nl
                            pos = seg_end

                            if current_line < eff_start:
                                if line_started_here:
                                    last_line_window = _BoundedByteWindow(
                                        win_start, win_end
                                    )
                                    if use_formatted:
                                        last_line_window.advance_virtual(
                                            len(str(current_line)) + 2
                                        )
                                last_line_window.append_segment(seg)
                            else:
                                matched_any_line = True
                                if line_started_here and use_formatted:
                                    window.advance_virtual(
                                        len(str(current_line)) + 2
                                    )
                                window.append_segment(seg)
                                if current_line == eff_end and has_nl:
                                    lines_done = True
                                    break
                        # Note: `current_line` only increments when `at_line_start` is True,
                        # and `current_line == eff_end and has_nl` breaks immediately, so
                        # `current_line` never exceeds `eff_end` while `not lines_done`.

                    if at_eof:
                        break
                    cur_raw = next_probe
        except OSError:  # pragma: no cover - race after resolve_candidate_path
            return PagedSliceResult(status="SKIP")

        target_window = window if matched_any_line else last_line_window
        decoded = target_window.decode_utf8()
        if not decoded.strip():
            return PagedSliceResult(status="SKIP")
        return PagedSliceResult(status="SCAN", content=decoded)

    def extract_notebook_view(
        self,
        notebook_path: str,
        action: str,
        cell_index: Any = None,
        workspace_paths: Sequence[str] = (),
    ) -> PagedSliceResult:
        """Parses an `.ipynb` (`<= 10 MiB`) for `list`, `get`, or `get_with_outputs`.

        Matches `notebook_subhandler.go` cell rendering, blocks multimodal binary
        `outputs[].data` under `on_unscannable_media == "BLOCK"`, and enforces
        `MAX_PRE_READ_SCAN_CHARS` (`250,000` chars).

        Args:
            notebook_path: Path or `file://` URI to the `.ipynb` file.
            action: Lowercased `notebook_edit` action (`list`, `get`,
                `get_with_outputs`).
            cell_index: Requested 0-based `CellIndex` for `get` /
                `get_with_outputs`.
            workspace_paths: Workspace root directories for relative resolution.

        Returns:
            `PagedSliceResult` with `status` in
            `{"SCAN", "BLOCK_MEDIA", "BLOCK_OVERSIZE", "SKIP"}`.
        """
        real_path = self.resolve_candidate_path(notebook_path, workspace_paths)
        if not real_path:
            return PagedSliceResult(status="SKIP")

        try:
            st = os.stat(real_path)
        except OSError:  # pragma: no cover - race after resolve_candidate_path
            return PagedSliceResult(status="SKIP")

        if st.st_size <= 0:
            return PagedSliceResult(status="SKIP")

        if st.st_size > NOTEBOOK_MAX_FILE_BYTES:
            return PagedSliceResult(
                status="BLOCK_OVERSIZE",
                reason=(
                    f"Notebook '{os.path.basename(real_path)}' ({st.st_size} bytes) "
                    f"exceeds {NOTEBOOK_MAX_FILE_BYTES}-byte (10 MiB) pre-read limit."
                ),
            )

        try:
            with open(real_path, "rb") as fh:
                raw_bytes = fh.read(NOTEBOOK_MAX_FILE_BYTES + 1)
        except OSError:  # pragma: no cover - race after resolve_candidate_path
            return PagedSliceResult(status="SKIP")

        if len(raw_bytes) > NOTEBOOK_MAX_FILE_BYTES:  # pragma: no cover - concurrent growth
            return PagedSliceResult(
                status="BLOCK_OVERSIZE",
                reason=(
                    f"Notebook '{os.path.basename(real_path)}' exceeds "
                    f"{NOTEBOOK_MAX_FILE_BYTES}-byte (10 MiB) pre-read limit."
                ),
            )

        if raw_bytes.startswith(_UTF8_BOM):
            raw_bytes = raw_bytes[len(_UTF8_BOM) :]
        head_512 = raw_bytes[:MIME_SNIFF_BYTES]
        if head_512.startswith(b"%PDF-") or b"\x00" in raw_bytes:
            return self._classify_binary_action(real_path, head_512)

        try:
            nb_data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return PagedSliceResult(status="SKIP")

        if not isinstance(nb_data, Mapping):
            return PagedSliceResult(status="SKIP")
        cells = nb_data.get("cells")
        if not isinstance(cells, list):
            return PagedSliceResult(status="SKIP")

        act = action.strip().lower()
        if act == "list":
            lines = [f"Notebook has {len(cells)} cells:"]
            for idx, cell in enumerate(cells):
                if not isinstance(cell, Mapping):
                    continue
                cell_type = str(cell.get("cell_type") or "unknown")
                src_text = _flatten_notebook_source(cell.get("source"))
                preview = src_text.replace("\n", "\\n")
                if len(preview) > 100:
                    preview = preview[:100] + "..."
                lines.append(f"[{idx}] {cell_type}: {preview}")
            rendered = "\n".join(lines)
        elif act in {"get", "get_with_outputs"}:
            idx_val = _parse_non_bool_int(cell_index)
            if idx_val is None or idx_val < 0 or idx_val >= len(cells):
                return PagedSliceResult(status="SKIP")
            cell = cells[idx_val]
            if not isinstance(cell, Mapping):
                return PagedSliceResult(status="SKIP")
            cell_type = str(cell.get("cell_type") or "unknown")
            src_text = _flatten_notebook_source(cell.get("source"))

            if act == "get_with_outputs":
                outputs = cell.get("outputs")
                if isinstance(outputs, list):
                    if self.config.on_unscannable_media == "BLOCK":
                        for out_item in outputs:
                            if not isinstance(out_item, Mapping):
                                continue
                            data_bundle = out_item.get("data")
                            if not isinstance(data_bundle, Mapping):
                                continue
                            for mime_key, payload_val in data_bundle.items():
                                if is_unscannable_multimodal_mime(
                                    str(mime_key)
                                ) and _has_non_empty_output_payload(payload_val):
                                    return PagedSliceResult(
                                        status="BLOCK_MEDIA",
                                        reason=(
                                            f"Notebook cell [{idx_val}] output contains "
                                            f"unscannable binary media ({mime_key}) "
                                            f"blocked under payload.on_unscannable_media=BLOCK."
                                        ),
                                    )
                    if outputs:
                        outputs_json = json.dumps(
                            outputs, ensure_ascii=False, indent=2
                        )
                        rendered = (
                            f"Cell [{idx_val}] ({cell_type}):\n{src_text}\n\n"
                            f"Outputs:\n{outputs_json}"
                        )
                    else:
                        rendered = f"Cell [{idx_val}] ({cell_type}):\n{src_text}"
                else:
                    rendered = f"Cell [{idx_val}] ({cell_type}):\n{src_text}"
            else:
                rendered = f"Cell [{idx_val}] ({cell_type}):\n{src_text}"
        else:
            return PagedSliceResult(status="SKIP")

        if len(rendered) > MAX_PRE_READ_SCAN_CHARS:
            return PagedSliceResult(
                status="BLOCK_OVERSIZE",
                reason=(
                    f"Notebook '{os.path.basename(real_path)}' view ({len(rendered)} chars) "
                    f"exceeds {MAX_PRE_READ_SCAN_CHARS}-character pre-read scan limit."
                ),
            )

        return PagedSliceResult(status="SCAN", content=rendered)

    @classmethod
    def _collect_nested_strings(cls, value: Any) -> list[str]:
        """Recursively collects non-empty string and numeric values from `args`."""
        collected: list[str] = []
        if isinstance(value, str):
            if value.strip():
                collected.append(value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            collected.append(str(value))
        elif isinstance(value, Mapping):
            for nested_val in value.values():
                collected.extend(cls._collect_nested_strings(nested_val))
        elif isinstance(value, (list, tuple)):
            for item in value:
                collected.extend(cls._collect_nested_strings(item))
        return collected

    @staticmethod
    def _build_slice_scan_result(
        tool: str, slice_text: str, args_text: str
    ) -> ScanExtractionResult:
        """Combines extracted `slice_text` and `args_text` under the 250k-char cap."""
        combined = f"{args_text}\n{slice_text}" if args_text else slice_text
        if len(combined) > MAX_PRE_READ_SCAN_CHARS:
            return ScanExtractionResult(
                action="BLOCK_POLICY",
                block_reason=(
                    f"Combined {tool} scan payload ({len(combined)} chars) "
                    f"exceeds {MAX_PRE_READ_SCAN_CHARS}-character limit."
                ),
                source=f"tool_oversize:{tool}",
            )
        return ScanExtractionResult(
            action="SCAN",
            text_to_scan=combined,
            source=f"tool_file_content:{tool}",
            slice_text=slice_text,
            args_text=args_text,
        )

    def extract_tool_scan_target(
        self, request: ToolScanRequest
    ) -> ScanExtractionResult:
        """Extracts file/notebook read slices combined with `_collect_nested_strings`."""
        tool = (request.tool_name or "").strip()
        args = request.tool_args or {}
        ws_paths = request.workspace_paths or ()

        nested_strings = self._collect_nested_strings(args)
        args_text = "\n".join(nested_strings)

        if self.config.pre_read_scan:
            if tool in PAGED_FILE_READ_TOOLS:
                raw_path = (
                    args.get("Path")
                    or args.get("AbsolutePath")
                    or args.get("File")
                )
                if isinstance(raw_path, str) and raw_path.strip():
                    start_line, end_line, offset, is_fmt = (
                        self._resolve_pagination_args(tool, args)
                    )
                    paged = self.read_paged_slice(
                        raw_path,
                        start_line=start_line,
                        end_line=end_line,
                        byte_offset=offset,
                        workspace_paths=ws_paths,
                        tool_name=tool,
                        offset_is_formatted=is_fmt,
                    )
                    if paged.status == "BLOCK_MEDIA":
                        return ScanExtractionResult(
                            action="BLOCK_POLICY",
                            block_reason=paged.reason,
                            source=f"tool_unscannable_media:{tool}",
                        )
                    if paged.status == "SCAN":
                        return self._build_slice_scan_result(
                            tool, paged.content, args_text
                        )

            elif tool == "notebook_edit":
                action = str(args.get("Action") or "list").strip().lower()
                nb_path = (
                    args.get("NotebookPath")
                    or args.get("Path")
                    or args.get("AbsolutePath")
                )
                if (
                    action in NOTEBOOK_READ_ACTIONS
                    and isinstance(nb_path, str)
                    and nb_path.strip()
                ):
                    nb_res = self.extract_notebook_view(
                        nb_path,
                        action=action,
                        cell_index=args.get("CellIndex"),
                        workspace_paths=ws_paths,
                    )
                    if nb_res.status in {"BLOCK_MEDIA", "BLOCK_OVERSIZE"}:
                        return ScanExtractionResult(
                            action="BLOCK_POLICY",
                            block_reason=nb_res.reason,
                            source=f"tool_notebook_block:{action}",
                        )
                    if nb_res.status == "SCAN":
                        return self._build_slice_scan_result(
                            "notebook_edit", nb_res.content, args_text
                        )

        if args_text.strip():
            if len(args_text) > MAX_PRE_READ_SCAN_CHARS:
                return ScanExtractionResult(
                    action="BLOCK_POLICY",
                    block_reason=(
                        f"Tool arguments ({len(args_text)} chars) exceed "
                        f"{MAX_PRE_READ_SCAN_CHARS}-character pre-read scan limit."
                    ),
                    source=f"tool_args_oversize:{tool}",
                )
            return ScanExtractionResult(
                action="SCAN",
                text_to_scan=args_text,
                source=f"tool_args:{tool}",
                args_text=args_text,
            )

        return ScanExtractionResult(action="NO_ACTIONABLE_TEXT")
