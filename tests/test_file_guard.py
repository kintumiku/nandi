"""Unit tests for AGY-Plugin/src/file_guard/scanner.py."""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
plugin_root = os.path.join(repo_root, "AGY-Plugin")
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.file_guard import (
    BINARY_SNIFF_BYTES,
    BYTE_OFFSET_OVERLAP_BYTES,
    FileScanConfig,
    FileScanner,
    MAX_PAGED_FILE_SIZE_BYTES,
    MAX_PRE_READ_SCAN_CHARS,
    MAX_SCAN_BYTES_PER_VIEW,
    MAX_SCAN_LINES_PER_VIEW,
    MAX_SINGLE_SHOT_SCAN_BYTES,
    MIME_SNIFF_BYTES,
    MULTI_CHUNK_MAX_CHARS,
    MULTI_CHUNK_OVERLAP_CHARS,
    NOTEBOOK_MAX_FILE_BYTES,
    SCAN_CACHE_MAX_ENTRIES,
    SCAN_CACHE_TTL_SECONDS,
    STREAM_CHUNK_BYTES,
    ToolScanRequest,
    decode_file_uri,
    detect_multimodal_mime,
    is_unscannable_multimodal_mime,
)
from src.pii_guard.detector import PIIDetector

_UTF8_BOM_BYTES = b"\xef\xbb\xbf"


class TestFileGuardScanner(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_dir = tempfile.mkdtemp(prefix="nandi_test_fg_")

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def _write_bytes(self, rel_name: str, data: bytes) -> str:
        path = os.path.join(self._tmp_dir, rel_name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def _write_text(self, rel_name: str, text: str) -> str:
        return self._write_bytes(rel_name, text.encode("utf-8"))

    def test_ast_zero_coupling_import_boundary(self) -> None:
        scanner_path = os.path.join(plugin_root, "src", "file_guard", "scanner.py")
        with open(scanner_path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=scanner_path)

        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)

        forbidden = [
            mod for mod in imported_modules if mod.startswith(("src.hooks", "src.cli"))
        ]
        self.assertEqual(forbidden, [])

    def test_v2_constants_config_yaml_and_hooks_json_timeouts(self) -> None:
        self.assertEqual(MAX_SCAN_LINES_PER_VIEW, 800)
        self.assertEqual(MAX_SCAN_BYTES_PER_VIEW, 46_080)
        self.assertEqual(BYTE_OFFSET_OVERLAP_BYTES, 512)
        self.assertEqual(MAX_SINGLE_SHOT_SCAN_BYTES, 49_152)
        self.assertEqual(MAX_PRE_READ_SCAN_CHARS, 250_000)
        self.assertEqual(MULTI_CHUNK_MAX_CHARS, 40_000)
        self.assertEqual(MULTI_CHUNK_OVERLAP_CHARS, 4_096)
        self.assertEqual(NOTEBOOK_MAX_FILE_BYTES, 10_485_760)
        self.assertEqual(MAX_PAGED_FILE_SIZE_BYTES, 104_857_600)
        self.assertEqual(MIME_SNIFF_BYTES, 512)
        self.assertEqual(BINARY_SNIFF_BYTES, 512)
        self.assertEqual(STREAM_CHUNK_BYTES, 65_536)
        self.assertEqual(SCAN_CACHE_TTL_SECONDS, 7_200)
        self.assertEqual(SCAN_CACHE_MAX_ENTRIES, 2_000)

        cfg_yaml_path = os.path.join(plugin_root, "config", "config.yaml")
        with open(cfg_yaml_path, "r", encoding="utf-8") as fh:
            raw_cfg_yaml = fh.read()
        self.assertNotIn("file_scanning:", raw_cfg_yaml)
        loaded_default = FileScanConfig.from_config()
        self.assertEqual(
            loaded_default.to_dict(),
            {"pre_read_scan": True, "on_unscannable_media": "BLOCK"},
        )

        hooks_json_path = os.path.join(plugin_root, "hooks.json")
        with open(hooks_json_path, "r", encoding="utf-8") as fh:
            hooks_cfg = json.load(fh)

        timeouts: list[int] = []
        for guard_cfg in hooks_cfg.values():
            for stage in ("PreInvocation", "PostInvocation"):
                for item in guard_cfg[stage]:
                    timeouts.append(item["timeout"])
            for matcher_item in guard_cfg["PreToolUse"]:
                for hook_item in matcher_item["hooks"]:
                    timeouts.append(hook_item["timeout"])

        self.assertEqual(len(timeouts), 9)
        self.assertEqual([t for t in timeouts if t < 30], [])

    def test_file_scan_config_from_yaml_and_mapping_ignores_removed_env_vars(self) -> None:
        custom_yaml = self._write_text(
            "custom_config.yaml",
            (
                "# Top-level comment\n"
                "enforcement_mode: 'BLOCK'\n"
                "hooks:\n"
                "  pre_read_scan: false # inline comment\n"
                "  nested_block:\n"
                "    ignored_child: true\n"
                "payload:\n"
                '  on_unscannable_media: "ALLOW"\n'
                "model_armor:\n"
                "  enabled: true\n"
            ),
        )
        with patch.dict(
            os.environ,
            {
                "NANDI_PRE_READ_SCAN": "true",
                "NANDI_ON_UNSCANNABLE_MEDIA": "BLOCK",
                "NANDI_FILE_SCAN_ENABLED": "true",
                "NANDI_FILE_SCAN_MODE": "prompt_only",
            },
            clear=False,
        ):
            cfg_from_path = FileScanConfig.from_config(custom_yaml)
            cfg_cached = FileScanConfig.from_config(custom_yaml)

        self.assertEqual(
            cfg_from_path.to_dict(),
            {"pre_read_scan": False, "on_unscannable_media": "ALLOW"},
        )
        self.assertEqual(cfg_cached, cfg_from_path)

        cfg_from_map = FileScanConfig.from_config(
            {
                "hooks": {"pre_read_scan": "yes"},
                "payload": {"on_unscannable_media": "allow"},
            }
        )
        self.assertEqual(
            cfg_from_map.to_dict(),
            {"pre_read_scan": True, "on_unscannable_media": "ALLOW"},
        )

        cfg_flat_invalid = FileScanConfig.from_config(
            {"pre_read_scan": "invalid_bool", "on_unscannable_media": "INVALID"}
        )
        self.assertEqual(
            cfg_flat_invalid.to_dict(),
            {"pre_read_scan": True, "on_unscannable_media": "BLOCK"},
        )

        missing_cfg = FileScanConfig.from_config(
            os.path.join(self._tmp_dir, "nonexistent.yaml")
        )
        self.assertEqual(
            missing_cfg.to_dict(),
            {"pre_read_scan": True, "on_unscannable_media": "BLOCK"},
        )

    def test_unconditional_scan_on_clean_git_tracked_file_and_switch_off(self) -> None:
        git_ws = os.path.join(self._tmp_dir, "repo")
        os.makedirs(git_ws, exist_ok=True)
        subprocess.run(["git", "-C", git_ws, "init"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", git_ws, "config", "user.email", "ci@example.com"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", git_ws, "config", "user.name", "CI"],
            check=True,
            capture_output=True,
        )
        tracked_fixture = os.path.join(git_ws, "committed_fixture.py")
        with open(tracked_fixture, "w", encoding="utf-8") as fh:
            fh.write("COMMITTED_PAN = 'ABCPE1234F'\n")
        subprocess.run(
            ["git", "-C", git_ws, "add", "committed_fixture.py"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", git_ws, "commit", "-m", "add fixture"],
            check=True,
            capture_output=True,
        )
        status_out = subprocess.run(
            ["git", "-C", git_ws, "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(status_out.stdout.strip(), "")

        scanner_on = FileScanner(FileScanConfig(pre_read_scan=True))
        res_on = scanner_on.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="read_file",
                tool_args={"Path": "committed_fixture.py"},
                workspace_paths=[git_ws],
            )
        )
        self.assertEqual(res_on.action, "SCAN")
        self.assertEqual(res_on.source, "tool_file_content:read_file")
        self.assertIn("ABCPE1234F", res_on.text_to_scan)
        detector = PIIDetector()
        pii_report = detector.scan(res_on.text_to_scan, action_mode="BLOCK")
        self.assertEqual(pii_report.blocked_by_policy, True)

        scanner_off = FileScanner(FileScanConfig(pre_read_scan=False))
        res_off = scanner_off.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="read_file",
                tool_args={"Path": "committed_fixture.py"},
                workspace_paths=[git_ws],
            )
        )
        self.assertEqual(res_off.action, "SCAN")
        self.assertEqual(res_off.source, "tool_args:read_file")
        self.assertNotIn("ABCPE1234F", res_off.text_to_scan)

    def test_non_read_tools_only_scan_inline_args(self) -> None:
        secret_file = self._write_text("secret.txt", "PAN = ABCPE1234F\n")
        scanner = FileScanner(FileScanConfig(pre_read_scan=True))

        for tool_name, tool_args in (
            ("run_command", {"CommandLine": f"cat {secret_file}", "WaitMs": 500, "Bg": False}),
            ("grep_search", {"SearchPath": self._tmp_dir, "Query": "revenue", "Weights": [1.5, ("tag", 2)]}),
            ("find_by_name", {"SearchDirectory": self._tmp_dir, "Pattern": "*.txt"}),
            ("list_dir", {"DirectoryPath": self._tmp_dir}),
        ):
            with self.subTest(tool=tool_name):
                res = scanner.extract_tool_scan_target(
                    ToolScanRequest(
                        tool_name=tool_name,
                        tool_args=tool_args,
                        workspace_paths=[self._tmp_dir],
                    )
                )
                self.assertEqual(res.action, "SCAN")
                self.assertEqual(res.source, f"tool_args:{tool_name}")
                self.assertNotIn("ABCPE1234F", res.text_to_scan)

        empty_res = scanner.extract_tool_scan_target(
            ToolScanRequest(tool_name="run_command", tool_args={"Flag": True, "Empty": "   "})
        )
        self.assertEqual(empty_res.action, "NO_ACTIONABLE_TEXT")

        oversize_args_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="run_command",
                tool_args={"CommandLine": "x" * (MAX_PRE_READ_SCAN_CHARS + 1)},
            )
        )
        self.assertEqual(oversize_args_res.action, "BLOCK_POLICY")
        self.assertEqual(oversize_args_res.source, "tool_args_oversize:run_command")

    def test_view_file_nested_text_options_endline_only_and_past_eof_fallback(self) -> None:
        lines = [f"row-{i:04d}" for i in range(1, 1501)]
        lines[1204] = "row-1205 PAN ABCPE1234F"
        doc_path = self._write_text("large_doc.txt", "\n".join(lines) + "\n")
        scanner = FileScanner(FileScanConfig(pre_read_scan=True))

        nested_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="view_file",
                tool_args={
                    "AbsolutePath": doc_path,
                    "StartLine": 1,
                    "EndLine": 5,
                    "TextOptions": {"StartLine": 1200, "EndLine": 1210},
                },
            )
        )
        self.assertEqual(nested_res.action, "SCAN")
        self.assertIn("row-1205 PAN ABCPE1234F", nested_res.slice_text)
        self.assertNotIn("row-0001", nested_res.slice_text)
        self.assertNotIn("row-1211", nested_res.slice_text)

        fallback_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="view_file",
                tool_args={
                    "AbsolutePath": doc_path,
                    "EndLine": "1206",
                    "TextOptions": {"StartLine": 1204.0, "ContentOffset": False},
                },
            )
        )
        self.assertEqual(
            fallback_res.slice_text.splitlines(),
            ["row-1204", "row-1205 PAN ABCPE1234F", "row-1206"],
        )

        end_only_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="view_file",
                tool_args={"AbsolutePath": doc_path, "TextOptions": {"EndLine": 1000}},
            )
        )
        end_only_lines = end_only_res.slice_text.splitlines()
        self.assertEqual(len(end_only_lines), 800)
        self.assertEqual(end_only_lines[0], "row-0201")
        self.assertEqual(end_only_lines[-1], "row-1000")

        past_eof_res = scanner.read_paged_slice(
            doc_path, start_line=5000, end_line=5100, tool_name="read_file"
        )
        self.assertEqual(past_eof_res.status, "SCAN")
        self.assertEqual(past_eof_res.content, "row-1500\n")

    def test_separated_read_file_formatted_vs_view_file_raw_byte_offsets_fit_single_shot(self) -> None:
        # 600 lines, each raw line = 100 bytes ("L001:" + 94 chars + "\n").
        # Formatted read_file adds "%d: " (3..5 bytes per line).
        raw_lines: list[str] = []
        for line_no in range(1, 601):
            tag = f"L{line_no:03d}:"
            body = f"{line_no % 10}" * (99 - len(tag))
            raw_lines.append(f"{tag}{body}\n")
        target_path = self._write_text("paged_offsets.txt", "".join(raw_lines))
        scanner = FileScanner(FileScanConfig(pre_read_scan=True))

        # Compute exact formatted offset of line 501 ("501: L501:...") vs raw offset of line 501.
        formatted_offset_501 = sum(
            len(f"{idx}: ".encode("utf-8")) + len(raw_lines[idx - 1].encode("utf-8"))
            for idx in range(1, 501)
        )
        raw_offset_501 = 500 * 100
        self.assertNotEqual(formatted_offset_501, raw_offset_501)

        read_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="read_file",
                tool_args={
                    "Path": target_path,
                    "StartLine": 1,
                    "EndLine": 600,
                    "ByteOffset": formatted_offset_501,
                },
            )
        )
        view_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="view_file",
                tool_args={
                    "AbsolutePath": target_path,
                    "TextOptions": {
                        "StartLine": 1,
                        "EndLine": 600,
                        "ContentOffset": raw_offset_501,
                    },
                },
            )
        )
        self.assertEqual(read_res.action, "SCAN")
        self.assertEqual(view_res.action, "SCAN")
        self.assertIn("L501:", read_res.slice_text)
        self.assertIn("L501:", view_res.slice_text)

        # Verify full-page paginated read + 512 B overlap + normal args fits <= 49,152 B (1 RPC)!
        big_single_line = self._write_text("single_200kb.txt", "A" * 200_000)
        page2 = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="read_file",
                tool_args={"Path": big_single_line, "ByteOffset": 46_080},
            )
        )
        self.assertEqual(len(page2.slice_text), MAX_SCAN_BYTES_PER_VIEW + BYTE_OFFSET_OVERLAP_BYTES)
        self.assertLessEqual(
            len(page2.text_to_scan.encode("utf-8")),
            MAX_SINGLE_SHOT_SCAN_BYTES,
        )

        # Also test ContentOffset fallback on read_file
        raw_fallback = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="read_file",
                tool_args={"Path": target_path, "ContentOffset": raw_offset_501},
            )
        )
        self.assertIn("L501:", raw_fallback.slice_text)

    def test_utf8_multibyte_boundary_alignment_bom_and_64kib_streaming(self) -> None:
        # 1. Multi-byte runes straddling the 65,536-byte STREAM_CHUNK_BYTES boundary:
        # Put 2-byte 'é' (C3 A9), 3-byte '₹' (E2 82 B9), and 4-byte '𝕳' (F0 9D 95 B3) across 65,536.
        for pad_len, rune in (
            (STREAM_CHUNK_BYTES - 1, "é"),
            (STREAM_CHUNK_BYTES - 1, "₹"),
            (STREAM_CHUNK_BYTES - 2, "₹"),
            (STREAM_CHUNK_BYTES - 3, "𝕳"),
        ):
            with self.subTest(pad_len=pad_len, rune=rune):
                raw_data = b"\xef\xbb\xbf" + (b"a" * pad_len) + rune.encode("utf-8") + b"\ntail\n"
                fpath = self._write_bytes(f"stream_{pad_len}_{ord(rune)}.txt", raw_data)
                scanner = FileScanner()
                res = scanner.read_paged_slice(fpath, start_line=1, end_line=5, byte_offset=pad_len)
                self.assertEqual(res.status, "SCAN")
                self.assertIn(rune, res.content)

        # 2. Exact b_end preservation vs split trimming on 3-byte '₹' (E2 82 B9):
        # Case A: '₹' ends at exact byte 46,080 -> excluded_next_byte is ASCII 'Z', so '₹' MUST stay!
        prefix_complete = ("x" * (MAX_SCAN_BYTES_PER_VIEW - 3)).encode("utf-8")
        complete_path = self._write_bytes(
            "complete_end.txt", prefix_complete + "₹".encode("utf-8") + b"Z"
        )
        scanner = FileScanner()
        complete_res = scanner.read_paged_slice(complete_path)
        self.assertEqual(complete_res.status, "SCAN")
        self.assertEqual(complete_res.content[-1], "₹")
        self.assertEqual(len(complete_res.content.encode("utf-8")), MAX_SCAN_BYTES_PER_VIEW)

        # Case B: '₹' starts at 46,079 (only 1 byte E2 inside 46,080; excluded_next_byte = 0x82) -> backed up cleanly!
        prefix_split = ("x" * (MAX_SCAN_BYTES_PER_VIEW - 1)).encode("utf-8")
        split_path = self._write_bytes(
            "split_end.txt", prefix_split + "₹".encode("utf-8") + b"Z"
        )
        split_res = scanner.read_paged_slice(split_path)
        self.assertEqual(split_res.status, "SCAN")
        self.assertEqual(len(split_res.content.encode("utf-8")), MAX_SCAN_BYTES_PER_VIEW - 1)

        # Case C: win_start (offset - 512) lands on continuation byte of '₹':
        # Put '₹' spanning bytes 511..513 (indices 511, 512, 513), then set raw ContentOffset = 1024 -> win_start = 512!
        start_split_bytes = (b"a" * 511) + "₹".encode("utf-8") + b"AFTER" + (b"b" * 1000)
        start_split_path = self._write_bytes("split_start.txt", start_split_bytes)
        start_split_res = scanner.read_paged_slice(
            start_split_path,
            byte_offset=512 + BYTE_OFFSET_OVERLAP_BYTES,
            tool_name="view_file",
            offset_is_formatted=False,
        )
        self.assertEqual(start_split_res.status, "SCAN")
        self.assertEqual(start_split_res.content[:5], "AFTER")

    def test_multimodal_binary_blocking_false_positive_guards_and_non_media_skip(self) -> None:
        scanner_block = FileScanner(
            FileScanConfig(pre_read_scan=True, on_unscannable_media="BLOCK")
        )
        scanner_allow = FileScanner(
            FileScanConfig(pre_read_scan=True, on_unscannable_media="ALLOW")
        )

        # Multimodal binaries (including ASCII-clean %PDF-1.7 and extension-spoofed PNG in .txt)
        multimodal_samples: list[tuple[str, bytes, str]] = [
            ("doc.pdf", b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n", "application/pdf"),
            ("spoofed.txt", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "image/png"),
            ("photo.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF", "image/jpeg"),
            ("anim.gif", b"GIF89a\x01\x00\x01\x00\x00", "image/gif"),
            ("pic.webp", b"RIFF\x24\x00\x00\x00WEBPVP8 ", "image/webp"),
            ("sound.wav", b"RIFF\x24\x00\x00\x00WAVEfmt ", "audio/wav"),
            ("clip.avi", b"RIFF\x24\x00\x00\x00AVI LIST", "video/avi"),
            ("track.aiff", b"FORM\x00\x00\x00\x10AIFFCOMM", "audio/aiff"),
            ("icon.ico", b"\x00\x00\x01\x00\x01\x00", "image/x-icon"),
            ("scan.tiff", b"II*\x00\x08\x00\x00\x00", "image/tiff"),
            ("img.avif", b"\x00\x00\x00\x1cftypavif\x00\x00", "image/avif"),
            ("img.heic", b"\x00\x00\x00\x18ftypheic\x00\x00", "image/heic"),
            ("voice.m4a", b"\x00\x00\x00\x18ftypM4A \x00\x00", "audio/mp4"),
            ("movie.mp4", b"\x00\x00\x00\x18ftypisom\x00\x00", "video/mp4"),
            ("audio.ogg", b"OggS\x00\x02\x00\x00", "audio/ogg"),
            ("video.ogv", b"OggS\x00\x02\x00\x00", "video/ogg"),
            ("music.flac", b"fLaC\x00\x00\x00\x22", "audio/flac"),
            ("tune.midi", b"MThd\x00\x00\x00\x06", "audio/midi"),
            ("song.mp3", b"ID3\x04\x00\x00\x00\x00", "audio/mpeg"),
            ("frame.mp3", b"\xff\xfb\x90\x64\x00", "audio/mpeg"),
            ("stream.webm", b"\x1a\x45\xdf\xa3\x00", "video/webm"),
            ("legacy.flv", b"FLV\x01\x05\x00\x00\x00\x09", "video/x-flv"),
            (
                "report.docx",
                b"PK\x03\x04\x14\x00\x00\x00",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            (
                "sheet.odt",
                b"PK\x03\x04\x14\x00\x00\x00",
                "application/vnd.oasis.opendocument.text",
            ),
            ("legacy.xls", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00", "application/msword"),
        ]
        for fname, raw_bytes, _ in multimodal_samples:
            with self.subTest(media=fname):
                fpath = self._write_bytes(fname, raw_bytes)
                blk = scanner_block.read_paged_slice(fpath, tool_name="view_file")
                self.assertEqual(blk.status, "BLOCK_MEDIA")
                alw = scanner_allow.read_paged_slice(fpath, tool_name="view_file")
                self.assertEqual(alw.status, "SKIP")

        # False-positive guards: valid UTF-8 text starting with BM / GIF89a / ID3 or .svg extension
        for text_name, content in (
            ("metrics.csv", "BMI,age,pan\n22.4,31,ABCPE1234F\n"),
            ("gif_spec.txt", "GIF89a header specification notes\n"),
            ("id3_notes.txt", "ID3 metadata parser documentation\n"),
            ("vector.svg", '<svg xmlns="http://www.w3.org/2000/svg"><text>ABCPE1234F</text></svg>'),
        ):
            with self.subTest(scannable_text=text_name):
                tpath = self._write_text(text_name, content)
                res = scanner_block.read_paged_slice(tpath, tool_name="view_file")
                self.assertEqual(res.status, "SCAN")
                self.assertEqual(res.content, content)

        self.assertIsNone(detect_multimodal_mime("diagram.svg", b"<svg></svg>"))
        self.assertEqual(is_unscannable_multimodal_mime("image/svg+xml"), False)
        self.assertEqual(is_unscannable_multimodal_mime("text/csv; charset=utf-8"), False)
        self.assertEqual(is_unscannable_multimodal_mime(""), False)

        # Non-media binaries -> SKIP even under on_unscannable_media="BLOCK"
        non_media_samples: list[tuple[str, bytes]] = [
            ("utf16le.txt", b"\xff\xfeH\x00i\x00"),
            ("archive.zip", b"PK\x03\x04\x14\x00\x00\x00"),
            ("program.bin", b"\x7fELF\x02\x01\x01\x00"),
            ("late_nul.txt", (b"A\n" * 35_000) + b"\x00BINARY_TAIL"),
            ("eof_trunc_utf8.txt", (b"B\n" * 35_000) + b"\xe2\x82"),
            ("bad_lead.bin", b"\xf9\x80\x80\x80"),
        ]
        for bname, bdata in non_media_samples:
            with self.subTest(non_media=bname):
                bpath = self._write_bytes(bname, bdata)
                res = scanner_block.read_paged_slice(bpath, start_line=1, end_line=10)
                self.assertEqual(res.status, "SKIP")

        # Media-extension file whose first 64 KiB is ASCII lines (>800 lines) and has NUL at 75 KiB:
        # must_verify_full_file=True forces full-file verification even after lines_done!
        late_bmp = self._write_bytes("tricky.bmp", (b"BM line\n" * 10_000) + b"\x00")
        late_bmp_res = scanner_block.read_paged_slice(
            late_bmp, start_line=1, end_line=5, tool_name="view_file"
        )
        self.assertEqual(late_bmp_res.status, "BLOCK_MEDIA")

    def test_decode_file_uri_and_candidate_resolution(self) -> None:
        spaced_dir = os.path.join(self._tmp_dir, "dir with spaces")
        os.makedirs(spaced_dir, exist_ok=True)
        hash_file = os.path.join(spaced_dir, "doc#1.txt")
        with open(hash_file, "w", encoding="utf-8") as fh:
            fh.write("PAN: ABCPE1234F\n")

        uri = "file://" + urllib.parse.quote(hash_file) + "#L1-L5"
        scanner = FileScanner()
        resolved_uri = scanner.resolve_candidate_path(f'"{uri}"')
        self.assertEqual(resolved_uri, os.path.realpath(hash_file))

        # Literal '#' in plain filesystem path is preserved without stripping
        literal_csharp = self._write_text("c#_guide.txt", "clean guide\n")
        self.assertEqual(
            scanner.resolve_candidate_path(literal_csharp),
            os.path.realpath(literal_csharp),
        )

        # Plain path with #L10-L20 line range suffix falls back cleanly
        plain_py = self._write_text("module.py", "x = 1\n")
        self.assertEqual(
            scanner.resolve_candidate_path(f"{plain_py}#L1-L1"),
            os.path.realpath(plain_py),
        )

        # localhost, Windows drive URI, and UNC host URI decoding
        self.assertEqual(
            decode_file_uri("file://localhost/tmp/example.txt"), "/tmp/example.txt"
        )
        if os.name != "nt":
            self.assertEqual(
                decode_file_uri("file:///C:/Users/dev/file.py"),
                "C:/Users/dev/file.py",
            )
            self.assertEqual(
                decode_file_uri("file://fileserver/share/report.csv"),
                "//fileserver/share/report.csv",
            )

        # Missing, whitespace, directory, or empty file returns None / SKIP
        self.assertIsNone(scanner.resolve_candidate_path("   "))
        self.assertIsNone(scanner.resolve_candidate_path(self._tmp_dir))
        empty_f = self._write_bytes("empty.txt", b"")
        self.assertEqual(scanner.read_paged_slice(empty_f).status, "SKIP")
        bom_only = self._write_bytes("bom_only.txt", b"\xef\xbb\xbf")
        self.assertEqual(scanner.read_paged_slice(bom_only).status, "SKIP")

    def test_notebook_edit_cell_extraction_media_gate_and_limits(self) -> None:
        nb_payload = {
            "cells": [
                {
                    "cell_type": "markdown",
                    "source": ["# Secret Cell 0\n", "PAN: ABCPE1234F\n" + ("x" * 110)],
                },
                {
                    "cell_type": "code",
                    "source": "print('clean cell 1')",
                    "outputs": [
                        {
                            "output_type": "display_data",
                            "data": {
                                "text/plain": ["clean output"],
                                "image/svg+xml": "<svg><text>ok</text></svg>",
                                "image/png": "",
                            },
                        }
                    ],
                },
                {
                    "cell_type": "code",
                    "source": ["plt.show()"],
                    "outputs": [
                        {
                            "output_type": "display_data",
                            "data": {"image/png": "iVBORw0KGgoAAAANSUhEUg=="},
                        }
                    ],
                },
            ]
        }
        nb_path = self._write_text("analysis.ipynb", json.dumps(nb_payload))
        scanner = FileScanner(
            FileScanConfig(pre_read_scan=True, on_unscannable_media="BLOCK")
        )

        # 1. Action="list" renders truncated 100-char cell previews
        list_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={"NotebookPath": nb_path, "Action": "list"},
            )
        )
        self.assertEqual(list_res.action, "SCAN")
        self.assertIn("Notebook has 3 cells:", list_res.slice_text)
        self.assertIn("...", list_res.slice_text)

        # 2. Action="get" on CellIndex=1 omits CellIndex=0's PAN
        get_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={"NotebookPath": nb_path, "Action": "get", "CellIndex": 1},
            )
        )
        self.assertEqual(get_res.action, "SCAN")
        self.assertIn("Cell [1] (code):\nprint('clean cell 1')", get_res.slice_text)
        self.assertNotIn("ABCPE1234F", get_res.slice_text)

        # 3. Action="get_with_outputs" on CellIndex=1 (SVG + empty PNG) -> SCAN
        out_clean = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={
                    "NotebookPath": nb_path,
                    "Action": "get_with_outputs",
                    "CellIndex": 1,
                },
            )
        )
        self.assertEqual(out_clean.action, "SCAN")
        self.assertIn("Outputs:", out_clean.slice_text)

        # 4. Action="get_with_outputs" on CellIndex=2 (non-empty image/png) -> BLOCK_POLICY under BLOCK, SCAN under ALLOW
        out_png_blk = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={
                    "NotebookPath": nb_path,
                    "Action": "get_with_outputs",
                    "CellIndex": 2,
                },
            )
        )
        self.assertEqual(out_png_blk.action, "BLOCK_POLICY")
        self.assertIn("image/png", out_png_blk.block_reason)

        scanner_allow = FileScanner(
            FileScanConfig(pre_read_scan=True, on_unscannable_media="ALLOW")
        )
        out_png_alw = scanner_allow.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={
                    "NotebookPath": nb_path,
                    "Action": "get_with_outputs",
                    "CellIndex": 2,
                },
            )
        )
        self.assertEqual(out_png_alw.action, "SCAN")

        # 5. Mutating Action="replace" scans inline args without dumping cell 0 from disk
        replace_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={
                    "NotebookPath": nb_path,
                    "Action": "replace",
                    "CellIndex": 1,
                    "NewSource": "x = 42",
                },
            )
        )
        self.assertEqual(replace_res.action, "SCAN")
        self.assertEqual(replace_res.source, "tool_args:notebook_edit")
        self.assertNotIn("ABCPE1234F", replace_res.text_to_scan)

        # 6. > 250,000-char cell output -> BLOCK_POLICY
        huge_cell_nb = self._write_text(
            "huge_cell.ipynb",
            json.dumps(
                {
                    "cells": [
                        {
                            "cell_type": "code",
                            "source": "x" * (MAX_PRE_READ_SCAN_CHARS + 50),
                        }
                    ]
                }
            ),
        )
        huge_cell_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={
                    "NotebookPath": huge_cell_nb,
                    "Action": "get",
                    "CellIndex": 0,
                },
            )
        )
        self.assertEqual(huge_cell_res.action, "BLOCK_POLICY")
        self.assertIn("250000", huge_cell_res.block_reason)

        # 7. > 10 MiB .ipynb file -> BLOCK_POLICY before JSON parsing
        oversize_nb = self._write_bytes(
            "oversize.ipynb", b" " * (NOTEBOOK_MAX_FILE_BYTES + 1)
        )
        oversize_nb_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={"NotebookPath": oversize_nb, "Action": "list"},
            )
        )
        self.assertEqual(oversize_nb_res.action, "BLOCK_POLICY")
        self.assertIn("10 MiB", oversize_nb_res.block_reason)

        # 8. Out-of-bounds CellIndex or invalid JSON falls back to args scan
        oob_res = scanner.extract_notebook_view(nb_path, action="get", cell_index=99)
        self.assertEqual(oob_res.status, "SKIP")
        bad_json_nb = self._write_text("bad.ipynb", "{not-json")
        self.assertEqual(
            scanner.extract_notebook_view(bad_json_nb, action="list").status, "SKIP"
        )

    def test_split_char_chunks_overlap_preserves_boundary_tokens(self) -> None:
        self.assertEqual(FileScanner.split_char_chunks(""), [])
        self.assertEqual(FileScanner.split_char_chunks("short"), ["short"])

        marker = "BOUNDARY_INJECTION_ABCPE1234F"
        left = "a" * (MULTI_CHUNK_MAX_CHARS - 10)
        right = "b" * 50_000
        full_text = left + marker + right

        chunks = FileScanner.split_char_chunks(
            full_text,
            chunk_chars=MULTI_CHUNK_MAX_CHARS,
            overlap_chars=MULTI_CHUNK_OVERLAP_CHARS,
        )
        self.assertEqual(len(chunks), 3)
        self.assertEqual(len(chunks[0]), MULTI_CHUNK_MAX_CHARS)
        self.assertEqual(len(chunks[1]), MULTI_CHUNK_MAX_CHARS)
        self.assertNotIn(marker, chunks[0])
        self.assertIn(marker, chunks[1])

    def test_utf8_streaming_chunk_boundaries_and_window_edges(self) -> None:
        scanner = FileScanner(
            FileScanConfig(pre_read_scan=True, on_unscannable_media="BLOCK")
        )

        # 1. 2-byte, 3-byte, and 4-byte UTF-8 runes straddling exact 64 KiB boundary (no BOM)
        for label, rune, pad_len in (
            ("2b", "é", STREAM_CHUNK_BYTES - 1),
            ("3b", "€", STREAM_CHUNK_BYTES - 2),
            ("4b", "🔒", STREAM_CHUNK_BYTES - 3),
            ("2b_exact_end", "é", STREAM_CHUNK_BYTES - 2),
        ):
            raw = (b"a" * pad_len) + rune.encode("utf-8") + b"tail\n"
            fpath = self._write_bytes(f"split_{label}.txt", raw)
            res = scanner.read_paged_slice(
                fpath,
                byte_offset=STREAM_CHUNK_BYTES - 16,
                tool_name="view_file",
            )
            self.assertEqual(res.status, "SCAN")
            self.assertIn(rune + "tail\n", res.content)

        # 2. Invalid lead byte (>= 0xF8) and 3 orphan continuation bytes across >64 KiB -> SKIP
        bad_lead = self._write_bytes(
            "bad_lead_64k.bin", (b"a" * (STREAM_CHUNK_BYTES - 1)) + b"\xf8tail\n"
        )
        self.assertEqual(scanner.read_paged_slice(bad_lead).status, "SKIP")

        bad_cont = self._write_bytes(
            "bad_cont_64k.bin", (b"a" * (STREAM_CHUNK_BYTES - 3)) + b"\x80\x80\x80tail\n"
        )
        self.assertEqual(scanner.read_paged_slice(bad_cont).status, "SKIP")

        # 3. Clean >64 KiB file with early end_line=2 finishes lines in chunk 1 & validates chunk 2
        clean_70k = self._write_text(
            "clean_70k.txt", "line1\nline2\n" + ("x" * 70_000) + "\n"
        )
        early_res = scanner.read_paged_slice(clean_70k, start_line=1, end_line=2)
        self.assertEqual(early_res.status, "SCAN")
        self.assertEqual(early_res.content, "line1\nline2\n")

        # 4. >64 KiB first line without newline when start_line=2 (line_started_here=False in chunk 2)
        long_first = self._write_text(
            "long_first.txt", ("z" * 70_000) + "\nsecond_line_ok\n"
        )
        second_res = scanner.read_paged_slice(long_first, start_line=2, end_line=2)
        self.assertEqual(second_res.status, "SCAN")
        self.assertEqual(second_res.content, "second_line_ok\n")

        # 5. StartLine past EOF with formatted ByteOffset > 0 uses last_line_window.advance_virtual
        three_line = self._write_text("three.txt", "alpha\nbeta\ngamma_delta\n")
        past_eof_fmt = scanner.read_paged_slice(
            three_line, start_line=99, byte_offset=3, tool_name="read_file"
        )
        self.assertEqual(past_eof_fmt.status, "SCAN")
        self.assertEqual(past_eof_fmt.content, "gamma_delta\n")

        # 6. Offset past entire file produces empty window -> SKIP; whitespace-only file -> SKIP
        self.assertEqual(
            scanner.read_paged_slice(three_line, byte_offset=999_999).status, "SKIP"
        )
        ws_only = self._write_text("ws_only.txt", "   \n\t\n")
        self.assertEqual(scanner.read_paged_slice(ws_only).status, "SKIP")

        # 7. Exact segment boundary landing on win_end (seg_start == win_end on line 2)
        exact_win = self._write_text(
            "exact_win.txt", ("m" * (MAX_SCAN_BYTES_PER_VIEW - 1)) + "\nline2\n"
        )
        exact_res = scanner.read_paged_slice(exact_win, byte_offset=0)
        self.assertEqual(exact_res.status, "SCAN")
        self.assertEqual(len(exact_res.content), MAX_SCAN_BYTES_PER_VIEW)

    def test_pagination_coercion_uri_quotes_riff_and_notebook_edges(self) -> None:
        scanner = FileScanner(
            FileScanConfig(pre_read_scan=True, on_unscannable_media="BLOCK")
        )
        sample_path = self._write_text("sample.txt", "row1\nrow2\nrow3\n")

        # 1. Non-integer float, non-numeric string, list, and TextOptions.ByteOffset fallbacks
        coerced_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="read_file",
                tool_args={
                    "Path": sample_path,
                    "StartLine": "not_an_int",
                    "EndLine": 2.5,
                    "ContentOffset": [1],
                    "TextOptions": {"ByteOffset": 2.0},
                },
            )
        )
        self.assertEqual(coerced_res.action, "SCAN")
        self.assertIn("row1\nrow2\nrow3\n", coerced_res.slice_text)

        # 2. Quoted file:// URI & empty file:// URI resolution
        self.assertEqual(
            decode_file_uri("'file:///tmp/quoted.txt'"), "/tmp/quoted.txt"
        )
        self.assertIsNone(scanner.resolve_candidate_path("file://"))

        # 3. RIFF container with non-multimodal fourcc ("JUNK") + binary NUL -> SKIP
        riff_junk = self._write_bytes("archive.bin", b"RIFF\x04\x00\x00\x00JUNK\x00\x01")
        self.assertEqual(scanner.read_paged_slice(riff_junk).status, "SKIP")

        # 4. Combined slice + args exceeding 250,000 chars -> BLOCK_POLICY
        slice_45k = self._write_text("medium.txt", "s" * 45_000)
        oversize_comb = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="read_file",
                tool_args={"Path": slice_45k, "ExtraContext": "p" * 210_000},
            )
        )
        self.assertEqual(oversize_comb.action, "BLOCK_POLICY")
        self.assertEqual(oversize_comb.source, "tool_oversize:read_file")

        # 5. Notebook edge cases: missing, empty, BOM, binary, non-dict JSON, non-list cells, action="replace"
        self.assertEqual(
            scanner.extract_notebook_view(
                os.path.join(self._tmp_dir, "missing.ipynb"), action="list"
            ).status,
            "SKIP",
        )
        empty_nb = self._write_bytes("empty.ipynb", b"")
        self.assertEqual(
            scanner.extract_notebook_view(empty_nb, action="list").status, "SKIP"
        )
        pdf_nb = self._write_bytes("spoof.ipynb", b"%PDF-1.7\n1 0 obj\n")
        self.assertEqual(
            scanner.extract_notebook_view(pdf_nb, action="list").status,
            "BLOCK_MEDIA",
        )
        arr_nb = self._write_text("arr.ipynb", "[1, 2, 3]")
        self.assertEqual(
            scanner.extract_notebook_view(arr_nb, action="list").status, "SKIP"
        )
        bad_cells_nb = self._write_text("bad_cells.ipynb", '{"cells": "invalid"}')
        self.assertEqual(
            scanner.extract_notebook_view(bad_cells_nb, action="list").status, "SKIP"
        )
        # Fallback to AbsolutePath on notebook_edit when NotebookPath/Path omitted and file missing -> scans args_text
        missing_abs_nb = os.path.join(self._tmp_dir, "missing_via_abs.ipynb")
        fallback_nb_res = scanner.extract_tool_scan_target(
            ToolScanRequest(
                tool_name="notebook_edit",
                tool_args={"AbsolutePath": missing_abs_nb, "Action": "list"},
            )
        )
        self.assertEqual(fallback_nb_res.action, "SCAN")
        self.assertEqual(fallback_nb_res.source, "tool_args:notebook_edit")

        # BOM-prefixed notebook with non-dict entries, None source/outputs, empty outputs, & varied data types
        edge_nb_obj = {
            "cells": [
                "not_a_dict_cell",
                {"cell_type": "code", "source": None, "outputs": None},
                {"cell_type": "code", "source": "x = 1", "outputs": []},
                {
                    "cell_type": "code",
                    "source": "x = 2",
                    "outputs": [
                        "bad_out",
                        {"data": "bad_data"},
                        {
                            "data": {
                                "image/png": ["   "],
                                "application/pdf": {},
                                "video/mp4": None,
                            }
                        },
                    ],
                },
                {
                    "cell_type": "code",
                    "source": "x = 3",
                    "outputs": [{"data": {"application/pdf": {"page": 1}}}],
                },
                {
                    "cell_type": "code",
                    "source": "x = 4",
                    "outputs": [{"data": {"video/mp4": 1}}],
                },
            ]
        }
        edge_nb = self._write_bytes(
            "edge.ipynb", _UTF8_BOM_BYTES + json.dumps(edge_nb_obj).encode("utf-8")
        )
        self.assertEqual(
            scanner.extract_notebook_view(edge_nb, action="replace").status, "SKIP"
        )
        self.assertEqual(
            scanner.extract_notebook_view(edge_nb, action="list").status, "SCAN"
        )
        self.assertEqual(
            scanner.extract_notebook_view(edge_nb, action="get", cell_index=0).status,
            "SKIP",
        )
        self.assertEqual(
            scanner.extract_notebook_view(
                edge_nb, action="get_with_outputs", cell_index=1
            ).status,
            "SCAN",
        )
        self.assertEqual(
            scanner.extract_notebook_view(
                edge_nb, action="get_with_outputs", cell_index=2
            ).status,
            "SCAN",
        )
        self.assertEqual(
            scanner.extract_notebook_view(
                edge_nb, action="get_with_outputs", cell_index=3
            ).status,
            "SCAN",
        )
        self.assertEqual(
            scanner.extract_notebook_view(
                edge_nb, action="get_with_outputs", cell_index=4
            ).status,
            "BLOCK_MEDIA",
        )
        self.assertEqual(
            scanner.extract_notebook_view(
                edge_nb, action="get_with_outputs", cell_index=5
            ).status,
            "BLOCK_MEDIA",
        )


if __name__ == "__main__":
    unittest.main()
