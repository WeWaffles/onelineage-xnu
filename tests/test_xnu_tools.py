#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "xnu"
sys.path.insert(0, str(TOOLS))
import adt  # noqa: E402
import mk_m3q_adt  # noqa: E402
import inspect_macho  # noqa: E402
import build_payload  # noqa: E402
import run_qemu  # noqa: E402
import verify_xnu_series  # noqa: E402


def child(node: adt.Node, name: str) -> adt.Node:
    return next(item for item in node.children if item.name == name)


class XnuToolsTest(unittest.TestCase):
    def setUp(self):
        self.manifest_path = ROOT / "kernel" / "device-hardware" / "generic-arm64.json"
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def test_deterministic_qemu_tree_round_trip(self):
        first = adt.serialize(mk_m3q_adt.build_qemu(self.manifest))
        second = adt.serialize(mk_m3q_adt.build_qemu(self.manifest))
        self.assertEqual(first, second)
        root, end = adt.parse(first)
        self.assertEqual(end, len(first))
        self.assertEqual(root.name, "device-tree")
        self.assertEqual(len(child(root, "cpus").children), 1)
        gic = child(child(root, "arm-io"), "gic")
        regs = struct.unpack("<4Q", gic.prop("reg"))
        # reg values are offsets from soc_base_phys (ranges[1] == QEMU_GICD),
        # so GICD is offset 0 and GICR is relative to it.
        self.assertEqual(regs[0], 0)
        self.assertEqual(regs[2], mk_m3q_adt.QEMU_GICR - mk_m3q_adt.QEMU_GICD)
        self.assertNotEqual(regs[0], int(self.manifest["gic"]["distributor_base"], 0))

    def test_root_compatible_contains_xiaomi_sweet(self):
        """Patch 0016 SweetPlatformExpert matches IONameMatch='xiaomi,sweet'."""
        blob = adt.serialize(mk_m3q_adt.build_qemu(self.manifest))
        root, _ = adt.parse(blob)
        compat = root.prop("compatible")
        # compatible is a sequence of NUL-terminated ASCII strings
        strings = [s.decode("ascii") for s in compat.split(b"\0") if s]
        self.assertIn("xiaomi,sweet", strings)

    def test_qemu_memory_covers_framebuffer(self):
        """2 GB QEMU RAM must cover the sweet early-console FB at 0x9c000000."""
        fb_end = mk_m3q_adt.QEMU_FB_BASE + mk_m3q_adt.QEMU_FB_W * mk_m3q_adt.QEMU_FB_H * 4
        ram_end = mk_m3q_adt.QEMU_PHYS_BASE + mk_m3q_adt.QEMU_MEMORY_SIZE
        self.assertGreater(ram_end, fb_end, "RAM must extend past the end of the framebuffer")

    def test_sweet_fbcon_node_present_and_valid(self):
        """Patch 0003 reads a 'sweet-fbcon' node for the late serial console."""
        blob = adt.serialize(mk_m3q_adt.build_qemu(self.manifest))
        root, _ = adt.parse(blob)
        fbcon = next((n for n in root.children if n.name == "sweet-fbcon"), None)
        self.assertIsNotNone(fbcon, "sweet-fbcon node must be present")
        # reg = [phys_base (u64), size (u64)]
        reg = struct.unpack("<2Q", fbcon.prop("reg"))
        self.assertEqual(reg[0], mk_m3q_adt.QEMU_FB_BASE)
        expected_size = mk_m3q_adt.QEMU_FB_W * mk_m3q_adt.QEMU_FB_H * 4
        self.assertEqual(reg[1], expected_size)
        width = struct.unpack("<I", fbcon.prop("width"))[0]
        height = struct.unpack("<I", fbcon.prop("height"))[0]
        stride = struct.unpack("<I", fbcon.prop("stride"))[0]
        self.assertEqual(width, mk_m3q_adt.QEMU_FB_W)
        self.assertEqual(height, mk_m3q_adt.QEMU_FB_H)
        self.assertEqual(stride, mk_m3q_adt.QEMU_FB_STRIDE)

    def test_run_qemu_build_image_rejects_wrong_magic(self):
        bad = b"BADMAGIC" + b"\0" * 100
        with self.assertRaises(ValueError):
            run_qemu.build_image(bad)

    def test_run_qemu_stub_layout(self):
        ba_pa, entry_pa = 0x44000000, 0x40100000
        stub = run_qemu.make_stub(ba_pa, entry_pa)
        self.assertEqual(len(stub), 32)
        # last two u64 must be the addresses embedded for ldr-literal
        embedded = struct.unpack_from("<2Q", stub, 16)
        self.assertEqual(embedded, (ba_pa, entry_pa))

    def test_phone_mode_fails_closed(self):
        output = ROOT / "build" / f"test-phone-{uuid.uuid4().hex}.adt"
        result = subprocess.run(
            [sys.executable, str(TOOLS / "mk_m3q_adt.py"), str(self.manifest_path), str(output), "--mode", "phone"],
            text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing phone ADT", result.stderr)
        self.assertFalse(output.exists())

    def test_parser_rejects_truncation(self):
        with self.assertRaises(ValueError):
            adt.parse(b"\0" * 7)

    def test_arm64_macho_structure(self):
        command = struct.pack(
            "<II16s4Q4I", inspect_macho.LC_SEGMENT_64, 72, b"__TEXT\0",
            0x100000000, 0x1000, 0, 104, 7, 5, 0, 0,
        )
        header = struct.pack(
            "<8I", inspect_macho.MH_MAGIC_64, inspect_macho.CPU_TYPE_ARM64,
            0, inspect_macho.MH_EXECUTE, 1, len(command), 0, 0,
        )
        report = inspect_macho.inspect(header + command)
        self.assertEqual(report["architecture"], "arm64")
        self.assertFalse(report["safe_for_phone_execution"])

    def test_macho_wrong_architecture_is_rejected(self):
        header = struct.pack("<8I", inspect_macho.MH_MAGIC_64, 0x01000007, 0, 2, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "ARM64"):
            inspect_macho.inspect(header)

    def test_qemu_payload_build(self):
        entry = 0x100000100
        command_size = 72 + 288
        file_size = 32 + command_size
        segment = struct.pack(
            "<II16s4Q4I", build_payload.LC_SEGMENT_64, 72, b"__TEXT\0",
            0x100000000, 0x4000, 0, file_size, 7, 5, 0, 0,
        )
        thread_state = bytearray(272)
        struct.pack_into("<Q", thread_state, 256, entry)
        thread = struct.pack("<IIII", build_payload.LC_UNIXTHREAD, 288, 6, 68) + thread_state
        header = struct.pack(
            "<8I", inspect_macho.MH_MAGIC_64, inspect_macho.CPU_TYPE_ARM64,
            0, inspect_macho.MH_EXECUTE, 2, command_size, 0, 0,
        )
        tree = adt.serialize(mk_m3q_adt.build_qemu(self.manifest))
        payload, report = build_payload.build(header + segment + thread, tree, "debug=0xc cpus=1")
        magic, version, segments = struct.unpack_from("<8sII", payload)
        self.assertEqual(magic, build_payload.MAGIC)
        self.assertEqual(version, 1)
        self.assertEqual(segments, 1)
        self.assertEqual(report["entry_virtual_address"], hex(entry))
        self.assertFalse(report["phone_execution_authorized"])



def series_manifest(patches: list[dict], **overrides) -> dict:
    manifest = {
        "schema": 1,
        "milestone": "test",
        "source": {
            "project": "xnu",
            "tag": "xnu-test-1.0",
            "url": "https://example.invalid/xnu.tar.gz",
            "sha256": "0" * 64,
        },
        "build": {
            "dxb_repo": "https://example.invalid/darwin-xnu-build",
            "dxb_sha": "0" * 40,
            "macos_version": "13.5",
            "kernel_config": "DEVELOPMENT",
            "machine_config": "SWEET",
            "arch_config": "ARM64",
        },
        "patches": patches,
    }
    manifest.update(overrides)
    return manifest


def entry(name: str, data: bytes) -> dict:
    return {"name": name, "sha256": verify_xnu_series.sha256_bytes(data), "purpose": "test"}


class XnuSeriesTest(unittest.TestCase):
    def setUp(self):
        self.series = verify_xnu_series.load_series()
        self.patches = verify_xnu_series.validate_series(self.series)

    def test_vendored_series_matches_manifest(self):
        self.assertEqual(self.series["source"]["tag"], "xnu-8796.141.3")
        manifest = json.loads(self.series.read_text(encoding="utf-8"))
        self.assertEqual(len(self.patches), len(manifest["patches"]))
        self.assertEqual([item["name"][:4] for item in self.patches], [f"{index:04d}" for index in range(1, 19)])
        for item in self.patches:
            self.assertNotIn(b"\r\n", item["data"])
        self.assertFalse(self.series["constraints"]["phone_execution_authorized"])
        self.assertFalse(self.series["verified"]["compiled"])
        self.assertFalse(self.series["verified"]["qemu_console_reached"])

    def test_series_rejects_crlf_patch(self):
        data = b"--- a/value.txt\r\n+++ b/value.txt\r\n@@ -1 +1 @@\r\n-base\r\n+one\r\n"
        with tempfile.TemporaryDirectory() as directory:
            patch_dir = Path(directory)
            (patch_dir / "0001-test.patch").write_bytes(data)
            with self.assertRaisesRegex(verify_xnu_series.SeriesError, "CRLF"):
                verify_xnu_series.validate_series(
                    series_manifest([entry("0001-test.patch", data)]), patch_dir
                )

    def test_series_rejects_hash_mismatch(self):
        data = b"--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-base\n+one\n"
        with tempfile.TemporaryDirectory() as directory:
            patch_dir = Path(directory)
            (patch_dir / "0001-test.patch").write_bytes(data)
            with self.assertRaisesRegex(verify_xnu_series.SeriesError, "does not match the manifest"):
                verify_xnu_series.validate_series(
                    series_manifest([{"name": "0001-test.patch", "sha256": "1" * 64}]), patch_dir
                )

    def test_series_rejects_undeclared_and_unsorted_patches(self):
        data = b"--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-base\n+one\n"
        with tempfile.TemporaryDirectory() as directory:
            patch_dir = Path(directory)
            (patch_dir / "0001-test.patch").write_bytes(data)
            (patch_dir / "0002-extra.patch").write_bytes(data)
            with self.assertRaisesRegex(verify_xnu_series.SeriesError, "not declared"):
                verify_xnu_series.validate_series(
                    series_manifest([entry("0001-test.patch", data)]), patch_dir
                )
            (patch_dir / "0002-extra.patch").unlink()
            with self.assertRaisesRegex(verify_xnu_series.SeriesError, "duplicate patch"):
                verify_xnu_series.validate_series(
                    series_manifest([entry("0001-test.patch", data), entry("0001-test.patch", data)]),
                    patch_dir,
                )
            with self.assertRaisesRegex(verify_xnu_series.SeriesError, "ascending order"):
                verify_xnu_series.validate_series(
                    series_manifest([entry("0002-test.patch", data), entry("0001-test.patch", data)]),
                    patch_dir,
                )

    def test_apply_refuses_tree_without_provenance_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(verify_xnu_series.SeriesError, "provenance marker"):
                verify_xnu_series.apply_series(Path(directory), [])

    def test_apply_series_in_declared_order(self):
        if not shutil.which("git"):
            self.skipTest("git is required to apply patches")
        first = b"--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-base\n+one\n"
        second = b"--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-one\n+two\n"
        patches = [
            {"name": "0001-first.patch", "sha256": "0" * 64, "data": first},
            {"name": "0002-second.patch", "sha256": "0" * 64, "data": second},
        ]
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            (tree / "value.txt").write_bytes(b"base\n")
            applied = verify_xnu_series.apply_series(tree, patches, require_marker=False)
            self.assertEqual([item["status"] for item in applied], ["applied", "applied"])
            self.assertEqual((tree / "value.txt").read_text(encoding="utf-8"), "two\n")
            with self.assertRaises(verify_xnu_series.SeriesError):
                verify_xnu_series.apply_series(tree, patches, require_marker=False)


if __name__ == "__main__":
    unittest.main()
