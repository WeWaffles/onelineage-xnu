#!/usr/bin/env python3
"""Verify and apply OneLineage's pinned XNU patch series, entirely offline.

The series declared in ``xnu/series.json`` is applied in order to the pinned
``apple-oss-distributions/xnu`` tag using ``git apply`` with text conversion
disabled. The tool downloads and hash-checks that source only when asked with
``--fetch``, and never writes into a tree whose provenance it cannot prove.

It never builds, links, packages, or runs a kernel, and it never authorizes
execution on the phone: a clean apply is evidence about patch text only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Iterable
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SERIES_PATH = ROOT / "xnu" / "series.json"
PATCH_DIR = ROOT / "xnu" / "patches"
MARKER_NAME = ".onelineage-xnu-source.json"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
PATCH_NAME = re.compile(r"^[0-9]{4}-[A-Za-z0-9][A-Za-z0-9._-]*\.patch$")
GIT_BASE = (
    "git",
    "-c", "core.autocrlf=false",
    "-c", "core.eol=lf",
    "-c", "apply.whitespace=nowarn",
)


class SeriesError(RuntimeError):
    """The vendored series or the pinned source failed a fail-closed check."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_series(path: Path = SERIES_PATH) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SeriesError(f"series manifest is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SeriesError(f"series manifest is not valid JSON: {path}: {exc}") from exc


def validate_series(series: dict, patch_dir: Path = PATCH_DIR) -> list[dict]:
    """Return the series' patches with their bytes, or raise SeriesError.

    Every patch must exist, hash to the manifest value, use LF line endings, and
    appear in ascending name order so the vendored directory cannot silently
    disagree with the declared sequence.
    """
    if series.get("schema") != 1:
        raise SeriesError(f"unsupported series schema: {series.get('schema')!r}")

    source = series.get("source") or {}
    if not str(source.get("tag", "")).startswith("xnu-"):
        raise SeriesError("source.tag must name an XNU release tag")
    if not HEX64.match(str(source.get("sha256", ""))):
        raise SeriesError("source.sha256 must be 64 lowercase hex characters")
    if not str(source.get("url", "")).startswith("https://"):
        raise SeriesError("source.url must be an https URL")

    build = series.get("build") or {}
    for key in ("dxb_repo", "dxb_sha", "macos_version", "kernel_config", "machine_config", "arch_config"):
        if not build.get(key):
            raise SeriesError(f"build pin is missing: {key}")

    entries = series.get("patches")
    if not isinstance(entries, list) or not entries:
        raise SeriesError("series declares no patches")

    names: list[str] = []
    previous = ""
    for entry in entries:
        name = str(entry.get("name", ""))
        if not PATCH_NAME.match(name):
            raise SeriesError(f"invalid patch name: {name!r}")
        if name in names:
            raise SeriesError(f"duplicate patch in series: {name}")
        if name <= previous:
            raise SeriesError(f"series is not in ascending order at {name}")
        names.append(name)
        previous = name

    seen = set(names)
    verified: list[dict] = []
    for entry in entries:
        name = str(entry["name"])
        path = patch_dir / name
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise SeriesError(f"vendored patch is missing: {path}") from exc
        digest = sha256_bytes(data)
        if digest != entry.get("sha256"):
            raise SeriesError(
                f"{name} does not match the manifest: expected {entry.get('sha256')}, found {digest}"
            )
        if b"\r\n" in data:
            raise SeriesError(f"{name} contains CRLF line endings; patches must be LF-only")
        verified.append({"name": name, "sha256": digest, "purpose": entry.get("purpose", ""), "data": data})

    vendored = sorted(path.name for path in patch_dir.glob("*.patch"))
    declared = sorted(seen)
    extra = [name for name in vendored if name not in seen]
    if extra:
        raise SeriesError("vendored patches are not declared in the series: " + ", ".join(extra))
    if len(declared) != len(vendored):
        raise SeriesError("series and vendored patch directory disagree on patch count")
    return verified


def source_marker(source_dir: Path) -> dict | None:
    try:
        return json.loads((source_dir / MARKER_NAME).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def source_is_pinned(series: dict, source_dir: Path) -> bool:
    marker = source_marker(source_dir)
    if marker is None:
        return False
    source = series["source"]
    return (
        marker.get("tag") == source["tag"]
        and marker.get("sha256") == source["sha256"]
        and (source_dir / "osfmk").is_dir()
        and (source_dir / "makedefs" / "MakeInc.def").is_file()
    )


def _extract(tarball: Path, destination: Path, project: str, tag: str) -> Path:
    # GitHub archive roots are "<project>-<tag>", e.g. xnu-xnu-8796.141.3.
    prefix = f"{project}-{tag}/"
    root = prefix.rstrip("/")
    with tarfile.open(tarball, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name.replace("\\", "/")
            if not (name == root or name.startswith(prefix)) or ".." in name.split("/") or name.startswith("/"):
                raise SeriesError(f"unexpected archive member outside {prefix}: {member.name}")
        try:
            archive.extractall(destination, filter="data")
        except TypeError:  # Python < 3.12 has no extraction filter
            archive.extractall(destination)
    extracted = destination / root
    if not extracted.is_dir():
        raise SeriesError(f"archive did not contain {prefix}")
    return extracted


def fetch_source(series: dict, work: Path) -> Path:
    """Download, hash-check and extract the pinned source into ``work/source``."""
    source = series["source"]
    work.mkdir(parents=True, exist_ok=True)
    tarball = work / f"{source['tag']}.tar.gz"
    if not tarball.is_file():
        print(f"fetching {source['url']}", file=sys.stderr)
        try:
            with urllib.request.urlopen(source["url"], timeout=120) as response:
                data = response.read()
        except OSError as exc:
            raise SeriesError(f"could not download the pinned source: {exc}") from exc
        tarball.write_bytes(data)
    digest = sha256_bytes(tarball.read_bytes())
    if digest != source["sha256"]:
        raise SeriesError(
            f"pinned source hash mismatch: expected {source['sha256']}, found {digest}"
        )

    staging = work / "source.extracting"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    extracted = _extract(tarball, staging, source["project"], source["tag"])
    target = work / "source"
    if target.exists():
        shutil.rmtree(target)
    extracted.rename(target)
    shutil.rmtree(staging)
    (target / MARKER_NAME).write_text(
        json.dumps(
            {"tag": source["tag"], "sha256": source["sha256"], "url": source["url"]},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return target


def apply_series(source_dir: Path, patches: Iterable[dict], require_marker: bool = True) -> list[dict]:
    """Apply each patch in order, stopping at the first failure."""
    if require_marker and source_marker(source_dir) is None:
        raise SeriesError(f"refusing to patch a tree without a provenance marker: {source_dir}")
    results: list[dict] = []
    for patch in patches:
        with tempfile.NamedTemporaryFile("wb", suffix=".patch", delete=False) as handle:
            handle.write(patch["data"])
            patch_path = Path(handle.name)
        try:
            check = subprocess.run(
                [*GIT_BASE, "apply", "--check", str(patch_path)],
                cwd=source_dir, text=True, capture_output=True,
            )
            if check.returncode != 0:
                raise SeriesError(
                    f"{patch['name']} does not apply: {check.stderr.strip().splitlines()[:1] or ['unknown error']}"
                )
            applied = subprocess.run(
                [*GIT_BASE, "apply", str(patch_path)],
                cwd=source_dir, text=True, capture_output=True,
            )
            if applied.returncode != 0:
                raise SeriesError(f"{patch['name']} failed to apply: {applied.stderr.strip()}")
        finally:
            patch_path.unlink(missing_ok=True)
        results.append({"name": patch["name"], "sha256": patch["sha256"], "status": "applied"})
    return results


def build_report(series: dict, result: str, patches: Iterable[dict]) -> dict:
    return {
        "schema": 1,
        "result": result,
        "milestone": series.get("milestone"),
        "source": {
            "tag": series.get("source", {}).get("tag"),
            "sha256": series.get("source", {}).get("sha256"),
        },
        "patches": [
            {"name": patch["name"], "sha256": patch["sha256"], "status": patch.get("status", "verified")}
            for patch in patches
        ],
        "compiled": False,
        "linked": False,
        "qemu_console_reached": False,
        "phone_execution_authorized": False,
        "notes": [
            "A clean apply proves the patch text composes against the pinned tag.",
            "It does not prove the kernel compiles, links, boots, or belongs on the phone.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work", type=Path, default=ROOT / "build" / "xnu-src",
                        help="scratch directory for the pinned source (default: build/xnu-src)")
    parser.add_argument("--fetch", action="store_true",
                        help="download the pinned source if needed and extract a fresh tree")
    parser.add_argument("--verify-only", action="store_true",
                        help="check the manifest and vendored patches without touching a source tree")
    parser.add_argument("--json", type=Path, help="write the machine-readable report here")
    args = parser.parse_args(argv)

    try:
        series = load_series()
        patches = validate_series(series)
    except SeriesError as exc:
        print(f"series invalid: {exc}", file=sys.stderr)
        if args.json:
            args.json.write_text(json.dumps({"schema": 1, "result": "series-invalid",
                                             "error": str(exc)}, indent=2) + "\n", encoding="utf-8")
        return 1

    print(f"series: {len(patches)} patches for {series['source']['tag']} ({series['milestone']})")
    print(f"source: sha256 {series['source']['sha256']}")
    if args.verify_only:
        report = build_report(series, "series-verified", patches)
        print("verified: manifest, hashes and line endings only; no source tree touched")
        if args.json:
            args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 0

    source_dir = args.work / "source"
    try:
        if args.fetch:
            source_dir = fetch_source(series, args.work)
        elif not source_is_pinned(series, source_dir):
            raise SeriesError(
                f"no pinned source at {source_dir}; rerun with --fetch to obtain "
                f"{series['source']['tag']} (sha256 {series['source']['sha256']})"
            )
        applied = apply_series(source_dir, patches)
    except SeriesError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        print("hint: the scratch tree may already be patched; rerun with --fetch for a fresh one",
              file=sys.stderr)
        if args.json:
            args.json.write_text(json.dumps({"schema": 1, "result": "failed",
                                             "error": str(exc)}, indent=2) + "\n", encoding="utf-8")
        return 2

    for record in applied:
        print(f"  applied {record['name']}")
    report = build_report(series, "applied", applied)
    print(f"source tree: {source_dir}")
    print("note: applying a patch series does not build it, boot it, or authorize phone execution")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
