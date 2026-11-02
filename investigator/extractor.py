"""Extract a firmware image before scheduling analysis tasks."""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from shared.external_tools import command_for, target_for_file


class ExtractionError(RuntimeError):
    """Raised when extraction cannot supply files for analysis."""


NESTED_EXTRACTION_VERSION = 2
MAX_NESTED_DEPTH = 3
MAX_NESTED_IMAGES_PER_RUN = 24
MAX_NESTED_IMAGE_BYTES = 512 * 1024 * 1024


def _image_candidates(directory: Path, *, squashfs_only: bool = False):
    for current, folders, names in os.walk(directory, followlinks=False):
        folders[:] = sorted(name for name in folders
                            if not (Path(current) / name).is_symlink()
                            and not name.endswith((".root", ".nested"))
                            and ".root_retry_" not in name
                            and ".nested_retry_" not in name)
        for name in sorted(names):
            path = Path(current) / name
            target = target_for_file(path)
            if target == "squashfs" or (target == "nested_image" and not squashfs_only):
                yield path, target


def _expand_nested_images(root: Path, deadline: float, *, max_depth: int = MAX_NESTED_DEPTH,
                          max_images: int = MAX_NESTED_IMAGES_PER_RUN,
                          squashfs_only: bool = False) -> list[dict]:
    """Expand recognized image files with an explicit depth and per-run limit."""
    records = []
    queue = [(root, 1)]
    extracted_this_run = 0
    while queue:
        directory, depth = queue.pop(0)
        if depth > max_depth:
            continue
        for image, target in _image_candidates(directory, squashfs_only=squashfs_only):
            relative = str(image.relative_to(root))
            suffix = "root" if target == "squashfs" else "nested"
            destination = image.with_name(image.name + f".{suffix}")
            variants = [destination, *sorted(image.parent.glob(
                image.name + f".{suffix}_retry_*"))]
            reusable = next((path for path in variants
                             if path.is_dir() and _inventory(path)[0]), None)
            if reusable:
                records.append({"source": relative, "type": target, "depth": depth,
                                "status": "reused", "file_count": _inventory(reusable)[0]})
                if depth < max_depth:
                    queue.append((reusable, depth + 1))
                continue
            if destination.exists():
                retry = 1
                while destination.exists():
                    destination = image.with_name(image.name + f".{suffix}_retry_{retry}")
                    retry += 1
            record = {"source": relative, "type": target, "depth": depth}
            if extracted_this_run >= max_images:
                records.append({**record, "status": "pending",
                                "reason": "nested extraction per-run limit reached"})
                continue
            if time.monotonic() >= deadline:
                records.append({**record, "status": "pending",
                                "reason": "extraction time budget reached"})
                continue
            if image.stat().st_size > MAX_NESTED_IMAGE_BYTES:
                records.append({**record, "status": "failed",
                                "reason": "nested image exceeds 512 MiB extraction limit"})
                continue
            alias = "squashfs_extract" if target == "squashfs" else "binwalk_extract"
            command = command_for(alias, input_file=image, output_dir=destination)
            if command is None:
                records.append({**record, "status": "failed",
                                "reason": f"{alias} is not installed"})
                continue
            extracted_this_run += 1
            destination.mkdir()
            try:
                result = subprocess.run(command, capture_output=True, text=True,
                                        timeout=max(1, deadline - time.monotonic()))
                count = _inventory(destination)[0]
                if not count:
                    shutil.rmtree(destination)
                status = ("partial" if result.returncode and count else
                          "complete" if count else
                          "failed" if result.returncode else "skipped")
                records.append({**record, "status": status, "file_count": count,
                                "reason": ((result.stderr or "")[-500:] if result.returncode else
                                           "no nested payload recognized" if not count else "")})
                if count and depth < max_depth:
                    queue.append((destination, depth + 1))
            except subprocess.TimeoutExpired:
                shutil.rmtree(destination)
                records.append({**record, "status": "pending",
                                "reason": f"{alias} exceeded extraction time budget"})
    return records


def _expand_squashfs(root: Path, deadline: float, max_images: int = 12) -> list[dict]:
    """Compatibility helper for SquashFS-only expansion."""
    return _expand_nested_images(root, deadline, max_images=max_images, squashfs_only=True)


def _inventory(root: Path) -> tuple[int, list[str], int]:
    files = []
    count = 0
    symlinks = 0
    for directory, folders, names in os.walk(root, followlinks=False):
        for name in folders + names:
            path = Path(directory) / name
            if path.is_symlink():
                symlinks += 1
                continue
            if path.is_file():
                count += 1
                if len(files) < 100:
                    files.append(str(path.relative_to(root)))
    return count, files, symlinks


def extract_firmware(firmware_path: str, session_dir: str | Path,
                     firmware_sha256: str, timeout: int = 300) -> dict:
    """Run Binwalk extraction and return a verified session-local manifest."""
    session = Path(session_dir).resolve()
    manifest_path = session / "extraction.json"
    deadline = time.monotonic() + timeout

    if manifest_path.exists():
        prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        prior_dir = Path(prior.get("output_dir", ""))
        if (prior.get("status") == "complete" and
                prior.get("firmware_sha256") == firmware_sha256 and
                prior_dir.is_dir() and prior_dir.resolve().is_relative_to(session)):
            count, sample, symlinks = _inventory(prior_dir)
            if count:
                needs_retry = (prior.get("nested_extraction_version") != NESTED_EXTRACTION_VERSION
                               or any(item.get("status") in {"failed", "pending"}
                                      for item in prior.get("nested_extraction") or []))
                if needs_retry:
                    nested = _expand_nested_images(prior_dir, deadline)
                    count, sample, symlinks = _inventory(prior_dir)
                    prior.update({"nested_extraction_version": NESTED_EXTRACTION_VERSION,
                                  "nested_extraction": nested, "file_count": count,
                                  "files_sample": sample, "symlink_count": symlinks,
                                  "scope_expanded": (prior.get("scope_expanded", False)
                                                     or count > prior.get("file_count", 0))})
                    manifest_path.write_text(json.dumps(prior, ensure_ascii=False, indent=2),
                                             encoding="utf-8")
                return {**prior, "file_count": count, "files_sample": sample,
                        "symlink_count": symlinks, "reused": True}

    output_dir = session / "extracted"
    retry = 1
    while output_dir.exists():
        output_dir = session / f"extracted_retry_{retry}"
        retry += 1
    output_dir.mkdir(parents=True)

    command = command_for("binwalk_extract", input_file=Path(firmware_path).resolve(),
                          output_dir=output_dir)
    if command is None:
        exit_code, stdout, stderr = None, "", ""
        error = "binwalk is not installed; install it before running Investigator"
    else:
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=timeout)
            exit_code = result.returncode
            stdout = result.stdout[-4000:]
            stderr = result.stderr[-4000:]
            error = None
        except subprocess.TimeoutExpired:
            exit_code, stdout, stderr = None, "", ""
            error = f"binwalk extraction exceeded {timeout} seconds"

    nested = _expand_nested_images(output_dir, deadline)
    count, sample, symlinks = _inventory(output_dir)
    if not error and exit_code != 0:
        error = f"binwalk exited with code {exit_code}: {stderr or stdout or 'no details'}"
    if not error and not count:
        error = "binwalk did not produce any regular extracted files"

    manifest = {
        "status": "failed" if error else "complete",
        "firmware_sha256": firmware_sha256,
        "output_dir": str(output_dir),
        "file_count": count,
        "files_sample": sample,
        "symlink_count": symlinks,
        "binwalk_exit_code": exit_code,
        "binwalk_stdout": stdout,
        "binwalk_stderr": stderr,
        "nested_extraction_version": NESTED_EXTRACTION_VERSION,
        "nested_extraction": nested,
        "error": error,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    return manifest
