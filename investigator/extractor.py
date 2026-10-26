"""Extract a firmware image before scheduling analysis tasks."""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path


class ExtractionError(RuntimeError):
    """Raised when extraction cannot supply files for analysis."""


NESTED_EXTRACTION_VERSION = 1
SQUASHFS_MAGIC = (b"hsqs", b"sqsh", b"qshs", b"shsq")


def _expand_squashfs(root: Path, deadline: float, max_images: int = 12) -> list[dict]:
    """Unpack SquashFS containers Binwalk left as opaque image files."""
    records = []
    processed = set()
    while len(processed) < max_images:
        images = []
        for directory, folders, names in os.walk(root, followlinks=False):
            folders[:] = [name for name in folders
                          if not (Path(directory) / name).is_symlink()]
            for name in names:
                path = Path(directory) / name
                if path in processed or path.is_symlink():
                    continue
                try:
                    with path.open("rb") as stream:
                        if stream.read(4) in SQUASHFS_MAGIC:
                            images.append(path)
                except OSError:
                    continue
        if not images:
            break
        for image in images[:max_images - len(processed)]:
            processed.add(image)
            relative = str(image.relative_to(root))
            destination = image.with_name(image.name + ".root")
            if destination.is_dir() and _inventory(destination)[0]:
                records.append({"source": relative, "status": "reused",
                                "file_count": _inventory(destination)[0]})
                continue
            if destination.exists():
                retry = 1
                while destination.exists():
                    destination = image.with_name(image.name + f".root_retry_{retry}")
                    retry += 1
            if time.monotonic() >= deadline:
                records.append({"source": relative, "status": "failed",
                                "reason": "extraction time budget reached"})
                continue
            if not shutil.which("unsquashfs"):
                records.append({"source": relative, "status": "failed",
                                "reason": "unsquashfs is not installed"})
                continue
            if image.stat().st_size > 512 * 1024 * 1024:
                records.append({"source": relative, "status": "failed",
                                "reason": "SquashFS image exceeds 512 MiB extraction limit"})
                continue
            destination.mkdir()
            command = ["unsquashfs", "-quiet", "-no-progress", "-no-xattrs",
                       "-ignore-errors", "-dest", str(destination), str(image)]
            try:
                result = subprocess.run(command, capture_output=True, text=True,
                                        timeout=max(1, deadline - time.monotonic()))
                count = _inventory(destination)[0]
                if not count:
                    shutil.rmtree(destination)
                records.append({"source": relative,
                                "status": ("partial" if result.returncode and count else
                                           "complete" if count else "failed"),
                                "file_count": count,
                                "reason": (result.stderr or "")[-500:] if result.returncode else ""})
            except subprocess.TimeoutExpired:
                shutil.rmtree(destination)
                records.append({"source": relative, "status": "failed",
                                "reason": "unsquashfs exceeded extraction time budget"})
    return records


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
                               or any(item.get("status") == "failed"
                                      for item in prior.get("nested_extraction") or []))
                if needs_retry:
                    nested = _expand_squashfs(prior_dir, deadline)
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

    command = ["binwalk", "--extract", "--matryoshka", "--directory", str(output_dir),
               str(Path(firmware_path).resolve())]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout)
        exit_code = result.returncode
        stdout = result.stdout[-4000:]
        stderr = result.stderr[-4000:]
        error = None
    except FileNotFoundError:
        exit_code, stdout, stderr = None, "", ""
        error = "binwalk is not installed; install it before running Investigator"
    except subprocess.TimeoutExpired:
        exit_code, stdout, stderr = None, "", ""
        error = f"binwalk extraction exceeded {timeout} seconds"

    nested = _expand_squashfs(output_dir, deadline)
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
