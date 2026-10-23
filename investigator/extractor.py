"""Extract a firmware image before scheduling analysis tasks."""

import json
import os
import subprocess
from pathlib import Path


class ExtractionError(RuntimeError):
    """Raised when extraction cannot supply files for analysis."""


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

    if manifest_path.exists():
        prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        prior_dir = Path(prior.get("output_dir", ""))
        if (prior.get("status") == "complete" and
                prior.get("firmware_sha256") == firmware_sha256 and
                prior_dir.is_dir() and prior_dir.resolve().is_relative_to(session)):
            count, sample, symlinks = _inventory(prior_dir)
            if count:
                return {**prior, "file_count": count, "files_sample": sample,
                        "symlink_count": symlinks, "reused": True}

    output_dir = session / "extracted"
    retry = 1
    while output_dir.exists():
        output_dir = session / f"extracted_retry_{retry}"
        retry += 1
    output_dir.mkdir(parents=True)

    command = ["binwalk", "--extract", "--directory", str(output_dir),
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
        "error": error,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    return manifest
