import subprocess
import hashlib
from pathlib import Path


def analyze_firmware(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Firmware not found: {path}")

    return {
        "path": str(p.absolute()),
        "filename": p.name,
        "size_bytes": p.stat().st_size,
        "hashes": _compute_hashes(path),
        "file_type": _run_file(path),
        "strings_sample": _run_strings(path, limit=300),
        "binwalk": _run_binwalk(path),
    }


def _compute_hashes(path: str) -> dict:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def _run_file(path: str) -> str:
    try:
        r = subprocess.run(["file", path], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip().split(": ", 1)[-1]
    except Exception:
        pass
    return "unknown"


def _run_strings(path: str, limit: int = 300) -> list:
    try:
        r = subprocess.run(
            ["strings", "-n", "8", path],
            capture_output=True, text=True, timeout=30
        )
        lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        return lines[:limit]
    except Exception:
        return []


def _run_binwalk(path: str) -> str | None:
    try:
        r = subprocess.run(["binwalk", path], capture_output=True, text=True, timeout=60)
        return r.stdout.strip() if r.returncode == 0 else None
    except FileNotFoundError:
        return None
    except Exception:
        return None
