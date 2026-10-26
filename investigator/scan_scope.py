"""Inventory extracted files and build deterministic review tasks."""

import json
import os
from pathlib import Path


CODE_SUFFIXES = {
    ".sh", ".bash", ".cgi", ".php", ".py", ".pl", ".lua", ".js",
    ".html", ".htm", ".asp", ".aspx", ".jsp", ".rb", ".tcl",
    ".awk", ".ps1", ".sql",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".go", ".rs", ".java",
    ".class", ".jar", ".apk", ".dex", ".wasm",
}
EXECUTABLE_MAGIC = (b"\x7fELF", b"MZ", b"\x00asm")
CONFIG_SUFFIXES = {".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
                   ".properties", ".service", ".socket", ".pem", ".crt", ".key"}


def file_inventory(extracted_dir: str | Path) -> list[dict]:
    """Record every directory entry, including files that cannot be read safely."""
    root = Path(extracted_dir).resolve()
    entries = []
    def on_error(exc: OSError) -> None:
        entries.append({"path": exc.filename or str(root),
                        "relative_path": str(Path(exc.filename or root).relative_to(root)),
                        "type": "directory", "status": "unreadable", "reason": str(exc)})

    for directory, folders, names in os.walk(root, followlinks=False, onerror=on_error):
        for name in sorted(folders + names):
            path = Path(directory) / name
            relative = str(path.relative_to(root))
            if path.is_symlink():
                entries.append({"path": str(path), "relative_path": relative,
                                "type": "symlink", "status": "skipped",
                                "reason": "symlink target is not followed"})
                continue
            if path.is_dir():
                entries.append({"path": str(path), "relative_path": relative,
                                "type": "directory", "status": "listed"})
                continue
            if not path.is_file():
                entries.append({"path": str(path), "relative_path": relative,
                                "type": "special", "status": "skipped",
                                "reason": "not a regular file"})
                continue
            try:
                with path.open("rb") as stream:
                    header = stream.read(128)
                size = path.stat().st_size
            except OSError as exc:
                entries.append({"path": str(path), "relative_path": relative,
                                "type": "unknown", "status": "unreadable",
                                "reason": str(exc)})
                continue
            suffix = path.suffix.lower()
            if suffix in CODE_SUFFIXES or header.startswith(EXECUTABLE_MAGIC) or header.startswith(b"#!"):
                kind = "code"
            elif suffix in CONFIG_SUFFIXES or path.name in {"passwd", "shadow", "inittab", "fstab"}:
                kind = "configuration"
            else:
                kind = "data"
            entries.append({"path": str(path), "relative_path": relative,
                            "type": kind, "status": "pending", "size_bytes": size})
        folders[:] = [name for name in folders
                      if not (Path(directory) / name).is_symlink()]
    return sorted(entries, key=lambda item: item["relative_path"])


def code_targets(extracted_dir: str | Path) -> list[str]:
    return [entry["path"] for entry in file_inventory(extracted_dir)
            if entry["type"] == "code" and entry["status"] == "pending"]


def scan_tasks(extracted_dir: str | Path, files_per_task: int = 4,
               *, all_files: bool = False) -> tuple[list[dict], list[str]]:
    if files_per_task < 1:
        raise ValueError("files_per_task must be positive")
    inventory = file_inventory(extracted_dir)
    targets = [entry["path"] for entry in inventory
               if entry["status"] == "pending" and (all_files or entry["type"] == "code")]
    types = {entry["path"]: entry["type"] for entry in inventory}
    tasks = []
    for start in range(0, len(targets), files_per_task):
        files = targets[start:start + files_per_task]
        task_id = f"scan_{len(tasks) + 1:04d}"
        tasks.append({
            "task_id": task_id,
            "type": "file_analysis" if all_files else "code_analysis",
            "priority": "high",
            "scope_files": files,
            "scope_types": {path: types[path] for path in files},
            "prompt": (
                "Inspect every file in SCOPE FILES. Enumerate all distinct suspicious "
                "locations in suspected_findings, including exact file and function, "
                "line, or offset with observed evidence. Examine code, configuration, "
                "service exposure, credentials, update paths, and third-party component "
                "identity as appropriate to each file type. For external components, "
                "collect product, version, build, and configuration evidence before "
                "checking relevant vendor advisories and CVEs when network access is "
                "enabled. Otherwise record that the external check is pending. A matching "
                "name or CVE alone is not proof. "
                "Do not stop after one finding. Record each inspected path in "
                "reviewed_files; explain files you could not inspect."
            ),
        })
    return tasks, targets


def save_scan_scope(session_dir: str | Path, tasks: list[dict], targets: list[str],
                    inventory: list[dict] | None = None, **extras) -> None:
    path = Path(session_dir) / "scan_scope.json"
    path.write_text(json.dumps({"targets": targets, "tasks": tasks,
                                "inventory": inventory or [], **extras},
                               ensure_ascii=False, indent=2), encoding="utf-8")
