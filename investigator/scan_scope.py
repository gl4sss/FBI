"""Build deterministic review tasks for extracted code-bearing files."""

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


def code_targets(extracted_dir: str | Path) -> list[str]:
    root = Path(extracted_dir).resolve()
    targets = []
    for directory, folders, names in os.walk(root, followlinks=False):
        folders[:] = [name for name in folders
                      if not (Path(directory) / name).is_symlink()]
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            try:
                with path.open("rb") as stream:
                    header = stream.read(128)
                is_code = (path.suffix.lower() in CODE_SUFFIXES or
                           header.startswith(EXECUTABLE_MAGIC) or
                           header.startswith(b"#!"))
            except OSError:
                continue
            if is_code:
                targets.append(str(path))
    return sorted(targets)


def scan_tasks(extracted_dir: str | Path, files_per_task: int = 4) -> tuple[list[dict], list[str]]:
    if files_per_task < 1:
        raise ValueError("files_per_task must be positive")
    targets = code_targets(extracted_dir)
    tasks = []
    for start in range(0, len(targets), files_per_task):
        files = targets[start:start + files_per_task]
        task_id = f"scan_{len(tasks) + 1:04d}"
        tasks.append({
            "task_id": task_id,
            "type": "code_analysis",
            "priority": "high",
            "scope_files": files,
            "prompt": (
                "Inspect every file in SCOPE FILES. Enumerate all distinct suspicious "
                "code locations in suspected_findings, including their exact file and "
                "function, line, or offset with observed evidence. Consider input handling, "
                "authentication, command execution, memory safety, and secret handling "
                "where applicable. Do not stop after one finding. Record each inspected "
                "path in reviewed_files; explain files you could not inspect."
            ),
        })
    return tasks, targets


def save_scan_scope(session_dir: str | Path, tasks: list[dict], targets: list[str]) -> None:
    path = Path(session_dir) / "scan_scope.json"
    path.write_text(json.dumps({"targets": targets, "tasks": tasks},
                               ensure_ascii=False, indent=2), encoding="utf-8")
