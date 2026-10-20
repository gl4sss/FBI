"""Restore completed worker tasks from a session directory."""

import json
from pathlib import Path


def load_completed_tasks(session_dir: str, prior_tasks: list[dict] | None = None) -> list[dict]:
    tasks = {task["task_id"]: task for task in (prior_tasks or []) if task.get("task_id")}
    session_path = Path(session_dir)

    # Older sessions only have worker conversation logs.
    for log_file in sorted((session_path / "codex_sessions").glob("*.jsonl")):
        with log_file.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if entry.get("role") != "assistant":
                    continue
                result = entry.get("content")
                if not isinstance(result, dict) or not result.get("task_id"):
                    continue
                task_id = result["task_id"]
                previous = tasks.get(task_id, {})
                tasks[task_id] = {
                    **previous,
                    "task_id": task_id,
                    "session_id": result.get("session_id") or previous.get("session_id"),
                    "result": result,
                }

    # New sessions record every dispatch result, including failed tasks.
    result_log = session_path / "task_results.jsonl"
    if result_log.exists():
        with result_log.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                task = json.loads(line)
                if task.get("task_id") and isinstance(task.get("result"), dict):
                    tasks[task["task_id"]] = task

    return list(tasks.values())


def load_sent_task_ids(session_dir: str) -> set[str]:
    log_path = Path(session_dir) / "orchestrator_conversation.jsonl"
    if not log_path.exists():
        return set()
    entries = []
    with log_path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            entries.append(json.loads(line))
    sent = set()
    pending = None
    for entry in entries:
        if entry.get("role") == "user":
            pending = entry
        elif entry.get("role") == "assistant" and pending:
            content = pending.get("content") or {}
            for task in content.get("completed_tasks", []) + content.get("new_results", []):
                if task.get("task_id"):
                    sent.add(task["task_id"])
            pending = None
    return sent


def verify_resume_firmware(session_dir: str, firmware_info: dict):
    saved_path = Path(session_dir) / "firmware_info.json"
    if not saved_path.exists():
        raise FileNotFoundError(f"Session firmware metadata is missing: {saved_path}")
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    prior_hash = (saved.get("hashes") or {}).get("sha256")
    current_hash = (firmware_info.get("hashes") or {}).get("sha256")
    if not prior_hash or prior_hash != current_hash:
        raise ValueError("Resume firmware does not match the saved session SHA256")
