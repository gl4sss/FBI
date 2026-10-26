import json
from datetime import datetime
from pathlib import Path


class ConversationLogger:
    def __init__(self, sessions_dir: str, firmware_name: str,
                 resume_from: str | None = None):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.session_path = (Path(resume_from) if resume_from else
                             Path(sessions_dir) / firmware_name / timestamp)
        self.session_path.mkdir(parents=True, exist_ok=True)

        self.orchestrator_log = self.session_path / "orchestrator_conversation.jsonl"
        self.codex_dir = self.session_path / "codex_sessions"
        self.codex_dir.mkdir(exist_ok=True)
        self.roadmap_file = self.session_path / "roadmap.json"
        self.firmware_info_file = self.session_path / "firmware_info.json"
        self.task_results_file = self.session_path / "task_results.jsonl"

        print(f"[Logger] Session: {self.session_path}")

    def log_orchestrator(self, role: str, content: dict, iteration: int,
                         session_id: str | None = None):
        entry: dict = {
            "timestamp": datetime.now().isoformat(),
            "iteration": iteration,
            "role": role,
            "content": content,
        }
        if session_id:
            entry["orchestrator_session_id"] = session_id
        self._append(self.orchestrator_log, entry)

    def log_codex(self, session_id: str, task_id: str, role: str, content: dict):
        log_file = self.codex_dir / f"{session_id}.jsonl"
        self._append(log_file, {
            "timestamp": datetime.now().isoformat(),
            "task_id": task_id,
            "role": role,
            "content": content,
        })

    def log_task_result(self, task: dict, result: dict):
        self._append(self.task_results_file, {
            "timestamp": datetime.now().isoformat(),
            "task_id": task["task_id"],
            "type": task.get("type"),
            "specialist_id": task.get("specialist_id"),
            "prompt_version": task.get("prompt_version"),
            "scope_files": task.get("scope_files") or [],
            "session_id": result.get("session_id"),
            "result": result,
        })

    def save_roadmap(self, roadmap: dict):
        with open(self.roadmap_file, "w", encoding="utf-8") as f:
            json.dump(roadmap, f, indent=2, ensure_ascii=False)

    def save_firmware_info(self, info: dict):
        with open(self.firmware_info_file, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2, ensure_ascii=False)

    def get_session_path(self) -> Path:
        return self.session_path

    @staticmethod
    def _append(path: Path, entry: dict):
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
