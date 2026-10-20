from dataclasses import dataclass, field


@dataclass
class SessionInfo:
    session_id: str
    analysis_type: str = ""
    task_ids: list = field(default_factory=list)


class SessionManager:
    """Codex 세션 ID를 추적하여 관련 태스크 간 세션 재사용을 지원."""

    def __init__(self):
        self._sessions: dict[str, SessionInfo] = {}   # session_id → info
        self._task_to_session: dict[str, str] = {}    # task_id → session_id

    def get_session_id(self, task_id: str, reuse_session_for: str | None) -> str | None:
        if reuse_session_for and reuse_session_for in self._task_to_session:
            return self._task_to_session[reuse_session_for]
        return None

    def register_session(self, task_id: str, session_id: str, analysis_type: str = ""):
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionInfo(
                session_id=session_id,
                analysis_type=analysis_type,
            )
        self._sessions[session_id].task_ids.append(task_id)
        self._task_to_session[task_id] = session_id

    def restore(self, completed_tasks: list[dict]):
        for task in completed_tasks:
            session_id = task.get("session_id")
            if session_id and not session_id.startswith("unknown_"):
                self.register_session(task["task_id"], session_id,
                                      task.get("type") or "")

    def summary(self) -> dict:
        return {
            sid: {"type": info.analysis_type, "tasks": info.task_ids}
            for sid, info in self._sessions.items()
        }
