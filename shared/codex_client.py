"""Run a Codex CLI task and return its final message and session ID."""

import json
import subprocess
import tempfile
from pathlib import Path


def extract_session_id(events: str) -> str | None:
    for line in events.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        for key in ("thread_id", "session_id", "conversation_id", "sessionId"):
            value = event.get(key)
            if isinstance(value, str) and len(value) > 8:
                return value
    return None


def run_codex(
    prompt: str,
    model: str,
    reasoning_effort: str,
    session_id: str | None = None,
    *,
    sandbox: str = "read-only",
    bypass_approvals: bool = False,
    sandbox_permissions: list[str] | None = None,
    network_access: bool = False,
    workdir: str | None = None,
) -> tuple[str, str | None]:
    """Run one turn without putting the prompt in the process argument list."""
    if reasoning_effort not in {"low", "medium", "high", "xhigh", "max"}:
        raise ValueError(f"Unsupported reasoning effort: {reasoning_effort}")

    with tempfile.TemporaryDirectory(prefix="fbi_codex_") as temporary_dir:
        output_file = Path(temporary_dir) / "last_message.txt"
        command = ["codex", "exec"]
        if session_id:
            command.extend(["resume", session_id])
        command.extend([
            "--model", model,
            "--json",
            "--output-last-message", str(output_file),
            "--skip-git-repo-check",
            "--config", f"model_reasoning_effort={reasoning_effort}",
        ])
        if bypass_approvals:
            command.append("--dangerously-bypass-approvals-and-sandbox")
        else:
            if session_id:
                command.extend(["--config", f"sandbox_mode={sandbox}"])
            else:
                command.extend(["--sandbox", sandbox])
            if sandbox == "workspace-write":
                command.extend([
                    "--config",
                    f"sandbox_workspace_write.network_access={str(network_access).lower()}",
                ])
            if sandbox_permissions:
                command.extend([
                    "--config",
                    f"sandbox_permissions={json.dumps(sandbox_permissions)}",
                ])
        command.append("-")

        run_options = {"input": prompt, "capture_output": True, "text": True}
        if workdir is not None:
            run_options["cwd"] = workdir
        result = subprocess.run(command, **run_options)
        if result.returncode != 0:
            raise RuntimeError(f"Codex exited {result.returncode}: {result.stderr[:500]}")
        if not output_file.exists():
            raise RuntimeError("Codex did not write a final message")
        message = output_file.read_text(encoding="utf-8").strip()
        if not message:
            raise RuntimeError("Codex returned an empty final message")
        return message, extract_session_id(result.stdout) or session_id
