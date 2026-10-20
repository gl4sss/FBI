"""
Lab Environment Manager
- 태스크 결과에서 환경 상태를 누적 업데이트
- lab_env.json (재사용 가능한 환경 명세) 생성
- setup.sh (재현 스크립트) 생성
"""
import json
from datetime import datetime
from pathlib import Path


class LabEnvManager:
    def __init__(self, session_path: Path, firmware_path: str):
        self.session_path = session_path
        self.firmware_path = firmware_path
        self._env: dict = {
            "created_at": datetime.now().isoformat(),
            "firmware_path": firmware_path,
            "arch": None,
            "endianness": None,
            "os_type": None,
            "filesystem_type": None,
            "compression": None,
            "rootfs_path": None,
            "kernel_path": None,
            "dtb_path": None,
            "qemu_system_cmd": None,
            "qemu_user_cmd": None,
            "qemu_pid": None,
            "ports": {
                "telnet": None,
                "monitor": None,
                "gdb": None,
                "http": None,
                "https": None,
                "ssh": None,
            },
            "chroot_cmd": None,
            "gdb_attach_cmd": None,
            "services_detected": [],
            "tools_installed": [],
            "verification": {
                "qemu_boots": None,
                "shell_accessible": None,
                "network_reachable": None,
                "gdb_attachable": None,
                "services_accessible": [],
            },
            "notes": [],
            "orchestrator_session_id": None,
        }
        self._script_fragments: list[str] = []

    def apply_task_result(self, task_id: str, result: dict):
        """태스크 결과에서 environment_update와 verification을 환경에 반영."""
        update = result.get("environment_update") or {}

        # scalar 필드 업데이트 (null이 아닌 경우만)
        for field in ("arch", "endianness", "os_type", "filesystem_type", "compression",
                      "rootfs_path", "kernel_path", "dtb_path",
                      "qemu_system_cmd", "qemu_user_cmd", "qemu_pid",
                      "chroot_cmd", "gdb_attach_cmd"):
            val = update.get(field)
            if val is not None:
                self._env[field] = val

        # 포트 업데이트
        ports = update.get("ports") or {}
        for port_name, port_val in ports.items():
            if port_val is not None:
                self._env["ports"][port_name] = port_val

        # 목록 필드 병합
        for field in ("services_detected", "tools_installed"):
            for item in (update.get(field) or []):
                if item not in self._env[field]:
                    self._env[field].append(item)

        # notes
        notes = update.get("notes", "")
        if notes:
            self._env["notes"].append(f"[{task_id}] {notes}")

        # verification 병합
        verif = result.get("verification") or {}
        for field in ("qemu_boots", "shell_accessible", "network_reachable", "gdb_attachable"):
            val = verif.get(field)
            if val is not None:
                self._env["verification"][field] = val
        for svc in (verif.get("services_accessible") or []):
            if svc not in self._env["verification"]["services_accessible"]:
                self._env["verification"]["services_accessible"].append(svc)

        # setup script fragment 수집
        frag = result.get("setup_script_fragment", "")
        if frag:
            self._script_fragments.append(f"\n# Task {task_id}\n{frag}")

    def set_orchestrator_session_id(self, sid: str | None):
        self._env["orchestrator_session_id"] = sid

    def save(self) -> tuple[Path, Path]:
        """lab_env.json 과 setup.sh 를 저장하고 경로를 반환."""
        env_path = self.session_path / "lab_env.json"
        script_path = self.session_path / "setup.sh"

        self._env["updated_at"] = datetime.now().isoformat()
        with open(env_path, "w", encoding="utf-8") as f:
            json.dump(self._env, f, indent=2, ensure_ascii=False)

        self._write_setup_script(script_path)

        return env_path, script_path

    def _write_setup_script(self, script_path: Path):
        fw = self.firmware_path
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        arch = self._env.get("arch", "unknown")
        rootfs = self._env.get("rootfs_path", "")
        qemu_cmd = self._env.get("qemu_system_cmd", "")
        qemu_user = self._env.get("qemu_user_cmd", "")
        chroot = self._env.get("chroot_cmd", "")
        gdb = self._env.get("gdb_attach_cmd", "")

        lines = [
            "#!/bin/bash",
            f"# FBI Lab Environment Setup Script",
            f"# Firmware : {fw}",
            f"# Generated: {now}",
            f"# Arch     : {arch}",
            "set -e",
            "",
        ]

        # Fragment들 삽입
        if self._script_fragments:
            lines.append("# SETUP STEPS (generated from Codex worker output)")
            lines.extend(self._script_fragments)
            lines.append("")

        # Quick-start 섹션
        lines.append("# QUICK-START COMMANDS")

        if qemu_cmd:
            lines.append("")
            lines.append("# Start QEMU (system emulation)")
            lines.append(f"{qemu_cmd} &")
            p = self._env["ports"]
            if p.get("telnet"):
                telnet_port = p["telnet"]
                lines.append(f'echo "Serial console: telnet 127.0.0.1 {telnet_port}"')
            if p.get("gdb"):
                gdb_port = p["gdb"]
                lines.append(f"echo \"GDB: gdb-multiarch -ex 'target remote :{gdb_port}'\"")

        if qemu_user:
            lines.append("")
            lines.append("# Run single binary (user-mode emulation)")
            lines.append(f"# {qemu_user}")

        if chroot:
            lines.append("")
            lines.append("# Chroot into extracted filesystem")
            lines.append(f"# {chroot}")

        if gdb:
            lines.append("")
            lines.append("# Attach GDB")
            lines.append(f"# {gdb}")

        ports = self._env.get("ports", {})
        exposed = {k: v for k, v in ports.items() if v}
        if exposed:
            lines.append("")
            lines.append("# Exposed ports:")
            for name, port in exposed.items():
                lines.append(f"#   {name:10}: 127.0.0.1:{port}")

        lines.append("")
        lines.append("echo 'Lab environment ready.'")

        with open(script_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        script_path.chmod(0o755)

    def summary(self) -> dict:
        """현재 환경 상태 요약 반환."""
        v = self._env.get("verification", {})
        ports = {k: v for k, v in self._env.get("ports", {}).items() if v}
        return {
            "arch": self._env.get("arch"),
            "os_type": self._env.get("os_type"),
            "rootfs_ready": bool(self._env.get("rootfs_path")),
            "qemu_system_ready": bool(self._env.get("qemu_system_cmd")),
            "qemu_user_ready": bool(self._env.get("qemu_user_cmd")),
            "chroot_ready": bool(self._env.get("chroot_cmd")),
            "gdb_ready": bool(self._env.get("gdb_attach_cmd")),
            "ports": ports,
            "services": self._env.get("services_detected", []),
            "verification": v,
        }

    @classmethod
    def load(cls, env_json_path: str) -> dict:
        """저장된 lab_env.json 로드."""
        with open(env_json_path, encoding="utf-8") as f:
            return json.load(f)
