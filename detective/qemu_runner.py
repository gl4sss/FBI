"""
QEMU 펌웨어 에뮬레이터 관리
- 아키텍처 자동 감지
- QEMU 프로세스 시작/정지
- 포트 및 연결 정보 제공
"""
import os
import re
import signal
import socket
import subprocess
import time
from pathlib import Path


_ARCH_MAP = {
    # (file 출력 키워드, binwalk 키워드) → (qemu-system-*, machine, cpu)
    "arm":    ("qemu-system-arm",    "versatilepb", "arm926"),
    "aarch64":("qemu-system-aarch64","virt",        "cortex-a57"),
    "mipsel": ("qemu-system-mipsel", "malta",       "mips32r2-generic"),
    "mips":   ("qemu-system-mips",   "malta",       "mips32r2-generic"),
    "x86_64": ("qemu-system-x86_64", "pc",          "qemu64"),
    "i386":   ("qemu-system-i386",   "pc",          "pentium3"),
    "ppc":    ("qemu-system-ppc",    "mac99",       "g3"),
}


def detect_arch(firmware_info: dict) -> str:
    """firmware_info의 file_type과 binwalk 출력에서 아키텍처를 추론."""
    combined = (
        (firmware_info.get("file_type") or "") + " " +
        (firmware_info.get("binwalk") or "")
    ).lower()

    if "aarch64" in combined or "arm64" in combined:
        return "aarch64"
    if "arm" in combined:
        return "arm"
    if "mipsel" in combined or "mips little" in combined:
        return "mipsel"
    if "mips" in combined:
        return "mips"
    if "x86-64" in combined or "x86_64" in combined or "amd64" in combined:
        return "x86_64"
    if "80386" in combined or "i386" in combined or "ia-32" in combined:
        return "i386"
    if "powerpc" in combined or "ppc" in combined:
        return "ppc"
    return "unknown"


def _free_port(start: int, reserved: set[int] | None = None) -> int:
    reserved = reserved or set()
    for port in range(start, start + 100):
        if port in reserved:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No free port found starting at {start}")


class QemuRunner:
    def __init__(self, cfg_qemu: dict):
        self.cfg = cfg_qemu
        self._proc: subprocess.Popen | None = None
        self.arch: str = "unknown"
        self.telnet_port: int = 0
        self.monitor_port: int = 0
        self.qemu_bin: str = ""
        self.log_path: str = ""

    def start(self, firmware_path: str, firmware_info: dict, work_dir: str) -> dict:
        """
        QEMU를 시작하고 연결 정보를 반환한다.
        Returns dict with: arch, qemu_bin, telnet_port, monitor_port, pid, log_path
        """
        self.arch = detect_arch(firmware_info)
        arch_cfg = _ARCH_MAP.get(self.arch)

        if not arch_cfg:
            return {
                "started": False,
                "arch": self.arch,
                "reason": f"Unsupported or unknown architecture: {self.arch}",
            }

        self.qemu_bin, machine, cpu = arch_cfg

        # QEMU 설치 여부 확인
        chk = subprocess.run(["which", self.qemu_bin], capture_output=True, text=True)
        if chk.returncode != 0:
            return {
                "started": False,
                "arch": self.arch,
                "qemu_bin": self.qemu_bin,
                "reason": f"{self.qemu_bin} not found in PATH. Install with: sudo apt install {self.qemu_bin}",
            }

        self.telnet_port = _free_port(self.cfg.get("telnet_port", 4444))
        self.monitor_port = _free_port(self.cfg.get("monitor_port", 4445),
                                       {self.telnet_port})
        http_port = _free_port(self.cfg.get("http_port", 8080),
                               {self.telnet_port, self.monitor_port})
        https_port = _free_port(self.cfg.get("https_port", 8443),
                                {self.telnet_port, self.monitor_port, http_port})

        Path(work_dir).mkdir(parents=True, exist_ok=True)
        self.log_path = str(Path(work_dir) / "qemu.log")

        cmd = [
            self.qemu_bin,
            "-M", machine,
            "-cpu", cpu,
            "-kernel", firmware_path,
            "-nographic",
            "-serial", f"telnet:127.0.0.1:{self.telnet_port},server,nowait",
            "-monitor", f"telnet:127.0.0.1:{self.monitor_port},server,nowait",
            "-net", "nic",
            "-net", (f"user,hostfwd=tcp::{http_port}-:80,"
                     f"hostfwd=tcp::{https_port}-:443"),
        ]

        log_f = open(self.log_path, "w")
        self._proc = subprocess.Popen(
            cmd, stdout=log_f, stderr=log_f,
            preexec_fn=os.setsid,
        )

        time.sleep(self.cfg.get("timeout_boot", 30))

        if self._proc.poll() is not None:
            log_f.close()
            return {
                "started": False,
                "arch": self.arch,
                "qemu_bin": self.qemu_bin,
                "reason": "QEMU process exited immediately",
                "log_path": self.log_path,
            }

        log_f.close()
        return {
            "started": True,
            "arch": self.arch,
            "qemu_bin": self.qemu_bin,
            "machine": machine,
            "cpu": cpu,
            "pid": self._proc.pid,
            "telnet_port": self.telnet_port,
            "monitor_port": self.monitor_port,
            "http_port": http_port,
            "https_port": https_port,
            "log_path": self.log_path,
            "connection_info": (
                f"Serial console: telnet 127.0.0.1 {self.telnet_port}\n"
                f"QEMU monitor:   telnet 127.0.0.1 {self.monitor_port}\n"
                f"HTTP (if any):  http://127.0.0.1:{http_port}\n"
                f"HTTPS (if any): https://127.0.0.1:{https_port}"
            ),
        }

    def stop(self):
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                self._proc.kill()
        self._proc = None

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def get_boot_log(self, max_bytes: int = 4096) -> str:
        if not self.log_path or not Path(self.log_path).exists():
            return ""
        with open(self.log_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        return content[-max_bytes:] if len(content) > max_bytes else content
