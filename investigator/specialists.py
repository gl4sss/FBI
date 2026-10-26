"""Fixed specialist catalog and local, conservative file routing."""

import hashlib
import re
from collections import deque
from pathlib import Path


PROMPT_DIR = Path(__file__).with_name("specialist_prompts")
SPECIALISTS = (
    ("secrets", "비밀정보·하드코딩 자격증명"),
    ("stack_overflow", "스택 버퍼 오버플로"),
    ("memory_safety", "기타 메모리 안전성"),
    ("denial_of_service", "서비스 거부"),
    ("injection", "입력 처리·명령 실행"),
    ("authz", "인증·권한 경계"),
    ("update_trust", "업데이트·부팅 신뢰"),
    ("crypto_transport", "암호화·통신 설정"),
    ("components", "외부 구성요소·CVE"),
    ("exposure_privilege", "서비스 노출·권한 설정"),
)

_NATIVE = {".elf", ".so", ".exe", ".dll", ".o", ".a", ".wasm"}
_C_SOURCE = {".c", ".cc", ".cpp", ".h", ".hpp"}
_SCRIPT = {".sh", ".bash", ".cgi", ".php", ".py", ".pl", ".lua",
           ".js", ".asp", ".aspx", ".jsp", ".rb", ".tcl", ".ps1"}
_WEB = {".cgi", ".php", ".js", ".html", ".htm", ".asp", ".aspx", ".jsp"}
_PACKAGE = {".apk", ".jar", ".class", ".dex", ".deb", ".rpm"}
_COMPONENT_NAMES = ("busybox", "openssl", "libcurl", "dropbear", "lighttpd",
                    "dnsmasq", "nginx", "libssl", "libcrypto", "uhttpd")


def prompt_version(specialist_id: str) -> str:
    return hashlib.sha256((PROMPT_DIR / f"{specialist_id}.md").read_bytes()).hexdigest()[:12]


def _clues(entry: dict, sample: bytes) -> dict[str, str]:
    path = Path(entry["path"])
    name = path.name.lower()
    rel = entry["relative_path"].lower()
    suffix = path.suffix.lower()
    text = sample.decode("utf-8", errors="ignore").lower()
    native = (sample.startswith((b"\x7fELF", b"MZ", b"\x00asm")) or
              suffix in _NATIVE or suffix in _C_SOURCE)
    script = suffix in _SCRIPT or sample.startswith(b"#!")
    code = native or script or suffix in _PACKAGE or entry["type"] == "code"
    config = entry["type"] == "configuration"
    selected = {}

    def add(identifier: str, condition: bool, reason: str) -> None:
        if condition:
            selected[identifier] = reason

    add("secrets", bool(re.search(r"private[ _-]?key|password|passwd|token|secret|api[ _-]?key|BEGIN [A-Z ]*PRIVATE KEY|ssh-rsa", text, re.I)) or
        any(part in rel for part in ("secret", "credential", "private", "passwd", "shadow")) or
        suffix in {".key", ".pem", ".p12", ".pfx"}, "credential or key clue")
    add("stack_overflow", native, "native executable or C-family source")
    add("memory_safety", native, "native executable or C-family source")
    add("denial_of_service", (native or script) and
        bool(re.search(r"while\s|for\s|listen|socket|recv|read\(|malloc|calloc|realloc|fork\(", text)),
        "native parser or long-running service clue")
    add("injection", suffix in _WEB or
        (code and bool(re.search(r"system\(|popen\(|exec\(|eval\b|subprocess|request|query_string|\$[1-9]", text))),
        "input handling or command execution clue")
    add("authz", (code or config) and
        (bool(re.search(r"auth|login|session|permission|role|admin", text)) or
         any(part in rel for part in ("auth", "login", "passwd", "shadow"))),
        "authentication or authorization clue")
    add("update_trust", any(part in rel for part in ("update", "upgrade", "firmware", "boot", "flash")) or
        ((code or config) and bool(re.search(r"signature|verify|rollback|fw_update|flashcp|mtd_write", text))),
        "update, boot, or integrity clue")
    add("crypto_transport", suffix in {".pem", ".crt", ".cer", ".key", ".p12"} or
        ((code or config) and bool(re.search(r"tls|ssl|cipher|crypto|openssl|certificate|x509|https", text))),
        "cryptography or transport clue")
    add("components", suffix in {".so", ".dll", ".a"} or suffix in _PACKAGE or
        any(part in rel for part in ("manifest", "package", "version", "license", "sbom")) or
        (code or config) and (any(part in name for part in _COMPONENT_NAMES) or
                              any(part in text for part in _COMPONENT_NAMES)),
        "component identity or version clue")
    add("exposure_privilege", suffix in {".service", ".socket"} or
        any(part in rel for part in ("/init", "/rc.", "inetd", "httpd", "dropbear", "telnetd", "sudoers", "service")) or
        ((script or config) and bool(re.search(r"listen|bind\(|chmod|chown|setuid|root:|0\.0\.0\.0", text))),
        "service exposure or privilege clue")
    if entry.get("size_bytes", 0) > len(sample) and (code or config):
        # A bounded read cannot rule out a relevant clue later in the file.
        for identifier in ("secrets", "authz", "update_trust", "crypto_transport",
                           "exposure_privilege"):
            selected.setdefault(identifier, "sample incomplete; applicability uncertain")
    elif entry.get("size_bytes", 0) > len(sample) and entry["type"] == "data":
        selected.setdefault("components", "opaque or large data; format uncertain after bounded sample")
        if b"\x00" not in sample:
            selected.setdefault("secrets", "large text data; later content was not sampled")
    return selected


def plan_specialists(inventory: list[dict], extracted_dir: str | Path) -> tuple[list[dict], dict]:
    """Route files without model calls; keep a reason for every inventory entry."""
    root = Path(extracted_dir).resolve()
    prompts = {identifier: (PROMPT_DIR / f"{identifier}.md").read_text(encoding="utf-8")
               for identifier, _ in SPECIALISTS}
    versions = {identifier: prompt_version(identifier) for identifier, _ in SPECIALISTS}
    tasks = []
    routing = []
    counts = {identifier: 0 for identifier, _ in SPECIALISTS}
    for entry in inventory:
        if entry.get("status") != "pending":
            routing.append({"path": entry["path"], "status": entry["status"],
                            "reason": entry.get("reason", "not a reviewable regular file"),
                            "specialists": []})
            continue
        path = Path(entry["path"])
        if not path.resolve().is_relative_to(root):
            routing.append({"path": entry["path"], "status": "unreadable",
                            "reason": "path escapes extraction root", "specialists": []})
            continue
        try:
            with path.open("rb") as stream:
                sample = stream.read(65536)
        except OSError as exc:
            routing.append({"path": entry["path"], "status": "unreadable",
                            "reason": str(exc), "specialists": []})
            continue
        selected = _clues(entry, sample)
        routing.append({"path": entry["path"],
                        "status": "scheduled" if selected else "no_applicable_clue",
                        "reason": "" if selected else "No relevant clue in local metadata and bounded sample",
                        "specialists": list(selected)})
        for identifier, _ in SPECIALISTS:
            if identifier not in selected:
                continue
            counts[identifier] += 1
            version = versions[identifier]
            path_id = hashlib.sha256(entry["relative_path"].encode()).hexdigest()[:12]
            tasks.append({
                "task_id": f"sp_{identifier}_{path_id}_{version}",
                "type": "specialist_analysis", "specialist_id": identifier,
                "prompt_version": version, "priority": "high",
                "scope_files": [entry["path"]], "scope_types": {entry["path"]: entry["type"]},
                "routing_reason": selected[identifier],
                "prompt": prompts[identifier] +
                          f"\n\nRouting clue: {selected[identifier]}. Inspect only the scoped file "
                          "and directly relevant callers or configuration.\n",
            })
    specialists = [
        {"id": identifier, "name": title, "prompt_version": versions[identifier],
         "status": "scheduled" if counts[identifier] else "no_applicable_clue",
         "task_count": counts[identifier],
         "reason": "" if counts[identifier] else "No relevant clue in extracted files"}
        for identifier, title in SPECIALISTS
    ]
    # Keep limited runs distributed across all fixed domains.
    queues = {identifier: deque(task for task in tasks
                                if task["specialist_id"] == identifier)
              for identifier, _ in SPECIALISTS}
    balanced = []
    while any(queues.values()):
        for identifier, _ in SPECIALISTS:
            if queues[identifier]:
                balanced.append(queues[identifier].popleft())
    return balanced, {"specialists": specialists, "file_routing": routing,
                   "mode": "specialists"}


def followup_tasks(completed_tasks: list[dict]) -> list[dict]:
    """One focused static follow-up per unresolved specialist finding."""
    tasks = []
    for saved in completed_tasks:
        if saved.get("type") != "specialist_analysis":
            continue
        result = saved.get("result") or {}
        identifier = result.get("specialist_id")
        if not identifier:
            continue
        for finding in result.get("suspected_findings") or []:
            if finding.get("disposition") != "needs_static_research":
                continue
            source_id = finding.get("finding_id")
            if not source_id:
                continue
            version = prompt_version(identifier)
            tasks.append({
                "task_id": f"sp_follow_{source_id}", "type": "specialist_followup",
                "specialist_id": identifier, "prompt_version": version,
                "source_finding_id": source_id,
                "scope_files": saved.get("scope_files") or [finding.get("file_path")],
                "reuse_session_for": saved["task_id"],
                "prompt": (PROMPT_DIR / f"{identifier}.md").read_text(encoding="utf-8") +
                          f"\n\nResolve only finding {source_id} at {finding.get('location')}. "
                          f"Observation: {finding.get('observation', '')}. "
                          "Trace the missing static evidence and return its final disposition. "
                          f"Fill investigation.source_finding_id with {source_id}. "
                          "Record any distinct newly found root cause separately.\n",
            })
    return tasks
