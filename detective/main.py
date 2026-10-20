#!/usr/bin/env python3
"""
FBI — Detective
PoC 개발, CVE/VDP 검증, 수동 트리거 가이드 생성

Usage:
  python detective/main.py --session sessions/investigator/firmware/20260630_120000
  python detective/main.py --session <investigator_session> --firmware <firmware_path>
  python detective/main.py --session <investigator_session> --no-qemu
"""
import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detective.ghidra_annotator import GhidraAnnotator
from detective.orchestrator import Detective
from detective.qemu_runner import QemuRunner
from detective.worker import PocWorker
from shared.logger import ConversationLogger
from shared.mcp_manager import McpManager
from shared.session_manager import SessionManager


def load_settings(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _bar(title: str):
    print(f"\n{'='*64}\n  {title}\n{'='*64}")


def load_investigator_session(session_dir: str) -> tuple[dict, list, str]:
    sp = Path(session_dir)

    firmware_info = {}
    fi_path = sp / "firmware_info.json"
    if fi_path.exists():
        with open(fi_path, encoding="utf-8") as f:
            firmware_info = json.load(f)

    vulnerabilities = []
    codex_dir = sp / "codex_sessions"
    if codex_dir.exists():
        for jf in sorted(codex_dir.glob("*.jsonl")):
            with open(jf, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    if entry.get("role") != "assistant":
                        continue
                    c = entry.get("content", {})
                    tid = c.get("task_id", "unknown")
                    findings = c.get("findings", [])
                    follow_up = c.get("follow_up_needed", False)

                    if findings or follow_up:
                        vulnerabilities.append({
                            "source_task": tid,
                            "findings": findings,
                            "evidence": c.get("evidence", []),
                            "inferences": c.get("inferences", []),
                            "recommendations": c.get("recommendations", []),
                            "analysis_snippet": (c.get("analysis") or "")[:600],
                            "follow_up_needed": follow_up,
                            "follow_up_reason": c.get("follow_up_reason"),
                        })

    orchestrator_summary = ""
    cl_path = sp / "orchestrator_conversation.jsonl"
    if cl_path.exists():
        with open(cl_path, encoding="utf-8") as f:
            entries = [json.loads(l) for l in f if l.strip()]
        for e in reversed(entries):
            if e["role"] == "assistant":
                orchestrator_summary = e["content"].get("analysis_summary", "")
                break

    return firmware_info, vulnerabilities, orchestrator_summary


def _save_detective_session(session_path: Path, orchestrator_session_id: str | None,
                             roadmap: dict, confirmed_vulns: list):
    """Codex 세션 정보를 파일로 저장 — 나중에 --resume으로 이어서 진행 가능."""
    info = {
        "saved_at": datetime.now().isoformat(),
        "orchestrator_session_id": orchestrator_session_id,
        "resume_command": f"codex resume {orchestrator_session_id}" if orchestrator_session_id else None,
        "status": roadmap.get("status", "unknown"),
        "last_summary": roadmap.get("analysis_summary", ""),
        "confirmed_vulns_count": len(confirmed_vulns),
        "confirmed_vulns": confirmed_vulns,
    }
    out = session_path / "detective_session.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)


def _save_trigger_guide(session_path: Path, task_id: str, result: dict):
    """태스크 결과에서 trigger_guide를 Markdown 파일로 저장."""
    guide = result.get("trigger_guide")
    vdp = result.get("vdp_assessment") or {}
    if not guide:
        return

    guides_dir = session_path / "trigger_guides"
    guides_dir.mkdir(exist_ok=True)

    lines = []
    title = guide.get("title", f"{task_id} 트리거 가이드")
    lines.append(f"# {title}\n")

    vuln_summary = guide.get("vulnerability_summary", "")
    if vuln_summary:
        lines.append(f"> {vuln_summary}\n")

    # VDP 평가 뱃지
    cvss = vdp.get("cvss_score")
    cvss_vec = vdp.get("cvss_vector", "")
    confirmed = vdp.get("trigger_confirmed")
    cve_worthy = vdp.get("cve_worthy")
    strength = vdp.get("evidence_strength", "")

    lines.append("## VDP/CVE 평가\n")
    lines.append(f"| 항목 | 값 |")
    lines.append(f"|------|-----|")
    lines.append(f"| 트리거 확인 | {'확인됨' if confirmed else ('미확인' if confirmed is False else '분석 중')} |")
    lines.append(f"| 증거 강도 | {strength} |")
    if cvss:
        lines.append(f"| CVSSv3.1 점수 | {cvss} |")
    if cvss_vec:
        lines.append(f"| CVSS 벡터 | `{cvss_vec}` |")
    lines.append(f"| CVE 제출 가능 | {'가능' if cve_worthy else ('불가' if cve_worthy is False else '검토 필요')} |")
    vdp_title = vdp.get("suggested_vdp_title", "")
    if vdp_title:
        lines.append(f"| VDP 제출 제목 | {vdp_title} |")
    lines.append("")

    # 환경 요구사항
    env = guide.get("environment", {})
    if env:
        lines.append("## 환경 요구사항\n")
        if env.get("os"):
            lines.append(f"**OS**: {env['os']}\n")
        tools = env.get("tools_required", [])
        if tools:
            lines.append(f"**필요 도구**: {', '.join(tools)}\n")
            lines.append("```bash")
            lines.append(f"# 도구 설치 예시 (Debian/Ubuntu)")
            lines.append(f"sudo apt install -y {' '.join(t for t in tools if not t.startswith('python'))}")
            lines.append("```\n")
        net = env.get("network_setup", "")
        if net:
            lines.append(f"**네트워크 설정**: {net}\n")

    # 준비 단계
    setup = guide.get("setup_steps", [])
    if setup:
        lines.append("## 준비 단계\n")
        for step in setup:
            lines.append(f"{step}")
        lines.append("")

    # 트리거 단계
    trigger = guide.get("trigger_steps", [])
    if trigger:
        lines.append("## 취약점 트리거 단계\n")
        for step in trigger:
            lines.append(f"{step}")
        lines.append("")

    # 성공 기준
    expected = guide.get("expected_result", "")
    if expected:
        lines.append("## 성공 기준 (이렇게 보이면 트리거 성공)\n")
        lines.append(f"{expected}\n")

    # 증거 수집
    evidence = guide.get("evidence_to_capture", [])
    if evidence:
        lines.append("## 수집해야 할 증거\n")
        for e in evidence:
            lines.append(f"- {e}")
        lines.append("")

    # 트러블슈팅
    ts = guide.get("troubleshooting", [])
    if ts:
        lines.append("## 트러블슈팅\n")
        for t in ts:
            lines.append(f"- {t}")
        lines.append("")

    # VDP 제출 체크리스트
    checklist = guide.get("vdp_checklist", [])
    if checklist:
        lines.append("## VDP 제출 체크리스트\n")
        for item in checklist:
            lines.append(f"- {item}")
        lines.append("")

    # VDP 영향 설명
    impact = vdp.get("suggested_impact", "")
    if impact:
        lines.append("## VDP 영향 설명 (영문 초안)\n")
        lines.append(f"> {impact}\n")

    additional = vdp.get("additional_evidence_needed")
    if additional:
        lines.append("## 추가 증거 필요\n")
        lines.append(f"주의: {additional}\n")

    # PoC 코드
    poc_code = result.get("poc_code")
    if poc_code:
        ext = "py" if poc_code.strip().startswith("#!") and "python" in poc_code[:50] else "sh"
        lines.append(f"## PoC 코드\n")
        lines.append(f"```{ext}")
        lines.append(poc_code)
        lines.append("```\n")

    md_path = guides_dir / f"{task_id}_trigger_guide.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return md_path


def _dispatch_tasks(new_tasks, worker, session_mgr, firmware_path,
                    qemu_info, logger, parallel_limit, session_path) -> list[dict]:
    task_results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=parallel_limit) as executor:
        futures = {}
        for task in new_tasks:
            existing_sid = session_mgr.get_session_id(
                task["task_id"], task.get("reuse_session_for")
            )
            fut = executor.submit(
                worker.execute, task, existing_sid, firmware_path, qemu_info
            )
            futures[fut] = task

        for fut in as_completed(futures):
            task = futures[fut]
            task_id = task["task_id"]
            try:
                result = fut.result()
                sid = result.get("session_id") or f"unknown_{task_id}"
                session_mgr.register_session(task_id, sid, task.get("type", ""))
                task_results[task_id] = result

                vdp = result.get("vdp_assessment") or {}
                confirmed = vdp.get("trigger_confirmed")
                cvss = vdp.get("cvss_score", "?")
                strength = vdp.get("evidence_strength", "?")
                status_str = result.get("status", "?")
                short_sid = sid[:8] if len(sid) >= 8 else sid

                print(f"\n[Codex] {task_id}  status={status_str}  session={short_sid}...")
                print(f"        trigger={'confirmed' if confirmed else ('not confirmed' if confirmed is False else 'pending')}  "
                      f"cvss={cvss}  evidence={strength}")

                findings = result.get("findings") or []
                for item in findings[:3]:
                    print(f"        - {str(item)[:120]}")

                # trigger guide 저장
                guide_path = _save_trigger_guide(session_path, task_id, result)
                if guide_path:
                    print(f"        Trigger guide: {guide_path}")

            except Exception as exc:
                print(f"[!] Task {task_id} failed: {exc}")
                task_results[task_id] = {
                    "task_id": task_id,
                    "status": "failed",
                    "trigger_guide": None,
                    "vdp_assessment": {"trigger_confirmed": None, "evidence_strength": "None"},
                    "findings": [],
                    "analysis": str(exc),
                    "session_id": None,
                }

    newly_completed = []
    for task in new_tasks:
        tid = task["task_id"]
        if tid in task_results:
            newly_completed.append({
                "task_id": tid,
                "type": task.get("type"),
                "vulnerability_ref": task.get("vulnerability_ref"),
                "session_id": task_results[tid].get("session_id"),
                "result": task_results[tid],
            })
    return newly_completed


def run_detective(investigator_session: str, settings: dict,
                  firmware_path: str | None = None, no_qemu: bool = False):
    cfg_analysis = settings["analysis"]
    cfg_orch = settings["orchestrator"]
    cfg_worker = settings["worker"]
    cfg_qemu = settings.get("qemu", {})

    sessions_dir = cfg_analysis["sessions_dir"]
    max_iterations = cfg_analysis["max_iterations"]
    parallel_limit = cfg_worker["parallel_limit"]
    poc_output_dir = cfg_qemu.get("poc_output_dir", "./poc_artifacts")

    _bar("FBI Detective — CVE/VDP PoC 검증 및 트리거 가이드 생성")
    print(f"[*] Investigator 세션: {investigator_session}")

    firmware_info, vulnerabilities, inv_summary = load_investigator_session(investigator_session)

    if not firmware_path:
        firmware_path = firmware_info.get("path", "")
    if not firmware_path or not Path(firmware_path).exists():
        print(f"[!] 펌웨어 파일을 찾을 수 없습니다: {firmware_path}")
        print(f"    --firmware 옵션으로 경로를 지정하세요.")
        firmware_path = firmware_path or "unknown"

    print(f"[*] 펌웨어: {firmware_path}")
    print(f"[*] 취약점 그룹: {len(vulnerabilities)}개  "
          f"(총 발견사항: {sum(len(v['findings']) for v in vulnerabilities)}건)")
    if inv_summary:
        print(f"\n[Investigator] {inv_summary[:300]}")

    firmware_name = Path(firmware_path).stem if firmware_path != "unknown" else "unknown"
    logger = ConversationLogger(sessions_dir, firmware_name)
    session_path = logger.get_session_path()

    # QEMU 시작
    qemu_info: dict = {"started": False, "reason": "skipped by --no-qemu"}
    qemu_runner: QemuRunner | None = None

    if not no_qemu and firmware_path != "unknown":
        _bar("QEMU 에뮬레이터 시작")
        qemu_runner = QemuRunner(cfg_qemu)
        work_dir = str(session_path / "qemu")
        qemu_info = qemu_runner.start(firmware_path, firmware_info, work_dir)

        if qemu_info["started"]:
            print(f"[QEMU] 시작 성공 (PID={qemu_info['pid']}, arch={qemu_info['arch']})")
            print(f"[QEMU] {qemu_info['connection_info']}")
        else:
            print(f"[QEMU] 시작 실패: {qemu_info.get('reason')}")
            print(f"[QEMU] 정적 분석 기반 PoC + 트리거 가이드 작성 모드로 진행")
    else:
        print(f"[QEMU] 건너뜀 — trigger_guide는 QEMU 설정 방법도 포함하여 작성됩니다.")

    # MCP 설정
    cfg_mcp = settings.get("mcp", {})
    mcp = McpManager(
        servers=cfg_mcp.get("servers", []),
        apply_to=cfg_mcp.get("apply_to", []),
    )
    if mcp.servers:
        print(f"\n[MCP] {len(mcp.servers)}개 서버 설정")
        mcp.register_codex_servers()

    detective = Detective(
        model=cfg_orch["model"],
        reasoning_effort=cfg_orch.get("reasoning_effort", "medium"),
        logger=logger,
        resume_session_id=None,
    )
    worker = PocWorker(
        model=cfg_worker["model"],
        reasoning_effort=cfg_worker.get("reasoning_effort", "high"),
        bypass_approvals=cfg_worker.get("bypass_approvals", False),
        sandbox_permissions=cfg_worker.get("sandbox_permissions", []),
        network_access=cfg_worker.get("network_access", False),
        logger=logger,
        poc_output_dir=poc_output_dir,
    )
    session_mgr = SessionManager()

    # Ghidra 주석 기능 — Ghidra MCP가 설정된 경우에만 활성화
    annotator = GhidraAnnotator(
        model=cfg_worker["model"],
        reasoning_effort=cfg_worker.get("reasoning_effort", "high"),
        logger=logger,
    ) if any(s.get("name") == "ghidra" for s in cfg_mcp.get("servers", [])) else None
    _annotated_vuln_ids: set[str] = set()

    context = {
        "investigator_session": investigator_session,
        "firmware_info": {
            k: v for k, v in firmware_info.items()
            if k not in ("strings_sample", "binwalk")
        },
        "architecture": firmware_info.get("file_type", "unknown"),
        "investigator_summary": inv_summary,
        "vulnerabilities": vulnerabilities,
        "qemu": {
            "available": qemu_info.get("started", False),
            "arch": qemu_info.get("arch"),
            "connection_info": qemu_info.get("connection_info"),
        },
        "objective": (
            "Assess each candidate for CVE/VDP submission using observed evidence. "
            "Test triggers where the target and permissions allow; record inconclusive cases. "
            "Estimate CVSS v3.1 only when the required conditions are known. "
            "Write Korean reproduction steps for verified tests and label untested steps clearly."
        ),
    }

    completed_tasks: list[dict] = []
    confirmed_vulns: list[dict] = []
    iteration = 0
    last_roadmap: dict = {}

    try:
        while iteration < max_iterations:
            iteration += 1

            _bar(f"Iteration {iteration}  |  Detective ({cfg_orch['model']})")
            print("[*] CVE/VDP 전략 수립 중...")
            try:
                roadmap = detective.decide(context, completed_tasks)
            except Exception as exc:
                print(f"[!] Orchestrator error: {exc}")
                break
            logger.save_roadmap(roadmap)
            last_roadmap = roadmap

            # 확인된 취약점 업데이트
            newly_confirmed = []
            for v in roadmap.get("confirmed_vulns", []):
                ids = [c.get("vuln_id") for c in confirmed_vulns]
                if v.get("vuln_id") not in ids:
                    confirmed_vulns.append(v)
                    newly_confirmed.append(v)

            # High/Critical 취약점 → Ghidra 자동 주석 (새로 확인된 것만)
            if annotator and newly_confirmed:
                poc_arts = [
                    t.get("result", t) for t in completed_tasks
                ]
                new_high = [
                    v for v in newly_confirmed
                    if annotator.should_annotate(v)
                    and v.get("vuln_id") not in _annotated_vuln_ids
                ]
                if new_high:
                    _bar(f"Ghidra 자동 주석  |  {len(new_high)}개 High/Critical 취약점")
                    annotation_results = annotator.annotate_batch(new_high, poc_arts)
                    for res in annotation_results:
                        _annotated_vuln_ids.add(res.get("vuln_id", ""))

            # 매 이터레이션 후 세션 저장
            _save_detective_session(session_path, detective.session_id,
                                    roadmap, confirmed_vulns)

            summary = roadmap.get("analysis_summary", "")
            status = roadmap.get("status", "unknown")
            print(f"\n[Orchestrator] {summary[:300]}")
            print(f"[Orchestrator] Status: {status}")

            if detective.session_id:
                print(f"[Orchestrator] Session: {detective.session_id[:20]}... "
                      f"(저장됨 → detective_session.json)")

            if status == "complete":
                _bar("분석 완료")
                conclusion = roadmap.get("conclusion")
                if conclusion:
                    print(f"\n{conclusion}")
                break

            new_tasks = roadmap.get("new_tasks") or []
            if not new_tasks:
                print("[!] Codex returned no new tasks. Stopping.")
                break

            print(f"\n[Orchestrator] Tasks ({len(new_tasks)}):")
            for t in new_tasks:
                tid = t.get("task_id", "?")
                ttype = t.get("type", "other")
                tprio = t.get("priority", "medium")
                vref = t.get("vulnerability_ref", "")
                print(f"  - {tid} [{tprio:6}] {ttype}  ref={vref}")

            _bar(f"Codex PoC Workers  |  {cfg_worker['model']}  |  parallel={parallel_limit}")

            newly = _dispatch_tasks(
                new_tasks, worker, session_mgr, firmware_path,
                qemu_info, logger, parallel_limit, session_path,
            )
            completed_tasks.extend(newly)

    finally:
        if qemu_runner:
            qemu_runner.stop()
            print("\n[QEMU] 프로세스 종료")


    # 최종 세션 저장
    _save_detective_session(session_path, detective.session_id, last_roadmap, confirmed_vulns)

    # 최종 결과 출력
    _bar("Detective 완료 — 결과 요약")
    print(f"[*] 세션 경로 : {session_path}")
    print(f"[*] 이터레이션: {iteration}")
    print(f"[*] 완료 태스크: {len(completed_tasks)}")
    print(f"[*] 확인된 취약점: {len(confirmed_vulns)}건")

    if confirmed_vulns:
        print("\n확인된 취약점 (CVE 제출 가능)")
        for v in confirmed_vulns:
            cvss = v.get("cvss_score", "?")
            cve = "CVE 제출 가능" if v.get("cve_worthy") else "검토 필요"
            print(f"  {v.get('vuln_id','?')}  CVSS={cvss}  {cve}")
            print(f"  {v.get('title','')[:70]}")

    # trigger guide 파일 목록
    guides_dir = session_path / "trigger_guides"
    if guides_dir.exists():
        guides = list(guides_dir.glob("*.md"))
        if guides:
            print(f"\n[가이드] 수동 트리거 가이드 ({len(guides)}개):")
            for g in guides:
                print(f"  파일: {g}")

    # HTML 보고서 생성
    try:
        from report_generator import generate_report
        cfg_report = settings.get("report", {})
        report_dir = cfg_report.get("output_dir", "./report")
        report_path = generate_report(str(session_path), report_dir)
        print(f"\n[Report] HTML report: {report_path}")
    except Exception as exc:
        print(f"[!] Report generation failed: {exc}")

    # Codex 세션 재개 안내
    if detective.session_id:
        print(f"""
{'-'*64}
 Codex 세션으로 이어서 진행하기
{'-'*64}

 분석 맥락을 그대로 이어받아 취약점 트리거, 트러블슈팅,
 추가 분석을 대화형으로 진행할 수 있습니다.

   codex resume {detective.session_id}

 예시 질문:
   "VULN-001을 내 환경에서 직접 트리거하고 싶어. 단계별로 안내해줘."
   "트리거 중에 [오류 메시지]가 발생했는데 어떻게 해결해?"
   "이 취약점으로 CVE를 신청하려면 어떤 증거가 더 필요해?"

 세션 정보 파일: {session_path}/detective_session.json
{'-'*64}""")
    else:
        print(f"\n[!] Codex session ID를 가져오지 못했습니다.")
        print(f"    Q&A 모드를 사용하세요: python qa.py --session {session_path}")

    print()


def main():
    default_settings = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "settings.json"
    )
    parser = argparse.ArgumentParser(
        description="FBI Detective — CVE/VDP PoC 검증, 수동 트리거 가이드, Codex 세션 연속"
    )
    parser.add_argument(
        "--session", required=True, metavar="INVESTIGATOR_SESSION",
        help="Investigator 세션 경로 (예: sessions/investigator/firmware/20260630_...)",
    )
    parser.add_argument(
        "--firmware", metavar="FIRMWARE_PATH",
        help="펌웨어 파일 경로 (생략 시 세션에서 자동 감지)",
    )
    parser.add_argument("--settings", default=default_settings,
                        help="detective/settings.json 경로")
    parser.add_argument("--no-qemu", action="store_true",
                        help="QEMU 없이 정적 분석 기반 PoC + 트리거 가이드만 생성")
    args = parser.parse_args()

    sp = Path(args.session)
    if not sp.exists():
        print(f"Error: investigator session not found: {args.session}", file=sys.stderr)
        sys.exit(1)

    cfg_path = Path(args.settings)
    if not cfg_path.exists():
        print(f"Error: settings not found: {args.settings}", file=sys.stderr)
        sys.exit(1)

    settings = load_settings(str(cfg_path))
    run_detective(
        investigator_session=str(sp),
        settings=settings,
        firmware_path=args.firmware,
        no_qemu=args.no_qemu,
    )


if __name__ == "__main__":
    main()
