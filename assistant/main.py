#!/usr/bin/env python3
"""
FBI — Assistant
Detective PoC를 기반으로 Full Kill Chain Exploit 개발

Usage:
  python assistant/main.py --session sessions/detective/firmware/20260630_...
  python assistant/main.py --session <detective_session> --firmware <firmware_path>
  python assistant/main.py --session <detective_session> --resume sessions/assistant/firmware/...
"""
import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from assistant.orchestrator import AssistantOrchestrator
from assistant.worker import ExploitWorker
from shared.logger import ConversationLogger
from shared.mcp_manager import McpManager
from shared.session_manager import SessionManager
from shared.resume import load_completed_tasks, load_sent_task_ids


def load_settings(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _bar(title: str):
    print(f"\n{'='*64}\n  {title}\n{'='*64}")


def load_detective_session(session_dir: str) -> dict:
    """Detective 세션에서 확인된 취약점, PoC 코드, 트리거 가이드를 로드."""
    sp = Path(session_dir)

    # detective_session.json (confirmed_vulns, orchestrator_session_id)
    confirmed_vulns = []
    detective_info = {}
    ds_path = sp / "detective_session.json"
    if ds_path.exists():
        with open(ds_path, encoding="utf-8") as f:
            detective_info = json.load(f)
        confirmed_vulns = detective_info.get("confirmed_vulns", [])

    # firmware_info.json
    firmware_info = {}
    fi_path = sp / "firmware_info.json"
    if fi_path.exists():
        with open(fi_path, encoding="utf-8") as f:
            firmware_info = json.load(f)

    # Codex 세션에서 PoC 코드 수집
    poc_artifacts: list[dict] = []
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
                    poc_code = c.get("poc_code")
                    poc_file = c.get("poc_file")
                    vdp = c.get("vdp_assessment") or {}
                    if poc_code or poc_file:
                        poc_artifacts.append({
                            "task_id": c.get("task_id", "unknown"),
                            "poc_code": poc_code,
                            "poc_file": poc_file,
                            "trigger_confirmed": vdp.get("trigger_confirmed"),
                            "cvss_score": vdp.get("cvss_score"),
                            "cvss_vector": vdp.get("cvss_vector"),
                            "findings": c.get("findings", []),
                            "evidence": c.get("evidence", []),
                            "inferences": c.get("inferences", []),
                            "analysis": (c.get("analysis") or "")[:800],
                        })

    # trigger_guides/*.md 목록
    trigger_guides: list[str] = []
    guides_dir = sp / "trigger_guides"
    if guides_dir.exists():
        for md in sorted(guides_dir.glob("*.md")):
            trigger_guides.append(str(md))

    # 마지막 Codex 요약
    orchestrator_summary = ""
    cl_path = sp / "orchestrator_conversation.jsonl"
    if cl_path.exists():
        with open(cl_path, encoding="utf-8") as f:
            entries = [json.loads(l) for l in f if l.strip()]
        for e in reversed(entries):
            if e["role"] == "assistant":
                orchestrator_summary = e["content"].get("analysis_summary", "")
                break

    return {
        "firmware_info": firmware_info,
        "confirmed_vulns": confirmed_vulns,
        "poc_artifacts": poc_artifacts,
        "trigger_guides": trigger_guides,
        "detective_summary": orchestrator_summary,
        "detective_session_path": str(sp),
    }


def load_resume_state(session_dir: str) -> tuple[list, str | None]:
    """이전 assistant 세션에서 completed_tasks와 orchestrator_session_id 복원."""
    sp = Path(session_dir)
    completed_tasks: list[dict] = []
    orchestrator_session_id: str | None = None

    as_path = sp / "assistant_session.json"
    if as_path.exists():
        with open(as_path, encoding="utf-8") as f:
            info = json.load(f)
        orchestrator_session_id = info.get("orchestrator_session_id")

    cl_path = sp / "orchestrator_conversation.jsonl"
    if cl_path.exists():
        with open(cl_path, encoding="utf-8") as f:
            entries = [json.loads(l) for l in f if l.strip()]
        for e in entries:
            if e.get("role") == "assistant" and e.get("orchestrator_session_id"):
                orchestrator_session_id = e["orchestrator_session_id"]
            if e["role"] == "user":
                c = e.get("content", {})
                for task in c.get("completed_tasks", []) + c.get("new_results", []):
                    tid = task.get("task_id")
                    if tid and not any(t.get("task_id") == tid for t in completed_tasks):
                        completed_tasks.append(task)

    return load_completed_tasks(session_dir, completed_tasks), orchestrator_session_id


def _save_assistant_session(session_path: Path, orchestrator_session_id: str | None,
                             roadmap: dict, kill_chain_info: dict):
    info = {
        "saved_at": datetime.now().isoformat(),
        "orchestrator_session_id": orchestrator_session_id,
        "resume_command": f"codex resume {orchestrator_session_id}" if orchestrator_session_id else None,
        "status": roadmap.get("status", "unknown"),
        "last_summary": roadmap.get("analysis_summary", ""),
        "attack_graph": roadmap.get("attack_graph"),
        "kill_chain_info": kill_chain_info,
    }
    out = session_path / "assistant_session.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)


def _save_kill_chain_report(session_path: Path, roadmap: dict,
                             completed_tasks: list, kill_chain_file: str | None):
    """Kill chain 결과를 Markdown 보고서로 저장."""
    report_dir = session_path / "kill_chain_report"
    report_dir.mkdir(exist_ok=True)

    lines = []
    lines.append("# Kill Chain Exploit 보고서\n")
    lines.append(f"**생성일시**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    attack_graph = roadmap.get("attack_graph") or {}
    if attack_graph:
        lines.append("## 공격 그래프\n")
        lines.append(f"- **진입점**: {attack_graph.get('entry_point_vuln', 'N/A')}")
        lines.append(f"- **최종 목표**: {attack_graph.get('final_objective', 'N/A')}")
        lines.append(f"- **전체 CVSS**: {attack_graph.get('overall_cvss', 'N/A')}")
        lines.append(f"- **체인 실현 가능성**: {attack_graph.get('chain_feasibility', 'N/A')}\n")

        stages = attack_graph.get("stages", [])
        if stages:
            lines.append("### 공격 단계\n")
            lines.append("| 단계 | 취약점 | MITRE | 행동 | 획득 |")
            lines.append("|------|--------|-------|------|------|")
            for s in stages:
                lines.append(
                    f"| {s.get('stage_num')} | {s.get('vuln_id', 'N/A')} | "
                    f"{s.get('mitre_technique')} {s.get('mitre_name', '')} | "
                    f"{s.get('action', '')[:60]} | {s.get('output_gained', '')[:60]} |"
                )
            lines.append("")

    if kill_chain_file:
        lines.append("## Kill Chain 스크립트\n")
        lines.append(f"```bash")
        lines.append(f"python {kill_chain_file} --target <TARGET_IP> [--port <PORT>]")
        lines.append(f"```\n")

    confirmed_chain = roadmap.get("confirmed_chain") or {}
    if confirmed_chain:
        tested = confirmed_chain.get("chain_tested")
        working = confirmed_chain.get("chain_working")
        lines.append("## 체인 테스트 결과\n")
        lines.append(f"- **테스트 완료**: {'예' if tested else '아니요'}")
        lines.append(f"- **체인 동작**: {'성공' if working else '실패 또는 미완료'}")
        evidence = confirmed_chain.get("evidence_files", [])
        if evidence:
            lines.append(f"- **증거 파일**:")
            for e in evidence:
                lines.append(f"  - `{e}`")
        lines.append("")

    for task_result in completed_tasks:
        result = task_result.get("result") or task_result
        task_type = task_result.get("type", "")
        task_id = task_result.get("task_id", "?")

        if task_type == "chain_integration":
            vdp = result.get("vdp_package") or {}
            if vdp:
                lines.append("## VDP 제출 패키지\n")
                lines.append(f"**제목**: {vdp.get('title', '')}\n")
                lines.append(f"**심각도**: {vdp.get('severity', '')} (CVSS {vdp.get('cvss_overall', '')})\n")
                lines.append(f"**공격 설명 (한국어)**:\n{vdp.get('attack_description_ko', '')}\n")
                lines.append(f"**영향도 (한국어)**:\n{vdp.get('impact_ko', '')}\n")
                lines.append(f"**조치 권고 (한국어)**:\n{vdp.get('remediation_ko', '')}\n")

                steps = vdp.get("reproduction_steps_ko", [])
                if steps:
                    lines.append("**재현 단계 (한국어)**:\n")
                    for step in steps:
                        lines.append(f"{step}")
                lines.append("")

        summary_ko = result.get("stage_summary_ko", "")
        if summary_ko:
            lines.append(f"### [{task_id}] 단계 요약\n")
            lines.append(f"{summary_ko}\n")

        mitre = result.get("mitre_mapping") or {}
        if mitre:
            lines.append(
                f"**MITRE ATT&CK**: [{mitre.get('technique_id')}] "
                f"{mitre.get('technique_name')} — {mitre.get('tactic')}\n"
            )

    md_path = report_dir / "kill_chain_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return md_path


def _dispatch_tasks(new_tasks, worker, session_mgr, firmware_path,
                    detective_session, logger, parallel_limit, session_path) -> list[dict]:
    task_results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=parallel_limit) as executor:
        futures = {}
        for task in new_tasks:
            existing_sid = session_mgr.get_session_id(
                task["task_id"], task.get("reuse_session_for")
            )
            fut = executor.submit(
                worker.execute, task, existing_sid, firmware_path, detective_session
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

                status_str = result.get("status", "?")
                short_sid = sid[:8] if len(sid) >= 8 else sid
                task_type = task.get("type", "?")
                stage_num = task.get("stage_num", "?")
                test = result.get("test_result") or {}
                stage_ok = test.get("stage_success") or test.get("full_chain_success")
                chain_ok = result.get("kill_chain_file")

                print(f"\n[Codex] {task_id}  type={task_type}  stage={stage_num}"
                      f"  status={status_str}  session={short_sid}...")
                if stage_ok is not None:
                    print(f"        stage_success={stage_ok}")
                if chain_ok:
                    print(f"        kill_chain_file: {chain_ok}")

                mitre = result.get("mitre_mapping") or {}
                if mitre:
                    print(f"        MITRE: [{mitre.get('technique_id')}] {mitre.get('technique_name')}")

                for finding in (result.get("findings") or [])[:3]:
                    print(f"        - {str(finding)[:120]}")

            except Exception as exc:
                print(f"[!] Task {task_id} failed: {exc}")
                task_results[task_id] = {
                    "task_id": task_id,
                    "status": "failed",
                    "exploit_code": None,
                    "exploit_file": None,
                    "findings": [],
                    "analysis": str(exc),
                    "follow_up_needed": True,
                }
            logger.log_task_result(task, task_results[task_id])

    newly_completed = []
    for task in new_tasks:
        tid = task["task_id"]
        if tid in task_results:
            newly_completed.append({
                "task_id": tid,
                "type": task.get("type"),
                "vuln_ref": task.get("vuln_ref"),
                "stage_num": task.get("stage_num"),
                "session_id": task_results[tid].get("session_id"),
                "result": task_results[tid],
            })
    return newly_completed


def run_assistant(detective_session_dir: str, settings: dict,
                  firmware_path: str | None = None,
                  resume_session_dir: str | None = None):
    if resume_session_dir and not Path(resume_session_dir).is_dir():
        raise FileNotFoundError(f"Assistant resume session not found: {resume_session_dir}")
    cfg_analysis = settings["analysis"]
    cfg_orch = settings["orchestrator"]
    cfg_worker = settings["worker"]
    cfg_exploit = settings.get("exploit", {})

    sessions_dir = cfg_analysis["sessions_dir"]
    max_iterations = cfg_analysis["max_iterations"]
    parallel_limit = cfg_worker["parallel_limit"]
    exploit_output_dir = cfg_exploit.get("output_dir", "./kill_chain_artifacts")

    _bar("FBI Assistant — Full Kill Chain Exploit 개발")
    print(f"[*] Detective 세션: {detective_session_dir}")

    detective_data = load_detective_session(detective_session_dir)
    firmware_info = detective_data["firmware_info"]

    if not firmware_path:
        firmware_path = firmware_info.get("path", "")
    if not firmware_path or not Path(firmware_path).exists():
        print(f"[!] 펌웨어 파일을 찾을 수 없습니다: {firmware_path}")
        firmware_path = firmware_path or "unknown"

    print(f"[*] 펌웨어: {firmware_path}")
    print(f"[*] 확인된 취약점: {len(detective_data['confirmed_vulns'])}건")
    print(f"[*] PoC 아티팩트: {len(detective_data['poc_artifacts'])}개")
    print(f"[*] 트리거 가이드: {len(detective_data['trigger_guides'])}개")

    # resume 처리
    completed_tasks: list[dict] = []
    resume_orchestrator_sid: str | None = None
    if resume_session_dir:
        completed_tasks, resume_orchestrator_sid = load_resume_state(resume_session_dir)
        print(f"[*] Resume: {len(completed_tasks)}개 태스크 복원, "
              f"session_id={resume_orchestrator_sid[:20] if resume_orchestrator_sid else 'None'}...")

    firmware_name = Path(firmware_path).stem if firmware_path != "unknown" else "unknown"
    logger = ConversationLogger(sessions_dir, firmware_name,
                                resume_from=resume_session_dir)
    session_path = logger.get_session_path()
    os.makedirs(exploit_output_dir, exist_ok=True)

    # MCP 설정
    cfg_mcp = settings.get("mcp", {})
    mcp = McpManager(
        servers=cfg_mcp.get("servers", []),
        apply_to=cfg_mcp.get("apply_to", []),
    )
    if mcp.servers:
        print(f"\n[MCP] {len(mcp.servers)}개 서버 설정")
        mcp.register_codex_servers()

    assistant = AssistantOrchestrator(
        model=cfg_orch["model"],
        reasoning_effort=cfg_orch.get("reasoning_effort", "medium"),
        logger=logger,
        resume_session_id=resume_orchestrator_sid,
        sent_task_ids=load_sent_task_ids(resume_session_dir) if resume_session_dir else None,
    )
    worker = ExploitWorker(
        model=cfg_worker["model"],
        reasoning_effort=cfg_worker.get("reasoning_effort", "high"),
        bypass_approvals=cfg_worker.get("bypass_approvals", False),
        sandbox_permissions=cfg_worker.get("sandbox_permissions", []),
        network_access=cfg_worker.get("network_access", False),
        logger=logger,
        exploit_output_dir=exploit_output_dir,
    )
    session_mgr = SessionManager()
    session_mgr.restore(completed_tasks)

    context = {
        "detective_session": detective_session_dir,
        "firmware_info": {k: v for k, v in firmware_info.items()
                          if k not in ("strings_sample", "binwalk")},
        "detective_summary": detective_data["detective_summary"],
        "confirmed_vulns": detective_data["confirmed_vulns"],
        "poc_artifacts": detective_data["poc_artifacts"][:10],
        "trigger_guides": detective_data["trigger_guides"],
        "exploit_output_dir": exploit_output_dir,
        "objective": (
            "Assess whether the confirmed vulnerabilities form a reproducible chain. "
            "Verify each dependency and any executable artifact in the configured local lab "
            "or explicitly supplied test target. Document tested results, missing evidence, "
            "and limitations in Korean for a potential VDP submission."
        ),
    }

    kill_chain_info: dict = {"kill_chain_file": None, "chain_working": False}
    iteration = 0
    last_roadmap: dict = {}

    while iteration < max_iterations:
        iteration += 1

        _bar(f"Iteration {iteration}  |  Assistant ({cfg_orch['model']})")
        print("[*] Kill chain 전략 수립 중...")

        try:
            roadmap = assistant.decide(context, completed_tasks)
        except Exception as exc:
            print(f"[!] Orchestrator error: {exc}")
            break

        logger.save_roadmap(roadmap)
        last_roadmap = roadmap

        # kill chain 파일 추적
        confirmed_chain = roadmap.get("confirmed_chain") or {}
        if confirmed_chain.get("kill_chain_script"):
            kill_chain_info["kill_chain_file"] = confirmed_chain["kill_chain_script"]
        if confirmed_chain.get("chain_working"):
            kill_chain_info["chain_working"] = True

        _save_assistant_session(session_path, assistant.session_id,
                                roadmap, kill_chain_info)

        summary = roadmap.get("analysis_summary", "")
        status = roadmap.get("status", "unknown")
        print(f"\n[Orchestrator] {summary[:300]}")
        print(f"[Orchestrator] Status: {status}")

        if assistant.session_id:
            print(f"[Orchestrator] Session: {assistant.session_id[:20]}...")

        # 공격 그래프 출력
        ag = roadmap.get("attack_graph") or {}
        if ag.get("stages"):
            print(f"\n[공격 그래프]  목표: {ag.get('final_objective', 'N/A')}")
            for s in ag["stages"]:
                print(f"  Stage {s['stage_num']}: [{s.get('vuln_id','?')}] "
                      f"{s.get('mitre_technique','')} → {s.get('output_gained','')[:60]}")

        if status == "complete":
            _bar("Kill Chain 개발 완료")
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
            print(f"  - {t.get('task_id','?')} [{t.get('priority','?'):6}] "
                  f"{t.get('type','?')}  stage={t.get('stage_num','?')}  "
                  f"vuln={t.get('vuln_ref','?')}")

        _bar(f"Codex Exploit Workers  |  {cfg_worker['model']}  |  parallel={parallel_limit}")

        newly = _dispatch_tasks(
            new_tasks, worker, session_mgr, firmware_path,
            detective_data, logger, parallel_limit, session_path,
        )
        completed_tasks.extend(newly)

        # kill_chain_file 추적 (worker 결과에서)
        for t in newly:
            r = t.get("result") or {}
            kc_file = r.get("kill_chain_file")
            if kc_file:
                kill_chain_info["kill_chain_file"] = kc_file
            if (r.get("test_result") or {}).get("full_chain_success"):
                kill_chain_info["chain_working"] = True


    _save_assistant_session(session_path, assistant.session_id, last_roadmap, kill_chain_info)

    # 보고서 저장
    report_path = _save_kill_chain_report(
        session_path, last_roadmap, completed_tasks,
        kill_chain_info.get("kill_chain_file"),
    )

    # 최종 결과 출력
    _bar("Assistant 완료 — Kill Chain 결과")
    print(f"[*] 세션 경로   : {session_path}")
    print(f"[*] 이터레이션  : {iteration}")
    print(f"[*] 완료 태스크 : {len(completed_tasks)}")

    kc_file = kill_chain_info.get("kill_chain_file")
    if kc_file:
        print(f"\n[Kill Chain] 스크립트: {kc_file}")
        print(f"[Kill Chain] 실행 방법: python {kc_file} --target <TARGET_IP>")
    else:
        print(f"\n[Kill Chain] 스크립트가 생성되지 않았습니다. 세션을 재개하여 계속 진행하세요.")

    print(f"\n[보고서] {report_path}")

    if assistant.session_id:
        print(f"""
{'-'*64}
 Codex 세션으로 이어서 진행하기
{'-'*64}

 Kill chain 개선, 추가 단계 개발, VDP 작성 등을 대화형으로
 이어서 진행할 수 있습니다.

   codex resume {assistant.session_id}

 예시 질문:
   "Stage 2가 실패했어. 다른 방법으로 권한 상승 시도해줘."
   "VDP 제출용 영문 보고서를 더 상세하게 작성해줘."
   "Kill chain 스크립트에 stealth 옵션을 추가해줘."

 세션 정보 파일: {session_path}/assistant_session.json
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
        description="FBI Assistant — Full Kill Chain Exploit 개발"
    )
    parser.add_argument(
        "--session", required=True, metavar="DETECTIVE_SESSION",
        help="Detective 세션 경로 (예: sessions/detective/firmware/20260630_...)",
    )
    parser.add_argument(
        "--firmware", metavar="FIRMWARE_PATH",
        help="펌웨어 파일 경로 (생략 시 세션에서 자동 감지)",
    )
    parser.add_argument(
        "--resume", metavar="ASSISTANT_SESSION",
        help="이전 Assistant 세션을 재개할 경로",
    )
    parser.add_argument("--settings", default=default_settings,
                        help="assistant/settings.json 경로")
    args = parser.parse_args()

    sp = Path(args.session)
    if not sp.exists():
        print(f"Error: detective session not found: {args.session}", file=sys.stderr)
        sys.exit(1)

    cfg_path = Path(args.settings)
    if not cfg_path.exists():
        print(f"Error: settings not found: {args.settings}", file=sys.stderr)
        sys.exit(1)

    settings = load_settings(str(cfg_path))
    run_assistant(
        detective_session_dir=str(sp),
        settings=settings,
        firmware_path=args.firmware,
        resume_session_dir=args.resume,
    )


if __name__ == "__main__":
    main()
