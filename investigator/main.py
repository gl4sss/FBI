#!/usr/bin/env python3
"""
FBI — Investigator
취약점 정찰: Codex 오케스트레이션 및 병렬 분석

Usage:
  python investigator/main.py <firmware>                       # 새 분석 시작
  python investigator/main.py <firmware> --resume <session>    # 중단된 분석 이어서
"""
import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from investigator.firmware_utils import analyze_firmware
from investigator.orchestrator import Orchestrator
from investigator.patch_differ import PatchDiffer
from investigator.worker import Worker
from shared.logger import ConversationLogger
from shared.mcp_manager import McpManager
from shared.session_manager import SessionManager
from shared.resume import (load_completed_tasks, load_sent_task_ids,
                           verify_resume_firmware)


def load_settings(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _bar(title: str):
    print(f"\n{'='*64}\n  {title}\n{'='*64}")


def load_resume_state(session_dir: str) -> tuple[list, dict | None, int, str | None]:
    """
    저장된 세션에서 상태를 복원합니다.
    Returns:
      completed_tasks    — 이미 완료된 태스크 목록
      pending_roadmap    — Codex가 결정했지만 Codex에 보내지 못한 roadmap (없으면 None)
      used_iterations    — 이미 소비된 Codex 호출 횟수
      orchestrator_session_id  — Codex 대화 세션 ID (--resume에 사용)
    """
    session_path = Path(session_dir)
    orchestrator_log = session_path / "orchestrator_conversation.jsonl"

    if not orchestrator_log.exists():
        raise FileNotFoundError(f"Session log not found: {orchestrator_log}")

    entries = []
    with open(orchestrator_log, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    completed_tasks = []
    last_assistant = None
    used_iterations = 0
    orchestrator_session_id: str | None = None

    for entry in entries:
        if entry["role"] == "user":
            # 최신 user 메시지의 completed_tasks 누적분 복원
            ct = entry["content"].get("completed_tasks") or entry["content"].get("new_results") or []
            if ct:
                completed_tasks = ct
        elif entry["role"] == "assistant":
            last_assistant = entry["content"]
            used_iterations += 1
            # 마지막으로 저장된 Codex 세션 ID
            if entry.get("orchestrator_session_id"):
                orchestrator_session_id = entry["orchestrator_session_id"]

    completed_tasks = load_completed_tasks(session_dir, completed_tasks)
    pending_roadmap = None
    if last_assistant:
        completed_ids = {t.get("task_id") for t in completed_tasks}
        pending = [
            t for t in last_assistant.get("new_tasks", [])
            if t.get("task_id") not in completed_ids
        ]
        if pending:
            pending_roadmap = dict(last_assistant)
            pending_roadmap["new_tasks"] = pending

    return completed_tasks, pending_roadmap, used_iterations, orchestrator_session_id


def _dispatch_tasks(new_tasks, worker, session_mgr, firmware_path, logger,
                    parallel_limit, cfg_worker) -> list[dict]:
    """new_tasks를 Codex 워커에 병렬 전송하고 completed 형태로 반환."""
    task_results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=parallel_limit) as executor:
        futures: dict = {}
        for task in new_tasks:
            existing_sid = session_mgr.get_session_id(
                task["task_id"], task.get("reuse_session_for")
            )
            fut = executor.submit(worker.execute, task, existing_sid, firmware_path)
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
                findings = result.get("findings") or []
                short_sid = sid[:8] if len(sid) >= 8 else sid
                print(f"\n[Codex] {task_id}  status={status_str}  session={short_sid}...")
                if findings:
                    print(f"        Findings ({len(findings)}):")
                    for item in findings[:4]:
                        print(f"          - {str(item)[:120]}")
                analysis_short = (result.get("analysis") or "")[:200]
                if analysis_short:
                    print(f"        Analysis: {analysis_short}...")

            except Exception as exc:
                print(f"[!] Task {task_id} failed: {exc}")
                task_results[task_id] = {
                    "task_id": task_id,
                    "status": "failed",
                    "findings": [],
                    "analysis": str(exc),
                    "session_id": None,
                }
            logger.log_task_result(task, task_results[task_id])

    newly_completed = []
    for task in new_tasks:
        tid = task["task_id"]
        if tid in task_results:
            newly_completed.append({
                "task_id": tid,
                "type": task.get("type"),
                "session_id": task_results[tid].get("session_id"),
                "result": task_results[tid],
            })
    return newly_completed


def run_analysis(firmware_path: str, settings: dict, resume_from: str | None = None,
                 patched_firmware_path: str | None = None):
    cfg_analysis = settings["analysis"]
    cfg_orch = settings["orchestrator"]
    cfg_worker = settings["worker"]

    sessions_dir = cfg_analysis["sessions_dir"]
    max_iterations = cfg_analysis["max_iterations"]
    parallel_limit = cfg_worker["parallel_limit"]

    firmware_name = Path(firmware_path).stem
    logger = ConversationLogger(sessions_dir, firmware_name, resume_from=resume_from)

    _bar(f"Firmware Analysis: {firmware_path}")

    print("\n[*] Collecting basic firmware information...")
    firmware_info = analyze_firmware(firmware_path)
    if resume_from:
        verify_resume_firmware(resume_from, firmware_info)
    logger.save_firmware_info(firmware_info)
    print(f"    Type  : {firmware_info['file_type']}")
    print(f"    Size  : {firmware_info['size_bytes']:,} bytes")
    print(f"    MD5   : {firmware_info['hashes']['md5']}")
    print(f"    SHA256: {firmware_info['hashes']['sha256']}")
    print(f"    Strings: {len(firmware_info['strings_sample'])} strings (sample)")
    if firmware_info["binwalk"]:
        print(f"    Binwalk: {len(firmware_info['binwalk'].splitlines())} lines")

    # 패치 펌웨어가 제공된 경우 diff 수행
    if patched_firmware_path:
        if not Path(patched_firmware_path).exists():
            print(f"[!] 패치 펌웨어를 찾을 수 없습니다: {patched_firmware_path}", file=sys.stderr)
        else:
            _bar(f"Patch Diff: {Path(firmware_path).name} vs {Path(patched_firmware_path).name}")
            work_dir = str(logger.get_session_path() / "patch_diff_work")
            differ = PatchDiffer(work_dir=work_dir)
            patch_diff = differ.diff(firmware_path, patched_firmware_path)
            firmware_info["patch_diff"] = patch_diff

            # diff 요약 저장
            diff_out = logger.get_session_path() / "patch_diff.json"
            with open(diff_out, "w", encoding="utf-8") as f:
                import json as _json
                _json.dump(patch_diff, f, indent=2, ensure_ascii=False)

            print(f"\n[PatchDiff] 결과 저장: {diff_out}")
            print(f"[PatchDiff] 분석 힌트: {patch_diff.get('patch_focus_hint', '')[:200]}")

    cfg_mcp = settings.get("mcp", {})
    mcp = McpManager(
        servers=cfg_mcp.get("servers", []),
        apply_to=cfg_mcp.get("apply_to", []),
    )
    if mcp.servers:
        print(f"\n[MCP] Configuring {len(mcp.servers)} server(s): "
              + ", ".join(s["name"] for s in mcp.servers))
        mcp.register_codex_servers()

    completed_tasks: list[dict] = []
    iteration = 0
    first_roadmap: dict | None = None
    resume_orchestrator_sid: str | None = None

    if resume_from:
        completed_tasks, first_roadmap, used_itr, resume_orchestrator_sid = load_resume_state(resume_from)
        iteration = used_itr - 1 if first_roadmap else used_itr
        print(f"\n[Resume] Session: {resume_from}")
        print(f"[Resume] Completed tasks : {len(completed_tasks)} "
              f"({', '.join(t.get('task_id','?') for t in completed_tasks)})")
        print(f"[Resume] Codex iterations used: {used_itr} / {max_iterations}")
        if resume_orchestrator_sid:
            print(f"[Resume] Codex session restored: {resume_orchestrator_sid[:16]}...")
        else:
            print(f"[Resume] Codex session ID not found — will start new Codex conversation")
        if first_roadmap:
            pending_ids = [t.get("task_id", "?")
                           for t in first_roadmap.get("new_tasks", [])]
            print(f"[Resume] Pending tasks to dispatch: {pending_ids}")
        else:
            print("[Resume] No pending tasks — requesting new roadmap from Codex")

    orchestrator = Orchestrator(
        model=cfg_orch["model"],
        reasoning_effort=cfg_orch.get("reasoning_effort", "medium"),
        logger=logger,
        resume_session_id=resume_orchestrator_sid,
        sent_task_ids=load_sent_task_ids(resume_from) if resume_from else None,
    )
    worker = Worker(
        model=cfg_worker["model"],
        reasoning_effort=cfg_worker.get("reasoning_effort", "high"),
        bypass_approvals=cfg_worker.get("bypass_approvals", False),
        sandbox_permissions=cfg_worker.get("sandbox_permissions", []),
        network_access=cfg_worker.get("network_access", False),
        logger=logger,
    )
    session_mgr = SessionManager()
    session_mgr.restore(completed_tasks)

    while iteration < max_iterations:
        iteration += 1

        if first_roadmap is not None:
            roadmap = first_roadmap
            first_roadmap = None
            _bar(f"Iteration {iteration}  |  Resuming from saved roadmap")
            print(f"[Resume] Using saved roadmap (skipping Codex call)")
        else:
            _bar(f"Iteration {iteration}  |  Codex Orchestrator ({cfg_orch['model']})")
            print("[*] Requesting roadmap from Codex...")
            try:
                roadmap = orchestrator.decide(firmware_info, completed_tasks)
            except Exception as exc:
                print(f"[!] Orchestrator error: {exc}")
                break
            logger.save_roadmap(roadmap)

        summary = roadmap.get("analysis_summary", "")
        status = roadmap.get("status", "unknown")
        print(f"\n[Orchestrator] {summary[:300]}")
        print(f"[Orchestrator] Status: {status}")

        if status == "complete":
            _bar("Analysis Complete")
            conclusion = roadmap.get("conclusion")
            if conclusion:
                print(f"\n{conclusion}")
            break

        new_tasks = roadmap.get("new_tasks") or []
        if not new_tasks:
            print("[!] Codex returned no new tasks. Stopping.")
            break

        print(f"\n[Orchestrator] Tasks dispatched ({len(new_tasks)}):")
        for t in new_tasks:
            tid = t.get("task_id", "?")
            ttype = t.get("type", "other")
            tprio = t.get("priority", "medium")
            reuse = t.get("reuse_session_for")
            reuse_str = f" [continues {reuse}]" if reuse else " [new session]"
            print(f"  - {tid} [{tprio:6}] {ttype}{reuse_str}")

        _bar(f"Codex Workers  |  model={cfg_worker['model']}  |  parallel={parallel_limit}")

        newly = _dispatch_tasks(
            new_tasks, worker, session_mgr, firmware_path, logger,
            parallel_limit, cfg_worker,
        )
        completed_tasks.extend(newly)


    _bar("Session Complete")
    session_path = logger.get_session_path()
    print(f"[*] Logs saved : {session_path}")
    print(f"[*] Iterations : {iteration}")
    print(f"[*] Tasks done : {len(completed_tasks)}")
    print(f"[*] Sessions   : {len(session_mgr.summary())}")

    # 분석 완료 시 HTML 보고서 자동 생성
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from report_generator import generate_report
        cfg_report = settings.get("report", {})
        report_dir = cfg_report.get("output_dir", "./report")
        report_path = generate_report(str(session_path), report_dir)
        print(f"\n[Report] HTML report: {report_path}")
        print(f"[Report] Q&A 모드:  python qa.py --session {session_path}")
    except Exception as exc:
        print(f"[!] Report generation failed: {exc}")

    print()


def main():
    default_settings = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "settings.json"
    )
    parser = argparse.ArgumentParser(
        description="FBI Investigator — Codex 기반 펌웨어 취약점 분석"
    )
    parser.add_argument("firmware", help="분석 대상 펌웨어 바이너리 경로 (구버전/취약 버전)")
    parser.add_argument("--settings", default=default_settings, help="settings.json 경로")
    parser.add_argument(
        "--resume",
        metavar="SESSION_DIR",
        help="중단된 세션 경로로 분석 재개 (예: sessions/investigator/firmware/20260626_153325)",
    )
    parser.add_argument(
        "--patched",
        metavar="PATCHED_FIRMWARE",
        help="최신(패치된) 펌웨어 경로 — 제공 시 패치 diff를 중심으로 취약점 탐색",
    )
    args = parser.parse_args()

    fw = Path(args.firmware)
    if not fw.exists():
        print(f"Error: firmware file not found: {args.firmware}", file=sys.stderr)
        sys.exit(1)

    cfg_path = Path(args.settings)
    if not cfg_path.exists():
        print(f"Error: settings file not found: {args.settings}", file=sys.stderr)
        sys.exit(1)

    if args.resume:
        resume_path = Path(args.resume)
        if not resume_path.exists():
            print(f"Error: resume session not found: {args.resume}", file=sys.stderr)
            sys.exit(1)

    if args.patched and not Path(args.patched).exists():
        print(f"Error: patched firmware not found: {args.patched}", file=sys.stderr)
        sys.exit(1)

    settings = load_settings(str(cfg_path))
    run_analysis(str(fw), settings, resume_from=args.resume,
                 patched_firmware_path=args.patched)


if __name__ == "__main__":
    main()
