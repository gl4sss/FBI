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
import math
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from investigator.firmware_utils import analyze_firmware
from investigator.extractor import ExtractionError, extract_firmware
from investigator.deep_research import baseline_tasks, finding_research_tasks
from investigator.orchestrator import Orchestrator
from investigator.patch_differ import PatchDiffer
from investigator.scan_scope import file_inventory, save_scan_scope, scan_tasks
from investigator.specialists import followup_tasks, plan_specialists
from investigator.worker import Worker
from shared.logger import ConversationLogger
from shared.mcp_manager import McpManager
from shared.session_manager import SessionManager
from shared.resume import (load_completed_tasks, load_sent_task_ids,
                           verify_resume_firmware)
from shared.validation import validate_specialist_scope


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
        return load_completed_tasks(session_dir), None, 0, None

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


def _dispatch_tasks(new_tasks, worker, session_mgr, firmware_path, extracted_dir, logger,
                    parallel_limit, cfg_worker, on_finding=None, task_runner=None) -> list[dict]:
    """new_tasks를 Codex 워커에 병렬 전송하고 completed 형태로 반환."""
    task_results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=parallel_limit) as executor:
        futures: dict = {}
        for task in new_tasks:
            existing_sid = session_mgr.get_session_id(
                task["task_id"], task.get("reuse_session_for")
            )
            runner = task_runner or (lambda w, t, sid, fw, root:
                                     w.execute(t, sid, fw, root))
            fut = executor.submit(runner, worker, task, existing_sid,
                                  firmware_path, extracted_dir)
            futures[fut] = task

        for fut in as_completed(futures):
            task = futures[fut]
            task_id = task["task_id"]
            try:
                result = fut.result()
                if task.get("specialist_id"):
                    validate_specialist_scope(result, extracted_dir)
                scoped_files = task.get("scope_files") or []
                if scoped_files:
                    reviewed = set(result.get("reviewed_files") or [])
                    missing = [path for path in scoped_files if path not in reviewed]
                    if missing:
                        if result.get("status") == "completed":
                            result["status"] = "partial"
                        result["follow_up_needed"] = True
                        result["follow_up_reason"] = (
                            f"Scoped files not reviewed: {', '.join(missing)}"
                        )
                sid = result.get("session_id") or f"unknown_{task_id}"
                session_mgr.register_session(task_id, sid, task.get("type", ""))
                task_results[task_id] = result

                status_str = result.get("status", "?")
                findings = result.get("findings") or []
                suspected = result.get("suspected_findings") or []
                short_sid = sid[:8] if len(sid) >= 8 else sid
                print(f"\n[Codex] {task_id}  status={status_str}  session={short_sid}...")
                if findings:
                    print(f"        Findings ({len(findings)}):")
                    for item in findings[:4]:
                        print(f"          - {str(item)[:120]}")
                if suspected:
                    print(f"        Suspicious sites: {len(suspected)}")
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
            if on_finding and task_results[task_id].get("status") != "failed":
                for finding in task_results[task_id].get("suspected_findings") or []:
                    on_finding(finding, task, logger.get_session_path())

    newly_completed = []
    for task in new_tasks:
        tid = task["task_id"]
        if tid in task_results:
            newly_completed.append({
                "task_id": tid,
                "type": task.get("type"),
                "specialist_id": task.get("specialist_id"),
                "prompt_version": task.get("prompt_version"),
                "scope_files": task.get("scope_files") or [],
                "session_id": task_results[tid].get("session_id"),
                "result": task_results[tid],
            })
    return newly_completed


def run_analysis(firmware_path: str, settings: dict, resume_from: str | None = None,
                 patched_firmware_path: str | None = None, *,
                 all_files: bool = False, on_finding=None, on_extracted=None,
                 specialists: bool = False, task_runner=None, task_reconcile=None):
    firmware_path = str(Path(firmware_path).resolve())
    if patched_firmware_path:
        patched_firmware_path = str(Path(patched_firmware_path).resolve())
    cfg_analysis = settings["analysis"]
    cfg_orch = settings["orchestrator"]
    cfg_worker = settings["worker"]

    sessions_dir = cfg_analysis["sessions_dir"]
    max_iterations = cfg_analysis["max_iterations"]
    parallel_limit = cfg_worker["parallel_limit"]
    if parallel_limit < 1:
        raise ValueError("worker.parallel_limit must be positive")
    research_minutes = float(cfg_analysis.get("research_minutes", 0))
    if not math.isfinite(research_minutes) or research_minutes < 0:
        raise ValueError("analysis.research_minutes must be a finite nonnegative number")

    firmware_name = Path(firmware_path).stem
    logger = ConversationLogger(sessions_dir, firmware_name, resume_from=resume_from)

    _bar(f"Firmware Analysis: {firmware_path}")

    print("\n[*] Collecting basic firmware information...")
    firmware_info = analyze_firmware(firmware_path)
    if resume_from:
        verify_resume_firmware(resume_from, firmware_info)
    print(f"    Type  : {firmware_info['file_type']}")
    print(f"    Size  : {firmware_info['size_bytes']:,} bytes")
    print(f"    MD5   : {firmware_info['hashes']['md5']}")
    print(f"    SHA256: {firmware_info['hashes']['sha256']}")
    print(f"    Strings: {len(firmware_info['strings_sample'])} strings (sample)")
    if firmware_info["binwalk"]:
        print(f"    Binwalk: {len(firmware_info['binwalk'].splitlines())} lines")

    # Save the identity before extraction so an interrupted extraction can resume.
    logger.save_firmware_info(firmware_info)
    _bar("Firmware Extraction")
    extraction = extract_firmware(
        firmware_path, logger.get_session_path(),
        firmware_info["hashes"]["sha256"],
        timeout=cfg_analysis.get("extraction_timeout_sec", 300),
    )
    firmware_info["extraction"] = extraction
    logger.save_firmware_info(firmware_info)
    if extraction["status"] != "complete":
        raise ExtractionError(extraction["error"])
    extracted_dir = str(Path(extraction["output_dir"]).resolve())
    if on_extracted:
        on_extracted(logger.get_session_path(), firmware_info, extracted_dir)
    print(f"[*] Extracted files: {extraction['file_count']}")
    print(f"[*] Extracted directory: {extracted_dir}")
    if extraction.get("reused"):
        print("[*] Reused verified extraction from this session")
    started_at = datetime.now(timezone.utc)
    started_clock = time.monotonic()
    deadline = started_clock + research_minutes * 60 if research_minutes else None

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
            logger.save_firmware_info(firmware_info)

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
    def new_worker() -> Worker:
        return Worker(
            model=cfg_worker["model"],
            reasoning_effort=cfg_worker.get("reasoning_effort", "high"),
            bypass_approvals=cfg_worker.get("bypass_approvals", False),
            sandbox_permissions=cfg_worker.get("sandbox_permissions", []),
            network_access=cfg_worker.get("network_access", False),
            sandbox=cfg_worker.get("sandbox", "read-only"),
            logger=logger,
        )
    worker = new_worker()
    (logger.get_session_path() / "research_artifacts").mkdir(exist_ok=True)
    session_mgr = SessionManager()
    session_mgr.restore(completed_tasks)

    inventory = file_inventory(extracted_dir)
    scope_extras = {}
    if specialists:
        sweep_tasks, scope_extras = plan_specialists(inventory, extracted_dir)
        code_files = [entry["path"] for entry in inventory if entry["status"] == "pending"]
    else:
        sweep_tasks, code_files = scan_tasks(
            extracted_dir, files_per_task=(1 if all_files else cfg_analysis.get("scan_files_per_task", 4)),
            all_files=all_files,
        )
    specialist_workers = ({identifier: new_worker() for identifier in {
        task["specialist_id"] for task in sweep_tasks}}
        if specialists else {})

    def selected_runner(default_worker, task, session_id, firmware, extracted):
        assigned = specialist_workers.get(task.get("specialist_id"), default_worker)
        if task_runner:
            return task_runner(assigned, task, session_id, firmware, extracted)
        return assigned.execute(task, session_id, firmware, extracted)
    scope_path = logger.get_session_path() / "scan_scope.json"
    if resume_from and scope_path.exists():
        previous_scope = json.loads(scope_path.read_text(encoding="utf-8"))
        if previous_scope.get("targets") != code_files:
            raise ExtractionError("extracted code files changed since the saved scan scope")
        if specialists:
            save_scan_scope(logger.get_session_path(), sweep_tasks, code_files,
                            inventory=inventory, **scope_extras)
    else:
        save_scan_scope(logger.get_session_path(), sweep_tasks, code_files,
                        inventory=inventory, **scope_extras)
    if specialists and resume_from:
        planned = {task["task_id"]: task for task in sweep_tasks}
        planned.update({task["task_id"]: task for task in followup_tasks(completed_tasks)})
        for saved in completed_tasks:
            task = planned.get(saved.get("task_id"))
            if task is None:
                continue
            missing_task_log = not saved.get("type")
            for field in ("type", "specialist_id", "prompt_version", "scope_files"):
                saved[field] = task.get(field)
            result = saved.get("result") or {}
            result["specialist_id"] = task["specialist_id"]
            result["prompt_version"] = task["prompt_version"]
            if task_reconcile and result.get("status") == "completed":
                result = task_reconcile(task, result) or result
                saved["result"] = result
            if missing_task_log:
                logger.log_task_result(task, result)
    goal_prompt = logger.get_session_path() / "GOAL_PROMPT.txt"
    specialist_goal = (
        "Use the fixed specialist catalog and file routing in scan_scope.json. "
        "A no_applicable_clue routing decision is a local heuristic, not proof that a file is safe. "
        "Use task_results.jsonl and research_status.json to identify unfinished specialist "
        "work; preserve each finding's disposition and separate static evidence from "
        "executed verification. Do not repeat completed specialist jobs. "
        if specialists else ""
    )
    goal_network_rule = (
        "Consult primary vendor or project sources when useful, but never upload firmware "
        "or extracted content. " if cfg_worker.get("network_access", False) else
        "Do not use the network or live targets without separate authorization. "
    )
    goal_prompt.write_text(
        "/goal Produce an evidence-backed security audit of the extracted firmware in "
        f"{logger.get_session_path().resolve()}. Read firmware_info.json, scan_scope.json, "
        "task_results.jsonl, and the extracted files. For every suspicious location, "
        "check its entry point, data flow, guards, counterevidence, impact, and remaining "
        "unknowns. Review configuration and component risks even if the first code scan "
        "found nothing. Save a Korean audit to research_artifacts/audit.md and a "
        "prioritized Detective handoff to research_artifacts/detective_handoff.md. "
        "For each handoff candidate include the exact code location, observed evidence, "
        "reachability conditions, counterevidence, and the next safe verification. "
        f"{specialist_goal}"
        "Cite exact local files and offsets; distinguish static "
        "evidence from executed verification. Keep original firmware and extracted files "
        f"unchanged. {goal_network_rule}"
        "Finish when each candidate has an evidence-backed disposition or an explicit "
        "blocker, and the remaining coverage limits are recorded.\n",
        encoding="utf-8",
    )
    print(f"[*] Interactive Codex /goal prompt: {goal_prompt}")
    completed_ids = {task.get("task_id") for task in completed_tasks
                     if ((task.get("result") or {}).get("status") == "completed"
                         if specialists else
                         (task.get("result") or {}).get("status") != "failed")}
    if on_finding:
        for saved in completed_tasks:
            if specialists and saved.get("type") not in {"specialist_analysis", "specialist_followup"}:
                continue
            for finding in (saved.get("result") or {}).get("suspected_findings") or []:
                on_finding(finding, saved, logger.get_session_path())
    pending_sweep = [task for task in sweep_tasks
                     if task["task_id"] not in completed_ids]
    scope_label = "Extracted files" if all_files or specialists else "Code files"
    print(f"[*] {scope_label} in scan scope: {len(code_files)}; "
          f"pending review tasks: {len(pending_sweep)}")
    def budget_available() -> bool:
        return deadline is None or time.monotonic() < deadline

    def dispatch_stage(tasks: list[dict], label: str) -> None:
        for start in range(0, len(tasks), parallel_limit):
            if not budget_available():
                return
            batch = tasks[start:start + parallel_limit]
            _bar(f"{label}  |  tasks {start + 1}-{start + len(batch)}")
            completed_tasks.extend(_dispatch_tasks(
                batch, worker, session_mgr, firmware_path, extracted_dir, logger,
                parallel_limit, cfg_worker, on_finding,
                selected_runner if specialists else task_runner,
            ))

    dispatch_stage(pending_sweep, "Specialist Review" if specialists else "Code Review Sweep")

    if specialists and budget_available():
        completed_ids = {task.get("task_id") for task in completed_tasks
                         if (task.get("result") or {}).get("status") == "completed"}
        latest_tasks = list({task.get("task_id"): task for task in completed_tasks}.values())
        pending_followups = [task for task in followup_tasks(latest_tasks)
                             if task["task_id"] not in completed_ids]
        dispatch_stage(pending_followups, "Specialist Static Follow-up")

    pending_baseline = []
    pending_finding_research = []
    if not specialists and cfg_analysis.get("deep_research_enabled", True):
        completed_ids = {task.get("task_id") for task in completed_tasks
                         if (task.get("result") or {}).get("status") != "failed"}
        pending_baseline = [task for task in baseline_tasks()
                            if task["task_id"] not in completed_ids]
        dispatch_stage(pending_baseline, "System Research")
        completed_ids = {task.get("task_id") for task in completed_tasks
                         if (task.get("result") or {}).get("status") != "failed"}
        pending_finding_research = [task for task in finding_research_tasks(completed_tasks)
                                    if task["task_id"] not in completed_ids]
        dispatch_stage(pending_finding_research, "Finding Research")

    stop_reason = "specialist_sweep_complete" if specialists else "iteration_limit"
    while not specialists and iteration < max_iterations and budget_available():
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
                stop_reason = "orchestrator_error"
                break
            logger.save_roadmap(roadmap)

        summary = roadmap.get("analysis_summary", "")
        status = roadmap.get("status", "unknown")
        print(f"\n[Orchestrator] {summary[:300]}")
        print(f"[Orchestrator] Status: {status}")

        if status == "complete":
            stop_reason = "evidence_complete"
            _bar("Analysis Complete")
            conclusion = roadmap.get("conclusion")
            if conclusion:
                print(f"\n{conclusion}")
            break

        new_tasks = roadmap.get("new_tasks") or []
        if not new_tasks:
            print("[!] Codex returned no new tasks. Stopping.")
            stop_reason = "no_new_tasks"
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

        dispatch_stage(new_tasks, "Codex Workers")

    if not budget_available() and stop_reason != "evidence_complete":
        stop_reason = "time_budget_reached"
        print("[*] Research time budget reached; remaining work is recorded for resume")

    latest_tasks = list({task.get("task_id"): task for task in completed_tasks}.values())
    if specialists and stop_reason == "specialist_sweep_complete" and any(
            (task.get("result") or {}).get("status") in {"partial", "failed"}
            for task in latest_tasks if task.get("type", "").startswith("specialist_")):
        stop_reason = "specialist_incomplete"

    stage_ids = {task.get("task_id") for task in completed_tasks}
    all_finding_tasks = (finding_research_tasks(completed_tasks)
                         if cfg_analysis.get("deep_research_enabled", True) else [])
    research_status = {
        "scan_scope_kind": "specialists" if specialists else
                           ("all_files" if all_files else "code_files"),
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "requested_minutes": research_minutes,
        "elapsed_seconds": round(time.monotonic() - started_clock, 2),
        "stop_reason": stop_reason,
        "code_tasks_recorded": sum(task["task_id"] in stage_ids for task in sweep_tasks),
        "code_tasks_total": len(sweep_tasks),
        "file_tasks_total": len(sweep_tasks) if all_files else None,
        "specialist_tasks_total": len(sweep_tasks) if specialists else None,
        "specialist_tasks_recorded": sum(task["task_id"] in stage_ids for task in sweep_tasks)
        if specialists else None,
        "no_applicable_clue_files": sum(
            item.get("status") == "no_applicable_clue"
            for item in scope_extras.get("file_routing", [])) if specialists else None,
        "baseline_tasks_recorded": sum(task["task_id"] in stage_ids for task in baseline_tasks())
        if cfg_analysis.get("deep_research_enabled", True) else 0,
        "finding_tasks_recorded": sum(task["task_id"] in stage_ids for task in all_finding_tasks),
        "finding_tasks_planned": len(all_finding_tasks),
    }
    (logger.get_session_path() / "research_status.json").write_text(
        json.dumps(research_status, ensure_ascii=False, indent=2), encoding="utf-8"
    )


    _bar("Session Complete")
    session_path = logger.get_session_path()
    print(f"[*] Logs saved : {session_path}")
    print(f"[*] Iterations : {iteration}")
    print(f"[*] Tasks done : {len(completed_tasks)}")
    print(f"[*] Sessions   : {len(session_mgr.summary())}")

    if settings.get("report", {}).get("enabled", True):
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
    return session_path


def main():
    default_settings = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "settings.json"
    )
    parser = argparse.ArgumentParser(
        description="FBI Investigator — Codex 기반 펌웨어 취약점 분석"
    )
    parser.add_argument("firmware", help="분석 대상 펌웨어 바이너리 경로 (구버전/취약 버전)")
    parser.add_argument("--research-minutes", type=float, default=None,
                        help="이번 실행의 리서치 시간 예산(분). 진행 중인 작업은 완료 후 중단")
    parser.add_argument("--max-iterations", type=int, default=None,
                        help="세션의 최대 오케스트레이터 반복 횟수 재설정")
    parser.add_argument("--allow-network-research", action="store_true",
                        help="워커의 외부 1차 자료 조회 허용(펌웨어 업로드 금지)")
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
    if args.research_minutes is not None:
        settings["analysis"]["research_minutes"] = args.research_minutes
    if args.max_iterations is not None:
        if args.max_iterations < 1:
            parser.error("--max-iterations must be positive")
        settings["analysis"]["max_iterations"] = args.max_iterations
    if args.allow_network_research:
        settings["worker"]["network_access"] = True
    try:
        run_analysis(str(fw), settings, resume_from=args.resume,
                     patched_firmware_path=args.patched)
    except ExtractionError as exc:
        print(f"Error: firmware extraction failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
