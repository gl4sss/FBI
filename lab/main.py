#!/usr/bin/env python3
"""
FBI — Lab
동적 분석 환경 자동 구축: QEMU 에뮬레이션, 루트 파일시스템 추출,
GDB 서버, chroot, 네트워크 설정 등을 Codex로 자동 구성합니다.

Usage:
  python lab/main.py firmware.bin
  python lab/main.py firmware.bin --resume sessions/lab/firmware/20260630_...
  python lab/main.py firmware.bin --env-only   # lab_env.json만 출력 (다른 모듈에서 참조용)
"""
import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lab.orchestrator import LabOrchestrator
from lab.worker import LabWorker
from lab.env_manager import LabEnvManager
from investigator.firmware_utils import analyze_firmware
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
    """저장된 lab 세션에서 상태 복원."""
    sp = Path(session_dir)
    cl_path = sp / "orchestrator_conversation.jsonl"
    if not cl_path.exists():
        raise FileNotFoundError(f"Session log not found: {cl_path}")

    entries = []
    with open(cl_path, encoding="utf-8") as f:
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
            completed_tasks = (entry["content"].get("completed_tasks")
                               or entry["content"].get("new_results") or [])
        elif entry["role"] == "assistant":
            last_assistant = entry["content"]
            used_iterations += 1
            if entry.get("orchestrator_session_id"):
                orchestrator_session_id = entry["orchestrator_session_id"]

    completed_tasks = load_completed_tasks(session_dir, completed_tasks)
    pending_roadmap = None
    if last_assistant:
        completed_ids = {t.get("task_id") for t in completed_tasks}
        pending = [t for t in last_assistant.get("new_tasks", [])
                   if t.get("task_id") not in completed_ids]
        if pending:
            pending_roadmap = dict(last_assistant)
            pending_roadmap["new_tasks"] = pending

    return completed_tasks, pending_roadmap, used_iterations, orchestrator_session_id


def _dispatch_tasks(new_tasks, worker, session_mgr, firmware_path,
                    env_mgr, parallel_limit) -> list[dict]:
    task_results: dict[str, dict] = {}
    current_env = env_mgr.summary()

    with ThreadPoolExecutor(max_workers=parallel_limit) as executor:
        futures = {}
        for task in new_tasks:
            existing_sid = session_mgr.get_session_id(
                task["task_id"], task.get("reuse_session_for")
            )
            fut = executor.submit(
                worker.execute, task, existing_sid, firmware_path, current_env
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
                print(f"\n[Codex] {task_id}  status={status_str}  session={short_sid}...")

                findings = result.get("findings") or []
                for f in findings[:3]:
                    print(f"        - {str(f)[:120]}")

                # 환경 상태 즉시 반영
                env_mgr.apply_task_result(task_id, result)
                env_summary = env_mgr.summary()

                status_icons = []
                if env_summary["arch"]:
                    status_icons.append(f"arch={env_summary['arch']}")
                if env_summary["rootfs_ready"]:
                    status_icons.append("rootfs ready")
                if env_summary["qemu_system_ready"]:
                    status_icons.append("qemu ready")
                if env_summary["chroot_ready"]:
                    status_icons.append("chroot ready")
                if env_summary["gdb_ready"]:
                    status_icons.append("gdb ready")
                if status_icons:
                    print(f"        Lab: {' | '.join(status_icons)}")

            except Exception as exc:
                print(f"[!] Task {task_id} failed: {exc}")
                task_results[task_id] = {
                    "task_id": task_id,
                    "status": "failed",
                    "environment_update": {},
                    "findings": [],
                    "analysis": str(exc),
                    "follow_up_needed": True,
                    "follow_up_reason": str(exc),
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


def run_lab(firmware_path: str, settings: dict,
            resume_from: str | None = None, env_only: bool = False,
            *, return_details: bool = False):
    cfg_analysis = settings["analysis"]
    cfg_orch = settings["orchestrator"]
    cfg_worker = settings["worker"]
    cfg_env = settings.get("environment", {})

    sessions_dir = cfg_analysis["sessions_dir"]
    max_iterations = cfg_analysis["max_iterations"]
    parallel_limit = cfg_worker["parallel_limit"]
    env_output_dir = cfg_env.get("output_dir", "./lab_environments")

    firmware_name = Path(firmware_path).stem

    _bar(f"FBI Lab — 동적 분석 환경 구축")
    print(f"[*] 펌웨어: {firmware_path}")

    print("\n[*] 펌웨어 기초 분석 중...")
    firmware_info = analyze_firmware(firmware_path)
    if resume_from:
        verify_resume_firmware(resume_from, firmware_info)
    print(f"    유형  : {firmware_info['file_type']}")
    print(f"    크기  : {firmware_info['size_bytes']:,} bytes")
    print(f"    MD5   : {firmware_info['hashes']['md5']}")
    if firmware_info["binwalk"]:
        print(f"    Binwalk: {len(firmware_info['binwalk'].splitlines())} lines")

    logger = ConversationLogger(sessions_dir, firmware_name, resume_from=resume_from)
    session_path = logger.get_session_path()
    logger.save_firmware_info(firmware_info)

    env_mgr = LabEnvManager(session_path, firmware_path)

    # MCP 설정
    cfg_mcp = settings.get("mcp", {})
    mcp = McpManager(
        servers=cfg_mcp.get("servers", []),
        apply_to=cfg_mcp.get("apply_to", []),
    )
    if mcp.servers:
        print(f"\n[MCP] {len(mcp.servers)}개 서버: "
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
        print(f"[Resume] Completed tasks: {len(completed_tasks)}")
        if resume_orchestrator_sid:
            print(f"[Resume] Codex session: {resume_orchestrator_sid[:20]}...")

    orchestrator = LabOrchestrator(
        model=cfg_orch["model"],
        reasoning_effort=cfg_orch.get("reasoning_effort", "medium"),
        logger=logger,
        resume_session_id=resume_orchestrator_sid,
        sent_task_ids=load_sent_task_ids(resume_from) if resume_from else None,
    )
    worker = LabWorker(
        model=cfg_worker["model"],
        reasoning_effort=cfg_worker.get("reasoning_effort", "high"),
        bypass_approvals=cfg_worker.get("bypass_approvals", False),
        sandbox_permissions=cfg_worker.get("sandbox_permissions", []),
        network_access=cfg_worker.get("network_access", False),
        logger=logger,
        env_output_dir=env_output_dir,
    )
    session_mgr = SessionManager()
    session_mgr.restore(completed_tasks)
    for task in completed_tasks:
        if task.get("result", {}).get("status") != "failed":
            env_mgr.apply_task_result(task["task_id"], task["result"])

    # -- 메인 루프 ------------------------------------------------------------
    last_status = "not_started"
    while iteration < max_iterations:
        iteration += 1

        if first_roadmap is not None:
            roadmap = first_roadmap
            first_roadmap = None
            _bar(f"Iteration {iteration}  |  Resuming saved roadmap")
        else:
            _bar(f"Iteration {iteration}  |  Lab Orchestrator ({cfg_orch['model']})")
            print("[*] 환경 구축 전략 수립 중...")
            try:
                roadmap = orchestrator.decide(firmware_info, completed_tasks)
            except Exception as exc:
                print(f"[!] Orchestrator error: {exc}")
                last_status = "failed"
                break
            logger.save_roadmap(roadmap)

        env_mgr.set_orchestrator_session_id(orchestrator.session_id)

        summary = roadmap.get("analysis_summary", "")
        status = roadmap.get("status", "unknown")
        last_status = status
        phase = roadmap.get("current_phase", "?")
        env_status = roadmap.get("environment_status", {})

        print(f"\n[Orchestrator] {summary[:300]}")
        print(f"[Orchestrator] Phase={phase}  Status={status}")

        # 환경 진행 상황 표시
        icons = []
        if env_status.get("arch"):
            icons.append(f"arch={env_status['arch']}")
        for k, label in [("rootfs_extracted","rootfs"), ("qemu_running","qemu"),
                          ("network_ready","net"), ("debug_ready","dbg"),
                          ("chroot_ready","chroot"), ("verified","verified")]:
            if env_status.get(k):
                icons.append(label)
        if icons:
            print(f"[Lab]    {' | '.join(icons)}")

        if status == "complete":
            _bar("환경 구축 완료")
            conclusion = roadmap.get("conclusion", "")
            if conclusion:
                print(f"\n{conclusion}")
            break

        if status == "blocked":
            reason = roadmap.get("blocked_reason", "unknown")
            print(f"\n[!] 환경 구축 차단됨: {reason}")
            print(f"    수동으로 문제를 해결한 뒤 --resume으로 재시작하거나")
            print(f"    codex resume {orchestrator.session_id} 로 직접 안내 받으세요.")
            break

        new_tasks = roadmap.get("new_tasks") or []
        if not new_tasks:
            print("[!] No new tasks. Stopping.")
            break

        print(f"\n[Orchestrator] Tasks ({len(new_tasks)}):")
        for t in new_tasks:
            print(f"  - {t.get('task_id','?')} [{t.get('priority','?'):6}] {t.get('type','?')}")

        _bar(f"Codex Lab Workers  |  {cfg_worker['model']}  |  parallel={parallel_limit}")

        newly = _dispatch_tasks(
            new_tasks, worker, session_mgr, firmware_path,
            env_mgr, parallel_limit,
        )
        completed_tasks.extend(newly)

        # 매 이터레이션 후 환경 저장
        env_mgr.save()


    # -- 최종 결과 저장 및 출력 -----------------------------------------------
    env_json_path, script_path = env_mgr.save()
    final_summary = env_mgr.summary()

    _bar("Lab 환경 구축 결과")
    print(f"[*] 세션 경로    : {session_path}")
    print(f"[*] 이터레이션   : {iteration}")
    print(f"[*] 완료 태스크  : {len(completed_tasks)}")

    print("\n구축된 환경")
    print(f"  아키텍처  : {final_summary.get('arch', '미감지')}")
    print(f"  OS 유형   : {final_summary.get('os_type', '미감지')}")
    print(f"  RootFS    : {final_summary.get('rootfs_path') if final_summary.get('rootfs_ready') else '미추출'}")
    print(f"  QEMU 시스템: {'준비됨' if final_summary.get('qemu_system_ready') else '미설정'}")
    print(f"  QEMU 유저 : {'준비됨' if final_summary.get('qemu_user_ready') else '미설정'}")
    print(f"  Chroot    : {'준비됨' if final_summary.get('chroot_ready') else '미설정'}")
    print(f"  GDB       : {'준비됨' if final_summary.get('gdb_ready') else '미설정'}")
    ports = final_summary.get("ports", {})
    if ports:
        print("  포트      : " + "  ".join(f"{k}={v}" for k, v in ports.items()))
    services = final_summary.get("services", [])
    if services:
        print(f"  서비스    : {', '.join(services)}")

    print(f"\n[파일]")
    print(f"  환경 명세  : {env_json_path}")
    print(f"  재현 스크립트: {script_path}")

    # Codex 세션 재개 안내
    if orchestrator.session_id:
        print(f"""
{'-'*64}
 Codex로 이어서 진행하기
{'-'*64}

 환경 구축 맥락을 이어받아 대화형으로 트러블슈팅할 수 있습니다.

   codex resume {orchestrator.session_id}

 예시:
   "QEMU가 부팅은 되는데 네트워크 연결이 안 돼. 해결해줘."
   "GDB로 httpd 프로세스에 어떻게 붙어?"
   "chroot 안에서 /usr/sbin/utelnetd를 실행하고 싶어."
   "investigator로 분석할 준비가 됐어. 다음 단계는?"

 세션 파일: {session_path}/lab_session.json
{'-'*64}""")

        # 세션 정보 파일 저장
        lab_session = {
            "orchestrator_session_id": orchestrator.session_id,
            "resume_command": f"codex resume {orchestrator.session_id}",
            "session_path": str(session_path),
            "env_json": str(env_json_path),
            "setup_script": str(script_path),
            "lab_summary": final_summary,
        }
        with open(session_path / "lab_session.json", "w", encoding="utf-8") as f:
            json.dump(lab_session, f, indent=2, ensure_ascii=False)

    # env-only 모드: lab_env.json 경로만 stdout으로 출력 (파이프 연계용)
    if env_only:
        print(f"\nLAB_ENV_JSON={env_json_path}")

    print()
    if return_details:
        return {"session_path": str(session_path), "environment": str(env_json_path),
                "setup_script": str(script_path), "summary": final_summary,
                "status": last_status}
    return str(env_json_path)


def main():
    default_settings = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "settings.json"
    )
    parser = argparse.ArgumentParser(
        description="FBI Lab — 펌웨어 동적 분석 환경 자동 구축 (QEMU, chroot, GDB, network)"
    )
    parser.add_argument("firmware", help="펌웨어 바이너리 경로")
    parser.add_argument("--settings", default=default_settings, help="lab/settings.json 경로")
    parser.add_argument(
        "--resume", metavar="SESSION_DIR",
        help="중단된 lab 세션 재개 (예: sessions/lab/firmware/20260630_...)",
    )
    parser.add_argument(
        "--env-only", action="store_true",
        help="LAB_ENV_JSON=<path> 형태로 경로만 출력 (investigator/detective 연계용)",
    )
    args = parser.parse_args()

    fw = Path(args.firmware)
    if not fw.exists():
        print(f"Error: firmware not found: {args.firmware}", file=sys.stderr)
        sys.exit(1)

    cfg_path = Path(args.settings)
    if not cfg_path.exists():
        print(f"Error: settings not found: {args.settings}", file=sys.stderr)
        sys.exit(1)

    if args.resume and not Path(args.resume).exists():
        print(f"Error: resume session not found: {args.resume}", file=sys.stderr)
        sys.exit(1)

    settings = load_settings(str(cfg_path))
    run_lab(str(fw), settings, resume_from=args.resume, env_only=args.env_only)


if __name__ == "__main__":
    main()
