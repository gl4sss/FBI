#!/usr/bin/env python3
"""Run the FBI stages as one bounded, resumable pipeline."""

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from assistant.main import run_assistant
from coordinator.state import StateStore, file_lock, job_key
from detective.main import run_detective
from investigator.main import run_analysis
from lab.main import run_lab
from shared.redaction import collect_secret_values, redact_record
from shared.validation import validate_specialist_scope
from shared.version import VERSION


ROOT = Path(__file__).resolve().parent.parent


def _settings(stage: str) -> dict:
    return json.loads((ROOT / stage / "settings.json").read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def _resume_session(sessions_dir: Path) -> str | None:
    logs = sorted(sessions_dir.glob("*/*/orchestrator_conversation.jsonl"))
    return str(logs[-1].parent) if logs else None


class Coordinator:
    def __init__(self, firmware: str | Path, state_root: str | Path = "./sessions/coordinator",
                 *, investigator_limit: int = 3, detective_limit: int = 2,
                 allow_network_research: bool = False, no_qemu: bool = False,
                 research_minutes: float | None = None, max_iterations: int | None = None,
                 max_specialist_tasks: int | None = None):
        self.firmware = Path(firmware).resolve()
        self.firmware_sha256 = _sha256(self.firmware)
        self.state_root = Path(state_root).resolve()
        self.resource_lock_dir = ROOT / "sessions" / ".locks"
        self.directory = self.state_root / self.firmware_sha256
        self.state = StateStore(self.directory)
        self.allow_network_research = allow_network_research
        self.no_qemu = no_qemu
        self.investigator_limit = investigator_limit
        self.detective_limit = detective_limit
        self.research_minutes = research_minutes
        self.max_iterations = max_iterations
        self.max_specialist_tasks = max_specialist_tasks
        self._mutex = threading.Lock()
        self._submitted: set[tuple[str, str]] = set()
        self._detective_pool = None
        self._lab_pool = None
        self._assistant_pool = None
        self._lab_futures = {}
        self._assistant_futures = {}
        self.extracted_dir = None
        self.investigator_session = None
        self.started_clock = None
        self.first_detective_start_seconds = None

    def _manifest(self) -> dict:
        path = self.directory / "coordinator.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def _resume_investigator_session(self) -> str | None:
        prior = self._manifest().get("investigator_session")
        candidates = ([Path(prior)] if prior else []) + sorted(
            (self.directory / "investigator").glob("*/*"), reverse=True)
        for session in candidates:
            info = session / "firmware_info.json"
            if not info.is_file():
                continue
            try:
                saved = json.loads(info.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if (saved.get("hashes") or {}).get("sha256") == self.firmware_sha256:
                return str(session)
        return None

    def _on_extracted(self, session: Path, firmware_info: dict, extracted_dir: str) -> None:
        self.extracted_dir = extracted_dir
        self.investigator_session = str(session)
        _atomic_json(self.directory / "coordinator.json", {
            "firmware": str(self.firmware), "firmware_sha256": self.firmware_sha256,
            "investigator_session": str(session), "extracted_dir": extracted_dir,
        })
        if not self.no_qemu:
            for job in self.state.list_jobs("lab"):
                if job["status"] != "complete":
                    settings = _settings("lab")
                    settings["analysis"]["sessions_dir"] = str(self.directory / "lab" / job["key"])
                    settings.setdefault("environment", {})["output_dir"] = str(
                        self.directory / "lab_artifacts" / job["key"])
                    with self._mutex:
                        if job["key"] not in self._lab_futures:
                            self._lab_futures[job["key"]] = self._lab_pool.submit(
                                self._lab_job, job["key"], job["payload"], settings)
        for job in self.state.list_jobs("detective"):
            if job["status"] != "complete":
                self._submit_detective(job["key"], job["payload"])

    def _on_finding(self, finding: dict, task: dict, session: Path) -> None:
        location = finding.get("location") or "unlocated"
        evidence = finding.get("evidence") or []
        source_files = task.get("scope_files") or []
        file_path = finding.get("file_path") or next(
            (path for path in source_files if path in location), "")
        line_or_offset = finding.get("line_or_offset") or ""
        if not line_or_offset:
            match = re.search(r"(?::|\+)(0x[0-9a-fA-F]+|\d+)(?:\b|$)", location)
            line_or_offset = match.group(1) if match else ""
        relative_location = (
            "<extracted>" + location[len(self.extracted_dir):]
            if self.extracted_dir and location.startswith(self.extracted_dir)
            else location
        )
        relative_file = (
            "<extracted>" + file_path[len(self.extracted_dir):]
            if self.extracted_dir and file_path.startswith(self.extracted_dir)
            else file_path
        )
        identity = (f"{relative_file}:{line_or_offset}" if relative_file and line_or_offset
                    else relative_location if location != "unlocated" else
                    finding.get("finding_id", task["task_id"]))
        key = job_key(self.firmware_sha256, identity)
        specialist_id = task.get("specialist_id") or finding.get("specialist_id")
        disposition = finding.get("disposition") or "needs_dynamic_verification"
        handoff = {
            "stable_id": key, "finding_id": finding["finding_id"],
            "source_task": task["task_id"], "location": location,
            "file_path": file_path, "line_or_offset": line_or_offset,
            "specialist_id": specialist_id, "disposition": disposition,
            "prompt_version": task.get("prompt_version"),
            "input_path": finding.get("input_path", ""),
            "use_path": finding.get("use_path", ""),
            "root_cause": finding.get("root_cause", ""),
            "impact_tags": finding.get("impact_tags") or [],
            "title": finding.get("title", ""),
            "category": finding.get("category", ""),
            "observation": finding.get("observation", ""), "evidence": evidence,
            "inference": finding.get("inference", ""),
            "entry_conditions": finding.get("entry_conditions") or [],
            "counterevidence": finding.get("counterevidence") or [],
            "unknowns": (finding.get("unknowns") or []) +
                        (["Exact line or offset is not yet established"] if not line_or_offset else []) +
                        (["Direct observation evidence is missing"] if not evidence else []),
            "investigator_session": str(session),
        }
        handoff = redact_record(handoff)
        finding_key = job_key(self.firmware_sha256, specialist_id or "legacy",
                              task["task_id"], identity)
        self.state.enqueue("finding", finding_key, handoff)
        self.state.finish("finding", finding_key, "complete", handoff)
        if specialist_id and disposition != "needs_dynamic_verification":
            return
        self.state.enqueue("detective", key, handoff)
        self._submit_detective(key, handoff)

    def _run_specialist_task(self, worker, task: dict, session_id: str | None,
                             firmware_path: str, extracted_dir: str) -> dict:
        key, payload = self._specialist_identity(task)
        with self.state.claim("specialist", key, payload) as lease:
            if lease is None:
                saved = self.state.get("specialist", key)
                if saved and saved["status"] == "complete" and saved["result"]:
                    return saved["result"]
                raise RuntimeError("Specialist task is already running")
            secret_values = (collect_secret_values(task.get("scope_files") or [])
                             if task.get("specialist_id") == "secrets" else ())
            result = redact_record(
                worker.execute(task, session_id, firmware_path, extracted_dir), secret_values)
            validate_specialist_scope(result, extracted_dir, task.get("scope_files"))
            self.state.finish("specialist", key,
                              "complete" if result.get("status") == "completed" else "failed",
                              result)
            return result

    def _specialist_identity(self, task: dict) -> tuple[str, dict]:
        specialist_id = task.get("specialist_id")
        scope_file = (task.get("scope_files") or [""])[0]
        key = job_key(self.firmware_sha256, specialist_id or "unknown",
                      scope_file, task.get("prompt_version") or "", task["task_id"])
        payload = {"task_id": task["task_id"], "specialist_id": specialist_id,
                   "file_path": scope_file, "prompt_version": task.get("prompt_version")}
        return key, payload

    def _reconcile_specialist_task(self, task: dict, result: dict) -> dict:
        key, payload = self._specialist_identity(task)
        secret_values = (collect_secret_values(task.get("scope_files") or [])
                         if task.get("specialist_id") == "secrets" else ())
        safe_result = redact_record(result, secret_values)
        if self.extracted_dir:
            validate_specialist_scope(safe_result, self.extracted_dir,
                                      task.get("scope_files"))
        with self.state.claim("specialist", key, payload) as lease:
            if lease is None:
                return safe_result
            self.state.finish("specialist", key,
                              "complete" if safe_result.get("status") == "completed" else "failed",
                              safe_result)
        return safe_result

    def _submit_detective(self, key: str, handoff: dict) -> None:
        with self._mutex:
            pair = ("detective", key)
            if pair in self._submitted:
                return
            self._submitted.add(pair)
        self._detective_pool.submit(self._detective_job, key, handoff)

    def _lab_request(self, firmware_path: str, firmware_info: dict) -> dict:
        settings = _settings("lab")
        key = job_key(self.firmware_sha256, json.dumps(settings.get("environment", {}), sort_keys=True))
        settings["analysis"]["sessions_dir"] = str(self.directory / "lab" / key)
        settings.setdefault("environment", {})["output_dir"] = str(
            self.directory / "lab_artifacts" / key)
        payload = {"firmware": firmware_path, "firmware_sha256": self.firmware_sha256,
                   "environment": settings.get("environment", {})}
        self.state.enqueue("lab", key, payload)
        saved = self.state.get("lab", key)
        if saved["status"] == "complete":
            return saved["result"] or {}
        with self._mutex:
            future = self._lab_futures.get(key)
            if future is None:
                future = self._lab_pool.submit(self._lab_job, key, payload, settings)
                self._lab_futures[key] = future
        try:
            return future.result() or {}
        except Exception as exc:
            return {"status": "failed", "error": str(exc)}

    def _lab_job(self, key: str, payload: dict, settings: dict) -> dict:
        with self.state.claim("lab", key, payload) as lease:
            if lease is None:
                return (self.state.get("lab", key) or {}).get("result") or {}
            with file_lock(self.resource_lock_dir,
                           "qemu-host-ports", blocking=True):
                result = run_lab(str(self.firmware), settings,
                                 resume_from=_resume_session(Path(settings["analysis"]["sessions_dir"])),
                                 return_details=True)
            self.state.finish("lab", key,
                              "failed" if result.get("status") == "failed" else "complete",
                              result)
            return result

    def _detective_job(self, key: str, handoff: dict) -> None:
        try:
            with self.state.claim("detective", key, handoff) as lease:
                if lease is None:
                    return
                with self._mutex:
                    if self.first_detective_start_seconds is None and self.started_clock is not None:
                        self.first_detective_start_seconds = round(
                            time.monotonic() - self.started_clock, 3)
                settings = _settings("detective")
                settings["analysis"]["sessions_dir"] = str(self.directory / "detective" / key)
                settings["analysis"]["qemu_lock_dir"] = str(self.resource_lock_dir)
                settings.setdefault("report", {})["enabled"] = False
                attempt = self.state.get("detective", key)["attempts"]
                settings.setdefault("qemu", {})["poc_output_dir"] = str(
                    self.directory / "poc_artifacts" / key / f"attempt_{attempt}")
                result = run_detective(
                    handoff["investigator_session"], settings,
                    firmware_path=str(self.firmware), no_qemu=self.no_qemu,
                    finding_ids={handoff["finding_id"]}, lab_request=self._lab_request,
                    handoff=handoff,
                )
                if (result.get("lab") or {}).get("status") == "failed" and not result.get("confirmed_vulns"):
                    self.state.finish("detective", key, "failed", result)
                    return
                self.state.finish("detective", key, "complete", result)
                if result.get("confirmed_vulns"):
                    self._schedule_assistant()
        except Exception as exc:
            print(f"[Coordinator] Detective {key[:12]} failed: {exc}", file=sys.stderr)

    def _confirmed_set(self) -> tuple[list[dict], list[str]]:
        claims = {}
        source_sessions = []
        for job in self.state.list_jobs("detective"):
            if job["status"] != "complete" or not job["result"]:
                continue
            result = job["result"]
            for claim in result.get("confirmed_vulns") or []:
                if claim.get("vuln_id"):
                    global_id = f"FBI-{job['key'][:12]}-{claim['vuln_id']}"
                    claims[global_id] = {
                        **claim, "vuln_id": global_id,
                        "detective_vuln_id": claim["vuln_id"],
                        "source_finding_id": job["payload"]["finding_id"],
                        "stable_finding_id": job["key"],
                    }
                    source_sessions.append(result["session_path"])
        return list(claims.values()), sorted(set(source_sessions))

    def _schedule_assistant(self) -> None:
        if not self.investigator_session:
            return
        claims, sessions = self._confirmed_set()
        if not claims:
            return
        key = job_key(self.firmware_sha256,
                      *sorted(claim["vuln_id"] for claim in claims))
        payload = {"confirmed_vulns": claims, "detective_sessions": sessions}
        self.state.enqueue("assistant", key, payload)
        with self._mutex:
            if key in self._assistant_futures:
                return
            self._assistant_futures[key] = self._assistant_pool.submit(
                self._assistant_job, key, payload)

    def _assistant_job(self, key: str, payload: dict) -> None:
        try:
            with self.state.claim("assistant", key, payload) as lease:
                if lease is None:
                    return
                input_dir = self.directory / "assistant_inputs" / key
                input_dir.mkdir(parents=True, exist_ok=True)
                _atomic_json(input_dir / "detective_session.json", {
                    "confirmed_vulns": payload["confirmed_vulns"]})
                firmware_info = Path(self.investigator_session) / "firmware_info.json"
                if firmware_info.exists():
                    shutil.copyfile(firmware_info, input_dir / "firmware_info.json")
                logs = input_dir / "codex_sessions"
                logs.mkdir(exist_ok=True)
                guides = input_dir / "trigger_guides"
                guides.mkdir(exist_ok=True)
                for index, session in enumerate(payload["detective_sessions"]):
                    for source in (Path(session) / "codex_sessions").glob("*.jsonl"):
                        shutil.copyfile(source, logs / f"{index}_{source.name}")
                    for source in (Path(session) / "trigger_guides").glob("*.md"):
                        shutil.copyfile(source, guides / f"{index}_{source.name}")
                settings = _settings("assistant")
                settings["analysis"]["sessions_dir"] = str(self.directory / "assistant" / key)
                settings.setdefault("exploit", {})["output_dir"] = str(
                    self.directory / "assistant_artifacts" / key)
                result = run_assistant(
                    str(input_dir), settings, firmware_path=str(self.firmware),
                    resume_session_dir=_resume_session(Path(settings["analysis"]["sessions_dir"])),
                )
                self.state.finish("assistant", key, "complete", result)
        except Exception as exc:
            print(f"[Coordinator] Assistant {key[:12]} failed: {exc}", file=sys.stderr)

    def run(self) -> dict:
        with file_lock(self.resource_lock_dir,
                       f"firmware:{self.firmware_sha256}") as locked:
            if not locked:
                raise RuntimeError("This firmware is already being processed by another coordinator")
            self.started_clock = time.monotonic()
            with ThreadPoolExecutor(max_workers=self.detective_limit) as detective_pool, \
                 ThreadPoolExecutor(max_workers=1) as lab_pool, \
                 ThreadPoolExecutor(max_workers=1) as assistant_pool:
                self._detective_pool = detective_pool
                self._lab_pool = lab_pool
                self._assistant_pool = assistant_pool
                settings = _settings("investigator")
                settings["worker"]["parallel_limit"] = self.investigator_limit
                settings["worker"]["network_access"] = self.allow_network_research
                settings["analysis"]["sessions_dir"] = str(self.directory / "investigator")
                settings.setdefault("report", {})["enabled"] = False
                if self.research_minutes is not None:
                    settings["analysis"]["research_minutes"] = self.research_minutes
                if self.max_iterations is not None:
                    settings["analysis"]["max_iterations"] = self.max_iterations
                if self.max_specialist_tasks is not None:
                    settings["analysis"]["max_specialist_tasks_per_run"] = self.max_specialist_tasks
                resume = self._resume_investigator_session()
                analysis_error = None
                self.state.start("investigator", self.firmware_sha256,
                                 {"firmware": str(self.firmware), "resume": resume})
                try:
                    run_analysis(str(self.firmware), settings, resume_from=resume,
                                 all_files=True, specialists=True,
                                 on_finding=self._on_finding,
                                 on_extracted=self._on_extracted,
                                 task_runner=self._run_specialist_task,
                                 task_reconcile=self._reconcile_specialist_task)
                    stop_reason = None
                    if self.investigator_session:
                        research_path = Path(self.investigator_session) / "research_status.json"
                        if research_path.exists():
                            research = json.loads(research_path.read_text(encoding="utf-8"))
                            stop_reason = research.get("stop_reason")
                            if stop_reason == "orchestrator_error":
                                raise RuntimeError("Investigator orchestrator failed; rerun to resume")
                    incomplete = stop_reason in {
                        "specialist_incomplete", "specialist_task_budget_reached",
                        "time_budget_reached",
                    }
                    self.state.finish("investigator", self.firmware_sha256,
                                      "partial" if incomplete else "complete",
                                      {"session_path": self.investigator_session,
                                       "stop_reason": stop_reason})
                    if incomplete:
                        print(f"[Coordinator] Investigator remains partial: {stop_reason}. "
                              "Run the same command to continue.")
                except Exception as exc:
                    analysis_error = exc
                    if not self.investigator_session:
                        extracted_manifests = sorted(Path(settings["analysis"]["sessions_dir"]).glob(
                            "*/*/extraction.json"))
                        if extracted_manifests:
                            self.investigator_session = str(extracted_manifests[-1].parent)
                    self.state.finish("investigator", self.firmware_sha256, "failed",
                                      {"error": str(exc),
                                       "session_path": self.investigator_session})
                finally:
                    detective_pool.shutdown(wait=True)
                    lab_pool.shutdown(wait=True)
                    self._schedule_assistant()
                    assistant_pool.shutdown(wait=True)
            summary = self.state.summary()
            status = {
                "firmware_sha256": self.firmware_sha256,
                "investigator_session": self.investigator_session,
                "stages": summary,
                "jobs": self.state.list_jobs(),
                "investigator_error": str(analysis_error) if analysis_error else None,
                "first_detective_start_seconds": self.first_detective_start_seconds,
                "elapsed_seconds": round(time.monotonic() - self.started_clock, 3),
            }
            _atomic_json(self.directory / "pipeline_status.json", status)
            if self.investigator_session:
                _atomic_json(Path(self.investigator_session) / "coordinator_status.json", status)
                if analysis_error is None:
                    try:
                        from report_generator import generate_report
                        status["report"] = generate_report(self.investigator_session)
                    except Exception as exc:
                        status["report_error"] = str(exc)
                    _atomic_json(self.directory / "pipeline_status.json", status)
            if analysis_error:
                raise analysis_error
            return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Integrated FBI firmware analysis")
    parser.add_argument("--version", action="version", version=f"FBI {VERSION}")
    parser.add_argument("firmware", help="Firmware image to inspect")
    parser.add_argument("--state-root", default="./sessions/coordinator")
    parser.add_argument("--investigator-workers", type=int, default=3)
    parser.add_argument("--detective-workers", type=int, default=2)
    parser.add_argument("--allow-network-research", action="store_true")
    parser.add_argument("--no-qemu", action="store_true")
    parser.add_argument("--research-minutes", type=float, default=None)
    parser.add_argument("--max-iterations", type=int, default=None)
    parser.add_argument("--max-specialist-tasks", type=int, default=None,
                        help="Per-run specialist task limit (0 means unlimited)")
    args = parser.parse_args()
    if args.investigator_workers < 1 or args.detective_workers < 1:
        parser.error("worker limits must be positive")
    if args.max_iterations is not None and args.max_iterations < 1:
        parser.error("--max-iterations must be positive")
    if args.research_minutes is not None and (
            not math.isfinite(args.research_minutes) or args.research_minutes < 0):
        parser.error("--research-minutes must be a finite nonnegative number")
    if args.max_specialist_tasks is not None and args.max_specialist_tasks < 0:
        parser.error("--max-specialist-tasks must be nonnegative")
    result = Coordinator(args.firmware, args.state_root,
                         investigator_limit=args.investigator_workers,
                         detective_limit=args.detective_workers,
                         allow_network_research=args.allow_network_research,
                         no_qemu=args.no_qemu,
                         research_minutes=args.research_minutes,
                         max_iterations=args.max_iterations,
                         max_specialist_tasks=args.max_specialist_tasks).run()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
