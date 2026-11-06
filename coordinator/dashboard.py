#!/usr/bin/env python3
"""Serve a local, read-only view of live Coordinator jobs."""

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from investigator.specialists import SPECIALISTS
from shared.redaction import redact_text
from shared.version import VERSION


ASSET_DIR = Path(__file__).resolve().parent
ASSETS = {
    "/": ("dashboard.html", "text/html; charset=utf-8"),
    "/dashboard.css": ("dashboard.css", "text/css; charset=utf-8"),
    "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
}
JOB_KINDS = ("investigator", "specialist", "finding", "detective", "lab", "assistant")


def firmware_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _read_jobs(database: Path) -> list[dict]:
    if not database.is_file():
        return []
    try:
        # Read-only connection; the dashboard never starts or modifies a job.
        with sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True,
                             timeout=2) as connection:
            rows = connection.execute(
                "SELECT kind,key,status,payload,result,attempts,updated_at FROM jobs"
            ).fetchall()
    except (OSError, sqlite3.Error):
        return []
    jobs = []
    for kind, key, status, raw_payload, raw_result, attempts, updated_at in rows:
        if kind not in JOB_KINDS:
            continue
        try:
            payload = json.loads(raw_payload)
        except (TypeError, ValueError):
            payload = {}
        try:
            result = json.loads(raw_result) if kind in {"finding", "detective"} else None
        except (TypeError, ValueError):
            result = None
        if kind == "specialist" and status == "failed" and raw_result:
            try:
                saved = json.loads(raw_result)
            except (TypeError, ValueError):
                saved = None
            if isinstance(saved, dict) and saved.get("status") == "partial":
                status = "partial"
        jobs.append({"kind": kind, "key": key, "status": status,
                     "payload": payload if isinstance(payload, dict) else {},
                     "result": result if isinstance(result, dict) else {},
                     "attempts": attempts, "updated_at": updated_at})
    return jobs


def _public_label(value: object, fallback: str) -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    # Titles are model output. Keep credentials and absolute paths out of the browser.
    cleaned = redact_text(value.strip())
    cleaned = re.sub(r"(?<!\w)/(?:[^\s:/]+/)*[^\s:/]+", "[path]", cleaned)
    return cleaned[:160]


def _confirmed_vulnerabilities(jobs: list[dict]) -> tuple[int, list[dict]]:
    findings = {}
    for job in jobs:
        if job["kind"] != "finding" or job["status"] != "complete":
            continue
        finding = job["result"]
        if finding.get("disposition") != "static_verified":
            continue
        identifier = finding.get("stable_id") or job["key"]
        findings[(identifier, "static")] = {
            "id": str(identifier)[:12], "verification": "static",
            "title": _public_label(finding.get("title"), "제목 미기록"),
            "category": _public_label(finding.get("category"), "종류 미기록"),
            "file": Path(finding.get("file_path") or "").name,
            "line": _public_label(finding.get("line_or_offset"), ""),
            "cvss_score": None, "updated_at": job["updated_at"],
        }
    for job in jobs:
        if job["kind"] != "detective" or job["status"] != "complete":
            continue
        payload, result = job["payload"], job["result"]
        claims = result.get("confirmed_vulns") or []
        if not isinstance(claims, list):
            continue
        for claim in claims:
            if not isinstance(claim, dict) or claim.get("trigger_confirmed") is not True:
                continue
            score = claim.get("cvss_score")
            score = float(score) if isinstance(score, (int, float)) and 0 <= score <= 10 else None
            identifier = payload.get("stable_id") or job["key"]
            findings.pop((identifier, "static"), None)
            findings[(identifier, str(claim.get("vuln_id") or ""))] = {
                "id": f"{str(identifier)[:12]}-{_public_label(claim.get('vuln_id'), 'finding')}",
                "verification": "dynamic",
                "title": _public_label(claim.get("title"), _public_label(payload.get("title"), "제목 미기록")),
                "category": _public_label(payload.get("category"), "종류 미기록"),
                "file": Path(payload.get("file_path") or "").name,
                "line": _public_label(payload.get("line_or_offset"), ""),
                "cvss_score": score, "updated_at": job["updated_at"],
            }
    ordered = sorted(findings.values(), key=lambda item: (
        item["cvss_score"] is None, -(item["cvss_score"] or 0),
        item["verification"] != "dynamic", -item["updated_at"]))
    for item in ordered:
        item.pop("updated_at")
    return len(ordered), ordered[:100]


def read_snapshot(state_dir: str | Path) -> dict:
    """Return status and safe finding labels; no evidence, prompts, or secret values."""
    directory = Path(state_dir)
    jobs = _read_jobs(directory / "jobs.sqlite3")
    manifest = _read_json(directory / "coordinator.json")
    session = Path(manifest["investigator_session"]) if manifest.get("investigator_session") else None
    scope = _read_json(session / "scan_scope.json") if session else {}
    planned = {task.get("task_id"): task for task in scope.get("tasks", [])
               if isinstance(task, dict) and task.get("specialist_id") and task.get("task_id")}
    specialist_jobs = {job["payload"].get("task_id"): job
                       for job in jobs if job["kind"] == "specialist"
                       and job["payload"].get("task_id")}
    tasks_by_specialist = {identifier: [] for identifier, _ in SPECIALISTS}
    for task_id, task in planned.items():
        identifier = task["specialist_id"]
        if identifier not in tasks_by_specialist:
            continue
        job = specialist_jobs.get(task_id)
        tasks_by_specialist[identifier].append({
            "id": task_id, "file": Path((task.get("scope_files") or [""])[0]).name,
            "status": job["status"] if job else "pending",
            "attempts": job["attempts"] if job else 0,
        })
    # An interrupted run can leave jobs visible before scan_scope.json is saved.
    for task_id, job in specialist_jobs.items():
        if task_id in planned:
            continue
        identifier = job["payload"].get("specialist_id")
        if identifier in tasks_by_specialist:
            tasks_by_specialist[identifier].append({
                "id": task_id, "file": Path(job["payload"].get("file_path") or "").name,
                "status": job["status"], "attempts": job["attempts"],
            })

    specialists = []
    for identifier, name in SPECIALISTS:
        tasks = sorted(tasks_by_specialist[identifier], key=lambda item: item["id"])
        counts = Counter(task["status"] for task in tasks)
        if not scope and not tasks:
            status = "waiting"
        elif not tasks:
            status = "no_clue"
        elif counts["running"]:
            status = "running"
        elif counts["failed"]:
            status = "failed"
        elif counts["partial"]:
            status = "partial"
        elif counts["pending"]:
            status = "pending"
        else:
            status = "complete"
        visible = sorted(tasks, key=lambda item: (
            {"running": 0, "failed": 1, "partial": 2, "pending": 3, "complete": 4}.get(
                item["status"], 4), item["id"]))[:30]
        specialists.append({"id": identifier, "name": name, "status": status,
                            "counts": dict(counts), "task_count": len(tasks),
                            "hidden_task_count": len(tasks) - len(visible),
                            "tasks": visible})

    detectives = []
    for job in jobs:
        if job["kind"] != "detective":
            continue
        payload = job["payload"]
        detectives.append({
            "id": job["key"][:12], "status": job["status"],
            "source_specialist": payload.get("specialist_id") or "legacy",
            "file": Path(payload.get("file_path") or "").name,
            "line": str(payload.get("line_or_offset") or ""),
            "attempts": job["attempts"], "updated_at": job["updated_at"],
        })
    detectives.sort(key=lambda item: (item["status"] != "running",
                                      item["status"] != "pending", -item["updated_at"]))

    stages = {}
    for kind in JOB_KINDS:
        counts = Counter(job["status"] for job in jobs if job["kind"] == kind)
        stages[kind] = dict(counts)
    investigator = next((job for job in jobs if job["kind"] == "investigator"), None)
    specialist_names = dict(SPECIALISTS)
    active_jobs = []
    for job in jobs:
        if job["status"] != "running" or job["kind"] not in {"specialist", "detective"}:
            continue
        payload = job["payload"]
        active_jobs.append({
            "kind": job["kind"],
            "name": (specialist_names.get(payload.get("specialist_id"), "전담 조사")
                     if job["kind"] == "specialist" else "Detective"),
            "file": Path(payload.get("file_path") or "").name,
            "attempts": job["attempts"],
            "updated_at": job["updated_at"],
        })
    active_jobs.sort(key=lambda item: -item["updated_at"])
    for item in active_jobs:
        item.pop("updated_at")
    current_run = {
        "status": investigator["status"] if investigator else "waiting",
        "resumed": (investigator["attempts"] > 1 or
                    bool(investigator["payload"].get("resume"))) if investigator else False,
        "attempt": investigator["attempts"] if investigator else 0,
        "started_at": (datetime.fromtimestamp(investigator["updated_at"], timezone.utc).isoformat()
                       if investigator and investigator["status"] == "running" else None),
        "active_count": len(active_jobs), "active_jobs": active_jobs[:20],
    }
    confirmed_count, confirmed = _confirmed_vulnerabilities(jobs)
    return {
        "firmware_id": directory.name[:12],
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "scope_ready": bool(scope), "total_files": len(scope.get("inventory", [])),
        "extraction_ready": bool(manifest.get("extracted_dir")),
        "investigator_status": investigator["status"] if investigator else "waiting",
        "current_run": current_run,
        "specialists": specialists, "detectives": detectives,
        "confirmed_count": confirmed_count, "confirmed_vulnerabilities": confirmed,
        "lab": [{"id": job["key"][:12], "status": job["status"]}
                for job in jobs if job["kind"] == "lab"],
        "assistant": [{"id": job["key"][:12], "status": job["status"]}
                      for job in jobs if job["kind"] == "assistant"],
        "stages": stages,
    }


def make_handler(state_dir: str | Path):
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            route = self.path.split("?", 1)[0]
            if route == "/api/status":
                try:
                    body = json.dumps(read_snapshot(state_dir), ensure_ascii=False).encode("utf-8")
                except Exception:
                    self.send_error(500, "Could not read local job state")
                    return
                mime = "application/json; charset=utf-8"
            elif route in ASSETS:
                name, mime = ASSETS[route]
                body = (ASSET_DIR / name).read_bytes()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'self'; style-src 'self'; "
                             "connect-src 'self'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return DashboardHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Live, local FBI worker dashboard")
    parser.add_argument("--version", action="version", version=f"FBI {VERSION}")
    parser.add_argument("firmware", type=Path, help="Same firmware passed to coordinator/main.py")
    parser.add_argument("--state-root", type=Path, default=Path("./sessions/coordinator"))
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser window")
    args = parser.parse_args()
    if not args.firmware.is_file():
        parser.error(f"Firmware file not found: {args.firmware}")
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    state_dir = args.state_root.resolve() / firmware_digest(args.firmware)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(state_dir))
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"FBI worker dashboard: {url}", flush=True)
    print("Press Ctrl+C to stop the dashboard.", flush=True)
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
