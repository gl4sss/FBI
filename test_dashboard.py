"""Read-only checks for the live local worker dashboard."""

import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from coordinator.dashboard import make_handler, read_snapshot
from coordinator.state import StateStore, job_key


class DashboardTests(unittest.TestCase):
    def test_legacy_partial_worker_is_displayed_as_partial(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            directory = Path(temporary_dir) / "state"
            state = StateStore(directory)
            key = job_key("partial-worker")
            state.enqueue("specialist", key, {
                "task_id": "sp_authz_1", "specialist_id": "authz",
                "file_path": "/private/auth.c",
            })
            state.finish("specialist", key, "failed", {
                "status": "partial", "analysis": "do-not-display",
            })
            snapshot = read_snapshot(directory)
            authz = next(item for item in snapshot["specialists"] if item["id"] == "authz")
            self.assertEqual(authz["status"], "partial")
            self.assertEqual(authz["counts"], {"partial": 1})
            self.assertEqual(snapshot["stages"]["specialist"], {"partial": 1})
            self.assertNotIn("do-not-display", json.dumps(snapshot))

    def test_confirmed_panel_separates_static_and_reproduced_findings(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            directory = Path(temporary_dir) / "state"
            state = StateStore(directory)
            static_key = job_key("static")
            static = {"stable_id": "static-site", "disposition": "static_verified",
                      "title": "embedded credential", "category": "credential",
                      "file_path": "/private/config.conf", "line_or_offset": "12",
                      "evidence": ["do-not-display"]}
            state.enqueue("finding", static_key, static)
            state.finish("finding", static_key, "complete", static)
            pending_key = job_key("pending")
            state.enqueue("finding", pending_key, {
                "disposition": "needs_dynamic_verification", "title": "unverified"})
            state.finish("finding", pending_key, "complete", {
                "disposition": "needs_dynamic_verification", "title": "unverified"})
            detective_key = job_key("detective")
            state.enqueue("detective", detective_key, {
                "stable_id": "dynamic-site", "title": "runtime candidate",
                "category": "command injection", "file_path": "/private/parser.c",
                "line_or_offset": "0x20", "evidence": ["do-not-display"],
            })
            state.finish("detective", detective_key, "complete", {
                "confirmed_vulns": [{"vuln_id": "VULN-1", "trigger_confirmed": True,
                                      "title": "password=do-not-display", "cvss_score": 8.2,
                                      "evidence": ["do-not-display"]}],
            })
            snapshot = read_snapshot(directory)
            findings = snapshot["confirmed_vulnerabilities"]
            self.assertEqual(snapshot["confirmed_count"], 2)
            self.assertEqual([item["verification"] for item in findings], ["dynamic", "static"])
            self.assertEqual(findings[0]["cvss_score"], 8.2)
            self.assertEqual(findings[0]["file"], "parser.c")
            self.assertEqual(findings[1]["file"], "config.conf")
            self.assertNotIn("unverified", json.dumps(snapshot))
            self.assertNotIn("do-not-display", json.dumps(snapshot))
            self.assertNotIn("/private/", json.dumps(snapshot))

    def test_large_scope_keeps_counts_but_bounds_browser_payload(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            directory = Path(temporary_dir) / ("a" * 64)
            directory.mkdir()
            session = Path(temporary_dir) / "session"
            session.mkdir()
            (directory / "coordinator.json").write_text(json.dumps({
                "investigator_session": str(session),
            }))
            (session / "scan_scope.json").write_text(json.dumps({
                "tasks": [{"task_id": f"sp_secrets_{index}",
                           "specialist_id": "secrets",
                           "scope_files": [f"/private/file_{index}.conf"]}
                          for index in range(100)],
            }))
            specialist = next(item for item in read_snapshot(directory)["specialists"]
                              if item["id"] == "secrets")
            self.assertEqual(specialist["task_count"], 100)
            self.assertEqual(len(specialist["tasks"]), 30)
            self.assertEqual(specialist["hidden_task_count"], 70)

    def test_snapshot_tracks_planned_running_and_dynamic_jobs_without_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            directory = Path(temporary_dir) / "state" / ("f" * 64)
            directory.mkdir(parents=True)
            session = Path(temporary_dir) / "session"
            session.mkdir()
            (directory / "coordinator.json").write_text(json.dumps({
                "investigator_session": str(session), "extracted_dir": str(session / "extracted"),
            }))
            (session / "scan_scope.json").write_text(json.dumps({
                "inventory": [{"path": "secret.conf"}, {"path": "data.dat"}],
                "tasks": [{"task_id": "sp_secrets_1", "specialist_id": "secrets",
                           "scope_files": ["/private/secret.conf"]}],
            }))
            state = StateStore(directory)
            state.start("investigator", job_key("investigator"), {
                "resume": None, "secret": "do-not-display",
            })
            state.start("investigator", job_key("investigator"), {
                "resume": "/private/previous-session", "secret": "do-not-display",
            })
            self.assertEqual(state.get("investigator", job_key("investigator"))["payload"]["resume"],
                             "/private/previous-session")
            key = job_key("specialist")
            state.start("specialist", key, {
                "task_id": "sp_secrets_1", "specialist_id": "secrets",
                "file_path": "/private/secret.conf", "secret": "do-not-display",
            })
            state.enqueue("detective", job_key("detective"), {
                "specialist_id": "secrets", "file_path": "/private/secret.conf",
                "line_or_offset": "7", "evidence": ["do-not-display"],
            })
            snapshot = read_snapshot(directory)
            secrets = next(item for item in snapshot["specialists"] if item["id"] == "secrets")
            self.assertEqual(len(snapshot["specialists"]), 10)
            self.assertEqual(secrets["status"], "running")
            self.assertEqual(snapshot["detectives"][0]["source_specialist"], "secrets")
            self.assertEqual(snapshot["total_files"], 2)
            self.assertEqual(snapshot["current_run"]["status"], "running")
            self.assertTrue(snapshot["current_run"]["resumed"])
            self.assertEqual(snapshot["current_run"]["attempt"], 2)
            self.assertEqual(snapshot["current_run"]["active_count"], 1)
            self.assertEqual(snapshot["current_run"]["active_jobs"][0]["file"], "secret.conf")
            self.assertNotIn("do-not-display", json.dumps(snapshot))
            self.assertNotIn("/private/", json.dumps(snapshot))
            state.finish("specialist", key, "complete", {"evidence": "do-not-display"})
            updated = read_snapshot(directory)
            completed = next(item for item in updated["specialists"]
                             if item["id"] == "secrets")
            self.assertEqual(completed["status"], "complete")
            self.assertNotIn("do-not-display", json.dumps(updated))

    def test_http_serves_dashboard_and_status_only(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            handler_type = make_handler(temporary_dir)

            def request(path):
                handler = handler_type.__new__(handler_type)
                handler.path = path
                handler.wfile = io.BytesIO()
                handler.send_response = Mock()
                handler.send_header = Mock()
                handler.end_headers = Mock()
                handler.send_error = Mock()
                handler.do_GET()
                return handler

            api = request("/api/status")
            snapshot = json.loads(api.wfile.getvalue())
            self.assertEqual(len(snapshot["specialists"]), 10)
            self.assertTrue(all(item["status"] == "waiting"
                                for item in snapshot["specialists"]))
            api.send_header.assert_any_call("Cache-Control", "no-store")
            for asset in ("/", "/dashboard.css", "/dashboard.js"):
                self.assertTrue(request(asset).wfile.getvalue())
            missing = request("/../README.md")
            missing.send_error.assert_called_once_with(404)


if __name__ == "__main__":
    unittest.main()
