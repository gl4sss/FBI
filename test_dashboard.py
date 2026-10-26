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
