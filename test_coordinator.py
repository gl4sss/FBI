"""Integration checks for the bounded, resumable pipeline."""

import json
import io
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from coordinator.main import Coordinator
from coordinator.state import StateStore, file_lock
from detective.main import run_detective
from detective.main import load_investigator_session
from detective.qemu_runner import QemuRunner
from investigator.scan_scope import file_inventory, scan_tasks
from investigator.specialists import SPECIALISTS, plan_specialists, prompt_version
from investigator.main import load_resume_state, run_analysis
from investigator.worker import Worker as InvestigatorWorker
from investigator.extractor import ExtractionError
from report_generator import _load_session, generate_report
from shared.redaction import redact_text
from shared.validation import (collect_report_candidates, validate_confirmed_chain,
                               validate_confirmed_vulns,
                               validate_specialist_scope, validate_worker_result)


class InventoryTests(unittest.TestCase):
    def test_integrated_scope_includes_every_regular_file(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "service.sh").write_text("#!/bin/sh\n")
            (root / "device.conf").write_text("port=80\n")
            (root / "payload.dat").write_bytes(b"\x00\x01")
            (root / "link").symlink_to(root / "payload.dat")
            inventory = file_inventory(root)
            self.assertEqual({entry["type"] for entry in inventory},
                             {"code", "configuration", "data", "symlink"})
            tasks, targets = scan_tasks(root, all_files=True, files_per_task=1)
            self.assertEqual(len(targets), 3)
            self.assertEqual(len(tasks), 3)
            self.assertTrue(all(len(task["scope_files"]) == 1 for task in tasks))
            self.assertNotIn(str(root / "link"), targets)

    def test_unreadable_file_keeps_reason(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "secret.conf").write_text("redacted")
            original_open = Path.open

            def deny_selected(path, *args, **kwargs):
                if path.name == "secret.conf":
                    raise PermissionError("simulated access denial")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", deny_selected):
                entries = file_inventory(root)
            self.assertEqual(entries[0]["status"], "unreadable")
            self.assertIn("simulated access denial", entries[0]["reason"])


class SpecialistRoutingTests(unittest.TestCase):
    def test_fixed_catalog_uses_distinct_versioned_prompt_files(self):
        self.assertEqual(len(SPECIALISTS), 10)
        self.assertEqual(len({identifier for identifier, _ in SPECIALISTS}), 10)
        self.assertTrue(all(len(prompt_version(identifier)) == 12
                            for identifier, _ in SPECIALISTS))
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "code.c").write_text("void f(char *s) { char b[8]; strcpy(b,s); }\n")
            tasks, scope = plan_specialists(file_inventory(root), root)
            owners = {task["specialist_id"] for task in tasks}
            self.assertIn("stack_overflow", owners)
            self.assertIn("memory_safety", owners)
            self.assertTrue(all(task["prompt_version"] in task["task_id"] for task in tasks))
            self.assertTrue(all(task["specialist_id"] in task["task_id"] for task in tasks))
            self.assertEqual(len(scope["specialists"]), 10)

    def test_unrelated_data_needs_no_specialist_model_call(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "payload.dat").write_bytes(b"\x00\x01\x02")
            tasks, scope = plan_specialists(file_inventory(root), root)
            self.assertEqual(tasks, [])
            self.assertEqual(scope["file_routing"][0]["status"], "no_applicable_clue")
            self.assertTrue(all(item["status"] == "no_applicable_clue"
                                for item in scope["specialists"]))

    def test_generic_native_binary_does_not_trigger_component_lookup(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "app.elf").write_bytes(b"\x7fELF\x00generic local application")
            tasks, _ = plan_specialists(file_inventory(root), root)
            owners = {task["specialist_id"] for task in tasks}
            self.assertIn("memory_safety", owners)
            self.assertNotIn("components", owners)

    def test_large_unclassified_data_is_kept_for_review(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "unknown.dat").write_bytes(b"x" * 70000)
            tasks, scope = plan_specialists(file_inventory(root), root)
            self.assertIn("components", {task["specialist_id"] for task in tasks})
            self.assertIn("secrets", {task["specialist_id"] for task in tasks})
            self.assertEqual(scope["file_routing"][0]["status"], "scheduled")

    def test_secret_value_is_redacted_in_persisted_text(self):
        self.assertNotIn("strong-value", redact_text("password=strong-value"))
        self.assertNotIn("abc123", redact_text("api_key: abc123"))

    def test_second_pass_read_failure_keeps_reason(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "service.conf").write_text("listen=80\n")
            inventory = file_inventory(root)
            original_open = Path.open

            def deny_selected(path, *args, **kwargs):
                if path.name == "service.conf":
                    raise PermissionError("changed permissions")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", deny_selected):
                tasks, scope = plan_specialists(inventory, root)
            self.assertEqual(tasks, [])
            self.assertEqual(scope["file_routing"][0]["status"], "unreadable")
            self.assertIn("changed permissions", scope["file_routing"][0]["reason"])

    def test_same_site_is_one_candidate_with_dynamic_priority(self):
        tasks = []
        for identifier, disposition in (("secrets", "static_verified"),
                                        ("authz", "needs_dynamic_verification")):
            tasks.append({
                "task_id": f"sp_{identifier}_1", "specialist_id": identifier,
                "suspected_findings": [{
                    "finding_id": f"sp_{identifier}_1-001",
                    "file_path": "/tmp/auth.c", "line_or_offset": "12",
                    "location": "/tmp/auth.c:12", "title": "same root cause",
                    "evidence": [identifier + " evidence"],
                    "impact_tags": [identifier], "disposition": disposition,
                }],
            })
        candidates = collect_report_candidates(tasks)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["disposition"], "needs_dynamic_verification")
        self.assertEqual(len(candidates[0]["evidence"]), 2)
        self.assertEqual(set(candidates[0]["impact_tags"]), {"secrets", "authz"})

    def test_outside_file_cannot_be_sent_for_dynamic_verification(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            result = {"status": "completed", "suspected_findings": [{
                "file_path": "/etc/passwd", "disposition": "needs_dynamic_verification",
            }]}
            validate_specialist_scope(result, temporary_dir)
            self.assertEqual(result["suspected_findings"][0]["disposition"],
                             "needs_static_research")
            self.assertEqual(result["status"], "partial")


class QemuPortTests(unittest.TestCase):
    def test_forwarded_ports_follow_reservations(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            captured = {}

            def fake_popen(command, **kwargs):
                captured["command"] = command
                return SimpleNamespace(pid=123, poll=lambda: None)

            runner = QemuRunner({"timeout_boot": 0})
            with patch("detective.qemu_runner.detect_arch", return_value="arm"), \
                 patch("detective.qemu_runner.subprocess.run",
                       return_value=SimpleNamespace(returncode=0)), \
                 patch("detective.qemu_runner.subprocess.Popen", side_effect=fake_popen), \
                 patch("detective.qemu_runner._free_port",
                       side_effect=[4444, 4445, 8081, 8444]), \
                 patch("detective.qemu_runner.time.sleep"):
                result = runner.start("/tmp/fixture.bin", {}, temporary_dir)
            self.assertTrue(result["started"])
            self.assertEqual(result["http_port"], 8081)
            self.assertIn("hostfwd=tcp::8081-:80", " ".join(captured["command"]))
            self.assertIn("127.0.0.1:8444", result["connection_info"])


class StateTests(unittest.TestCase):
    def test_file_lock_is_process_safe(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            ready = root / "ready"
            code = (
                "import sys,time; from pathlib import Path; "
                "from coordinator.state import file_lock; "
                "directory=Path(sys.argv[1]); ready=Path(sys.argv[2]); "
                "\nwith file_lock(directory, 'same') as lease:\n"
                " ready.write_text('locked'); time.sleep(0.3)\n"
            )
            process = subprocess.Popen([sys.executable, "-c", code, str(root), str(ready)])
            try:
                deadline = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                with file_lock(root, "same") as lease:
                    self.assertFalse(lease)
            finally:
                process.wait(timeout=2)
            with file_lock(root, "same") as lease:
                self.assertTrue(lease)

    def test_lease_prevents_duplicate_and_preserves_result(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            state = StateStore(temporary_dir)
            payload = {"finding_id": "scan_0001-001"}
            with state.claim("detective", "site", payload) as first:
                self.assertIsNotNone(first)
                with state.claim("detective", "site", payload) as second:
                    self.assertIsNone(second)
                state.finish("detective", "site", "complete", {"confirmed_vulns": []})
            with state.claim("detective", "site", payload) as third:
                self.assertIsNone(third)
            self.assertEqual(state.get("detective", "site")["attempts"], 1)

    def test_interrupted_running_job_can_be_reclaimed(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            state = StateStore(temporary_dir)
            state.enqueue("lab", "firmware", {})
            with state._connect() as connection:
                connection.execute("UPDATE jobs SET status='running' WHERE kind='lab'")
            with state.claim("lab", "firmware", {}) as lease:
                self.assertIsNotNone(lease)
                state.finish("lab", "firmware", "complete", {"ready": True})
            self.assertEqual(state.get("lab", "firmware")["attempts"], 1)

    def test_failed_job_can_be_retried_on_later_runs(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            state = StateStore(temporary_dir)
            for _ in range(3):
                with state.claim("detective", "site", {}) as lease:
                    self.assertIsNotNone(lease)
                    state.finish("detective", "site", "failed", {"error": "temporary"})
            with state.claim("detective", "site", {}) as lease:
                self.assertIsNotNone(lease)
                state.finish("detective", "site", "complete", {"verified": True})
            self.assertEqual(state.get("detective", "site")["attempts"], 4)


class CoordinatorTests(unittest.TestCase):
    def _fixture(self, root: Path):
        firmware = root / "fixture.bin"
        firmware.write_bytes(b"synthetic firmware")
        session = root / "investigator-session"
        session.mkdir()
        (session / "firmware_info.json").write_text(json.dumps({
            "path": str(firmware), "filename": firmware.name,
            "hashes": {"sha256": "test"},
        }))
        extracted = session / "extracted"
        extracted.mkdir()
        return firmware, session, extracted

    def test_static_secret_is_reported_without_detective(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "fixture.bin"
            firmware.write_bytes(b"synthetic firmware")
            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": "fixture", "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}
            executed = []

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "secret.conf").write_text("password=strong-value\n")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 1}

            def fake_worker(self, task, session_id, path, extracted_dir):
                executed.append(task["specialist_id"])
                result = {"task_id": task["task_id"], "status": "completed",
                          "reviewed_files": task["scope_files"], "findings": [],
                          "suspected_findings": []}
                if task["specialist_id"] == "secrets":
                    result["analysis"] = "strong-value is embedded in this file"
                    result["suspected_findings"] = [{
                        "file_path": task["scope_files"][0],
                        "line_or_offset": "1", "location": task["scope_files"][0] + ":1",
                        "title": "embedded credential", "category": "credential",
                        "observation": "password=strong-value", "input_path": "embedded constant",
                        "use_path": "login check",
                        "evidence": ["secret.conf:1 password=strong-value"],
                        "disposition": "static_verified",
                    }]
                return validate_worker_result(result, task["task_id"])

            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("coordinator.main.run_detective") as detective, \
                 patch("report_generator.generate_report", return_value="report.html"), \
                 redirect_stdout(io.StringIO()):
                coordinator = Coordinator(firmware, root / "state", no_qemu=True)
                coordinator.run()

            self.assertIn("secrets", executed)
            detective.assert_not_called()
            findings = coordinator.state.list_jobs("finding")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["result"]["disposition"], "static_verified")
            self.assertNotIn("strong-value", json.dumps(findings))
            session = Path(coordinator.investigator_session)
            self.assertNotIn("strong-value", (session / "coordinator_status.json").read_text())
            self.assertNotIn("strong-value", (session / "task_results.jsonl").read_text())
            self.assertIn("prompt_version", (session / "task_results.jsonl").read_text())
            self.assertEqual(_load_session(str(session))["specialists"][0]["id"], "secrets")

    def test_no_relevant_clue_invokes_no_specialist_worker(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "fixture.bin"
            firmware.write_bytes(b"synthetic firmware")
            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": "fixture", "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "payload.dat").write_bytes(b"\x00\x01")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 1}

            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute") as worker, \
                 patch("report_generator.generate_report", return_value="report.html"), \
                 redirect_stdout(io.StringIO()):
                coordinator = Coordinator(firmware, root / "state", no_qemu=True)
                coordinator.run()
            worker.assert_not_called()
            scope = json.loads((Path(coordinator.investigator_session) /
                                "scan_scope.json").read_text())
            self.assertEqual(scope["mode"], "specialists")
            self.assertEqual(len(scope["specialists"]), 10)
            self.assertTrue(all(item["status"] == "no_applicable_clue"
                                for item in scope["specialists"]))

    def test_dynamic_specialist_handoff_starts_while_other_specialist_runs(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "fixture.bin"
            firmware.write_bytes(b"synthetic firmware")
            started = threading.Event()
            active = 0
            peak = 0
            mutex = threading.Lock()
            worker_ids = {}
            case = self
            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": "fixture", "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "parser.c").write_text(
                    "void parse(char *s) { char b[8]; strcpy(b,s); }\n")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 1}

            def fake_worker(self, task, session_id, path, extracted_dir):
                nonlocal active, peak
                with mutex:
                    active += 1
                    peak = max(peak, active)
                    worker_ids[task["specialist_id"]] = id(self)
                try:
                    if task["specialist_id"] == "memory_safety":
                        case.assertTrue(started.wait(1), "Detective did not start during another review")
                    if task["specialist_id"] == "stack_overflow":
                        time.sleep(0.02)
                    result = {"task_id": task["task_id"], "status": "completed",
                              "reviewed_files": task["scope_files"], "findings": [],
                              "suspected_findings": []}
                    if task["specialist_id"] == "stack_overflow":
                        file_path = task["scope_files"][0]
                        result["suspected_findings"] = [{
                            "location": file_path + ":1", "file_path": file_path,
                            "line_or_offset": "1", "input_path": "parse argument",
                            "use_path": "strcpy destination",
                            "title": "unchecked copy", "category": "stack_overflow",
                            "observation": "unbounded copy into stack buffer",
                            "evidence": ["parser.c:1 strcpy"],
                            "disposition": "needs_dynamic_verification",
                        }]
                    return validate_worker_result(result, task["task_id"])
                finally:
                    with mutex:
                        active -= 1

            def fake_detective(session, settings, **kwargs):
                _, candidates, _ = load_investigator_session(
                    session, finding_ids=kwargs["finding_ids"])
                self.assertEqual(len(candidates), 1)
                started.set()
                return {"session_path": str(root / "det"), "confirmed_vulns": []}

            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("coordinator.main.run_detective", side_effect=fake_detective), \
                 patch("report_generator.generate_report", return_value="report.html"), \
                 redirect_stdout(io.StringIO()):
                summary = Coordinator(firmware, root / "state", investigator_limit=2,
                                      detective_limit=1, no_qemu=True).run()
            self.assertEqual(summary["detective"]["complete"], 1)
            self.assertEqual(peak, 2)
            self.assertEqual(summary["specialist"].get("failed", 0), 0)
            self.assertEqual(len(set(worker_ids.values())), len(worker_ids))

    def test_same_root_cause_from_two_specialists_has_one_detective_job(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, session, extracted = self._fixture(root)
            calls = []

            def fake_analysis(path, settings, **kwargs):
                kwargs["on_extracted"](session, {}, str(extracted))
                for identifier in ("stack_overflow", "denial_of_service"):
                    kwargs["on_finding"]({
                        "finding_id": f"sp_{identifier}-001",
                        "location": str(extracted / "parser.c") + ":12",
                        "file_path": str(extracted / "parser.c"),
                        "line_or_offset": "12", "disposition": "needs_dynamic_verification",
                        "title": identifier, "evidence": ["parser.c:12"],
                    }, {"task_id": f"sp_{identifier}", "specialist_id": identifier,
                        "scope_files": [str(extracted / "parser.c")]}, session)
                return session

            def fake_detective(*args, **kwargs):
                calls.append(1)
                return {"session_path": str(root / "det"), "confirmed_vulns": []}

            with patch("coordinator.main.run_analysis", side_effect=fake_analysis), \
                 patch("coordinator.main.run_detective", side_effect=fake_detective), \
                 patch("report_generator.generate_report", return_value="report.html"):
                coordinator = Coordinator(firmware, root / "state", no_qemu=True)
                coordinator.run()
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(coordinator.state.list_jobs("finding")), 2)
            self.assertEqual(len(coordinator.state.list_jobs("detective")), 1)

    def test_completed_specialist_work_is_reused_after_restart(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "fixture.bin"
            firmware.write_bytes(b"synthetic firmware")
            coordinator = Coordinator(firmware, root / "state", no_qemu=True)
            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": coordinator.firmware_sha256, "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}
            calls = []

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "service.sh").write_text("#!/bin/sh\nexec service\n")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 1}

            def fake_worker(self, task, session_id, path, extracted_dir):
                calls.append(task["task_id"])
                return {"task_id": task["task_id"], "status": "completed",
                        "reviewed_files": task["scope_files"], "findings": [],
                        "suspected_findings": []}

            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("report_generator.generate_report", return_value="report.html"), \
                 redirect_stdout(io.StringIO()):
                coordinator.run()
                first_count = len(calls)
                restarted = Coordinator(firmware, root / "state", no_qemu=True)
                restarted.run()
            self.assertGreater(first_count, 0)
            self.assertEqual(len(calls), first_count)
            self.assertEqual(coordinator.investigator_session, restarted.investigator_session)

    def test_failed_specialist_task_retries_after_restart(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "fixture.bin"
            firmware.write_bytes(b"synthetic firmware")
            coordinator = Coordinator(firmware, root / "state", no_qemu=True)
            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": coordinator.firmware_sha256, "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}
            calls = []

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "secret.conf").write_text("password=fixture-value\n")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 1}

            def fake_worker(self, task, session_id, path, extracted_dir):
                calls.append(task["task_id"])
                return {"task_id": task["task_id"],
                        "status": "failed" if len(calls) == 1 else "completed",
                        "reviewed_files": task["scope_files"], "findings": [],
                        "suspected_findings": []}

            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("report_generator.generate_report", return_value="report.html"), \
                 redirect_stdout(io.StringIO()):
                first = coordinator.run()
                restarted = Coordinator(firmware, root / "state", no_qemu=True)
                second = restarted.run()
            self.assertEqual(first["specialist"]["failed"], 1)
            self.assertEqual(second["specialist"]["complete"], 1)
            self.assertEqual(len(calls), 2)
            self.assertEqual(restarted.state.list_jobs("specialist")[0]["attempts"], 2)

    def test_partial_specialist_task_retries_after_restart(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "fixture.bin"
            firmware.write_bytes(b"synthetic firmware")
            coordinator = Coordinator(firmware, root / "state", no_qemu=True)
            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": coordinator.firmware_sha256, "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}
            calls = []

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "secret.conf").write_text("password=fixture-value\n")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 1}

            def fake_worker(self, task, session_id, path, extracted_dir):
                calls.append(task["task_id"])
                return {"task_id": task["task_id"],
                        "status": "partial" if len(calls) == 1 else "completed",
                        "reviewed_files": task["scope_files"], "findings": [],
                        "suspected_findings": []}

            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("report_generator.generate_report", return_value="report.html"), \
                 redirect_stdout(io.StringIO()):
                coordinator.run()
                restarted = Coordinator(firmware, root / "state", no_qemu=True)
                restarted.run()
            self.assertEqual(len(calls), 2)
            self.assertEqual(restarted.state.list_jobs("specialist")[0]["status"], "complete")
            self.assertEqual(restarted.state.list_jobs("specialist")[0]["attempts"], 2)
            research = json.loads((Path(restarted.investigator_session) /
                                   "research_status.json").read_text())
            self.assertEqual(research["stop_reason"], "specialist_sweep_complete")

    def test_unreviewed_specialist_file_does_not_enter_completed_cache(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "fixture.bin"
            firmware.write_bytes(b"synthetic firmware")
            extracted = root / "extracted"
            extracted.mkdir()
            source = extracted / "secret.conf"
            source.write_text("password=fixture-value\n")
            coordinator = Coordinator(firmware, root / "state", no_qemu=True)
            task = {"task_id": "sp_secrets_fixture", "specialist_id": "secrets",
                    "prompt_version": "fixture", "scope_files": [str(source)]}
            calls = []

            class FakeWorker:
                def execute(self, *_args):
                    calls.append(True)
                    return {"task_id": task["task_id"], "status": "completed",
                            "reviewed_files": [] if len(calls) == 1 else [str(source)],
                            "suspected_findings": []}

            worker = FakeWorker()
            first = coordinator._run_specialist_task(
                worker, task, None, str(firmware), str(extracted))
            key, _ = coordinator._specialist_identity(task)
            self.assertEqual(first["status"], "partial")
            self.assertEqual(coordinator.state.get("specialist", key)["status"], "failed")
            second = coordinator._run_specialist_task(
                worker, task, None, str(firmware), str(extracted))
            self.assertEqual(second["status"], "completed")
            self.assertEqual(coordinator.state.get("specialist", key)["attempts"], 2)

    def test_crash_between_codex_log_and_task_state_is_reconciled(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "fixture.bin"
            firmware.write_bytes(b"synthetic firmware")
            coordinator = Coordinator(firmware, root / "state", no_qemu=True)
            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": coordinator.firmware_sha256, "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}
            calls = []

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "secret.conf").write_text("password=fixture-value\n")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 1}

            def fake_worker(self, task, session_id, path, extracted_dir):
                calls.append(task["task_id"])
                file_path = task["scope_files"][0]
                return validate_worker_result({
                    "task_id": task["task_id"], "status": "completed",
                    "reviewed_files": [file_path], "findings": [],
                    "suspected_findings": [{
                        "location": file_path + ":1", "file_path": file_path,
                        "line_or_offset": "1", "input_path": "embedded constant",
                        "use_path": "login check", "title": "credential",
                        "observation": "embedded credential used at login check",
                        "evidence": ["secret.conf:1 password=fixture-value"],
                        "disposition": "static_verified",
                    }],
                }, task["task_id"])

            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("report_generator.generate_report", return_value="report.html"), \
                 redirect_stdout(io.StringIO()):
                coordinator.run()
                session = Path(coordinator.investigator_session)
                saved = json.loads((session / "task_results.jsonl").read_text().splitlines()[0])
                codex_log = session / "codex_sessions" / "crashed.jsonl"
                codex_log.write_text(json.dumps({
                    "role": "assistant", "content": saved["result"]}) + "\n")
                (session / "task_results.jsonl").unlink()
                with coordinator.state._connect() as connection:
                    connection.execute("UPDATE jobs SET status='running' WHERE kind='specialist'")
                    connection.execute("DELETE FROM jobs WHERE kind='finding'")
                restarted = Coordinator(firmware, root / "state", no_qemu=True)
                restarted.run()

            self.assertEqual(len(calls), 1)
            self.assertEqual(restarted.state.list_jobs("specialist")[0]["status"], "complete")
            self.assertEqual(len(restarted.state.list_jobs("finding")), 1)
            self.assertTrue((session / "task_results.jsonl").exists())

    def test_discovery_starts_detective_before_investigator_finishes(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, session, extracted = self._fixture(root)
            started = threading.Event()
            active = 0
            peak = 0
            mutex = threading.Lock()
            lab_calls = []
            assistant_calls = []

            def fake_analysis(path, settings, **kwargs):
                kwargs["on_extracted"](session, {"hashes": {"sha256": "test"}}, str(extracted))
                for index in range(4):
                    kwargs["on_finding"]({
                        "finding_id": f"scan_{index + 1:04d}-001",
                        "location": str(extracted / f"file{index}.sh") + ":1",
                        "title": f"site {index}", "category": "shell",
                        "evidence": [f"file{index}:1"],
                    }, {"task_id": f"scan_{index + 1:04d}"}, session)
                self.assertTrue(started.wait(1), "Detective did not begin during Investigator")
                return session

            def fake_detective(inv_session, settings, **kwargs):
                nonlocal active, peak
                with mutex:
                    active += 1
                    peak = max(peak, active)
                started.set()
                lab = kwargs["lab_request"](str(firmware), {})
                self.assertEqual(lab["environment"], "ready")
                time.sleep(0.02)
                with mutex:
                    active -= 1
                finding_id = next(iter(kwargs["finding_ids"]))
                return {"session_path": str(root / finding_id),
                        "confirmed_vulns": [{"vuln_id": finding_id, "trigger_confirmed": True,
                                              "evidence": ["executed local test"]}]}

            def fake_lab(path, settings, **kwargs):
                lab_calls.append(path)
                time.sleep(0.03)
                return {"session_path": str(root / "lab"), "environment": "ready"}

            def fake_assistant(path, settings, **kwargs):
                assistant_calls.append(path)
                self.assertTrue((Path(path) / "detective_session.json").exists())
                return {"session_path": str(root / "assistant")}

            with patch("coordinator.main.run_analysis", side_effect=fake_analysis), \
                 patch("coordinator.main.run_detective", side_effect=fake_detective), \
                 patch("coordinator.main.run_lab", side_effect=fake_lab), \
                 patch("coordinator.main.run_assistant", side_effect=fake_assistant), \
                 patch("report_generator.generate_report", return_value="report.html"):
                summary = Coordinator(firmware, root / "state", detective_limit=2).run()

            self.assertLessEqual(peak, 2)
            self.assertGreaterEqual(peak, 1)
            self.assertEqual(len(lab_calls), 1)
            self.assertGreaterEqual(len(assistant_calls), 1)
            self.assertEqual(summary["detective"]["complete"], 4)
            self.assertEqual(summary["lab"]["complete"], 1)
            status = json.loads((session / "coordinator_status.json").read_text())
            self.assertEqual(status["stages"]["detective"]["complete"], 4)

    def test_real_investigator_log_is_consumed_by_detective_loader(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"synthetic firmware")
            detective_started = threading.Event()
            inspected = []

            def fake_extract(path, session_dir, sha, timeout=300):
                self.assertTrue((Path(session_dir) / "firmware_info.json").exists())
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "a.sh").write_text("#!/bin/sh\neval \"$1\"\n")
                (extracted / "b.conf").write_text("listen=80\n")
                (extracted / "c.dat").write_bytes(b"\x00\x01")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 3, "files_sample": ["a.sh", "b.conf", "c.dat"]}

            def fake_worker(self, task, session_id, path, extracted_dir):
                inspected.extend(task["scope_files"])
                result = {"task_id": task["task_id"], "status": "completed",
                          "reviewed_files": task["scope_files"], "findings": [],
                          "analysis": "reviewed", "suspected_findings": []}
                if task["scope_files"][0].endswith("a.sh"):
                    result["suspected_findings"] = [{
                        "location": task["scope_files"][0] + ":2",
                        "file_path": task["scope_files"][0],
                        "line_or_offset": "2", "input_path": "shell argument",
                        "use_path": "eval call",
                        "disposition": "needs_dynamic_verification",
                        "title": "shell input", "category": "command",
                        "observation": "eval reads shell argument",
                        "evidence": ["a.sh:2 eval"],
                    }]
                return validate_worker_result(result, task["task_id"])

            def fake_detective(session, settings, **kwargs):
                _, candidates, _ = load_investigator_session(
                    session, finding_ids=kwargs["finding_ids"])
                self.assertEqual(len(candidates), 1)
                self.assertEqual(candidates[0]["location"].split(":")[-1], "2")
                self.assertEqual(kwargs["handoff"]["line_or_offset"], "2")
                detective_started.set()
                return {"session_path": str(root / "detective"),
                        "confirmed_vulns": []}

            def fake_settings(stage):
                settings = json.loads(Path(stage, "settings.json").read_text())
                if stage == "investigator":
                    settings["analysis"]["max_iterations"] = 1
                    settings["analysis"]["deep_research_enabled"] = False
                return settings

            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": "fixture", "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}
            with patch("coordinator.main._settings", side_effect=fake_settings), \
                 patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("coordinator.main.run_detective", side_effect=fake_detective), \
                 patch("report_generator.generate_report", return_value="report.html") as report_call, \
                 redirect_stdout(io.StringIO()):
                summary = Coordinator(firmware, root / "state", no_qemu=True).run()
            self.assertTrue(detective_started.is_set())
            self.assertTrue(any(path.endswith("a.sh") for path in inspected))
            self.assertFalse(any(path.endswith("c.dat") for path in inspected))
            self.assertEqual(summary["detective"]["complete"], 1)
            self.assertEqual(report_call.call_count, 1)

    def test_resume_before_orchestrator_log_skips_completed_files_and_retries_failed(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"synthetic firmware")
            settings = json.loads(Path("investigator/settings.json").read_text())
            settings["analysis"].update({
                "sessions_dir": str(root / "sessions"),
                "max_iterations": 1,
                "deep_research_enabled": False,
            })
            settings["report"] = {"enabled": False}
            attempts = {"a.sh": 0, "b.conf": 0}

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "a.sh").write_text("#!/bin/sh\n")
                (extracted / "b.conf").write_text("port=80\n")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 2, "files_sample": ["a.sh", "b.conf"]}

            def fake_worker(self, task, session_id, path, extracted_dir):
                name = Path(task["scope_files"][0]).name
                attempts[name] += 1
                return {"task_id": task["task_id"],
                        "status": "failed" if name == "a.sh" and attempts[name] == 1
                        else "completed", "reviewed_files": task["scope_files"],
                        "suspected_findings": [], "findings": []}

            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": "fixture", "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}
            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("investigator.main.Orchestrator.decide", return_value={
                     "status": "complete", "analysis_summary": "done"}), \
                 redirect_stdout(io.StringIO()):
                session = run_analysis(str(firmware), settings, all_files=True)
                self.assertFalse((session / "orchestrator_conversation.jsonl").exists())
                restored, _, _, _ = load_resume_state(str(session))
                self.assertEqual(len(restored), 2)
                run_analysis(str(firmware), settings, resume_from=str(session),
                             all_files=True)

            self.assertEqual(attempts, {"a.sh": 2, "b.conf": 1})

    def test_legacy_integrated_session_accepts_specialist_migration(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"synthetic firmware")
            settings = json.loads(Path("investigator/settings.json").read_text())
            settings["analysis"].update({
                "sessions_dir": str(root / "sessions"),
                "max_iterations": 1, "deep_research_enabled": False,
            })
            settings["report"] = {"enabled": False}
            info = {"path": str(firmware), "filename": firmware.name,
                    "file_type": "data", "size_bytes": firmware.stat().st_size,
                    "hashes": {"sha256": "fixture", "md5": "fixture"},
                    "strings_sample": [], "binwalk": None}
            forwarded = []

            def fake_extract(path, session_dir, sha, timeout=300):
                extracted = Path(session_dir) / "extracted"
                extracted.mkdir(exist_ok=True)
                (extracted / "service.sh").write_text("#!/bin/sh\nexec service\n")
                return {"status": "complete", "output_dir": str(extracted),
                        "file_count": 1}

            def fake_worker(self, task, session_id, path, extracted_dir):
                result = {"task_id": task["task_id"], "status": "completed",
                          "reviewed_files": task["scope_files"], "findings": [],
                          "suspected_findings": []}
                if task["task_id"].startswith("scan_"):
                    result["suspected_findings"] = [{
                        "location": task["scope_files"][0] + ":2",
                        "title": "legacy candidate", "evidence": ["service.sh:2"],
                    }]
                return validate_worker_result(result, task["task_id"])

            with patch("investigator.main.analyze_firmware", return_value=info), \
                 patch("investigator.main.extract_firmware", side_effect=fake_extract), \
                 patch("investigator.main.Worker.execute", fake_worker), \
                 patch("investigator.main.Orchestrator.decide", return_value={
                     "status": "complete", "analysis_summary": "done"}), \
                 redirect_stdout(io.StringIO()):
                session = run_analysis(str(firmware), settings, all_files=True)
                run_analysis(str(firmware), settings, resume_from=str(session),
                             all_files=True, specialists=True,
                             on_finding=lambda *args: forwarded.append(args))
            scope = json.loads((session / "scan_scope.json").read_text())
            self.assertEqual(scope["mode"], "specialists")
            self.assertTrue(any(item["task_id"].startswith("scan_")
                                for item in load_resume_state(str(session))[0]))
            self.assertEqual(forwarded, [])

    def test_interrupted_extraction_session_is_discovered_without_manifest(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, _, _ = self._fixture(root)
            coordinator = Coordinator(firmware, root / "state")
            session = (coordinator.directory / "investigator" /
                       firmware.stem / "interrupted")
            session.mkdir(parents=True)
            (session / "firmware_info.json").write_text(json.dumps({
                "hashes": {"sha256": coordinator.firmware_sha256}}))
            self.assertEqual(coordinator._resume_investigator_session(), str(session))

    def test_orchestrator_error_is_failed_and_session_can_resume(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, session, extracted = self._fixture(root)
            calls = []

            state = Coordinator(firmware, root / "state", no_qemu=True)
            (session / "firmware_info.json").write_text(json.dumps({
                "hashes": {"sha256": state.firmware_sha256}}))

            def fake_analysis(path, settings, **kwargs):
                calls.append(kwargs["resume_from"])
                kwargs["on_extracted"](session, {}, str(extracted))
                (session / "research_status.json").write_text(json.dumps({
                    "stop_reason": "orchestrator_error" if len(calls) == 1
                    else "evidence_complete"}))
                return session

            with patch("coordinator.main.run_analysis", side_effect=fake_analysis), \
                 patch("report_generator.generate_report", return_value="report.html"):
                coordinator = state
                with self.assertRaisesRegex(RuntimeError, "orchestrator failed"):
                    coordinator.run()
                self.assertEqual(coordinator.state.summary()["investigator"]["failed"], 1)
                coordinator.run()
            self.assertIsNone(calls[0])
            self.assertEqual(calls[1], str(session))

    def test_failed_detective_is_retried_without_duplicate_handoff(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, session, extracted = self._fixture(root)
            calls = []

            def fake_analysis(path, settings, **kwargs):
                kwargs["on_extracted"](session, {}, str(extracted))
                finding = {"finding_id": "scan_0001-001",
                           "location": str(extracted / "a.sh") + ":1",
                           "title": "site", "evidence": ["a.sh:1"]}
                kwargs["on_finding"](finding, {"task_id": "scan_0001"}, session)
                kwargs["on_finding"](finding, {"task_id": "scan_0001"}, session)
                return session

            def fake_detective(*args, **kwargs):
                calls.append(1)
                if len(calls) == 1:
                    raise RuntimeError("temporary failure")
                return {"session_path": str(root / "detective"), "confirmed_vulns": []}

            with patch("coordinator.main.run_analysis", side_effect=fake_analysis), \
                 patch("coordinator.main.run_detective", side_effect=fake_detective), \
                 patch("report_generator.generate_report", return_value="report.html"):
                first = Coordinator(firmware, root / "state").run()
                second = Coordinator(firmware, root / "state").run()
            self.assertEqual(first["detective"]["failed"], 1)
            self.assertEqual(second["detective"]["complete"], 1)
            self.assertEqual(len(calls), 2)
            self.assertNotIn("assistant", second)

    def test_distinct_sites_keep_unique_ids_and_completed_set_is_reused(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, session, extracted = self._fixture(root)
            assistant_calls = []

            def fake_analysis(path, settings, **kwargs):
                kwargs["on_extracted"](session, {}, str(extracted))
                for index in range(2):
                    kwargs["on_finding"]({
                        "finding_id": f"scan_{index + 1:04d}-001",
                        "location": f"{extracted}/site{index}.sh:1",
                        "title": "same issue", "evidence": ["observed code"],
                    }, {"task_id": f"scan_{index + 1:04d}"}, session)
                return session

            def fake_detective(*args, **kwargs):
                return {"session_path": str(root / "detective"),
                        "confirmed_vulns": [{"vuln_id": "VULN-1",
                                              "trigger_confirmed": True,
                                              "evidence": ["local test"]}]}

            def fake_assistant(*args, **kwargs):
                assistant_calls.append(1)
                return {"session_path": str(root / "assistant")}

            with patch("coordinator.main.run_analysis", side_effect=fake_analysis), \
                 patch("coordinator.main.run_detective", side_effect=fake_detective), \
                 patch("coordinator.main.run_assistant", side_effect=fake_assistant), \
                 patch("report_generator.generate_report", return_value="report.html"):
                first = Coordinator(firmware, root / "state", no_qemu=True)
                summary = first.run()
                first_count = len(assistant_calls)
                Coordinator(firmware, root / "state", no_qemu=True).run()
            self.assertEqual(summary["detective"]["complete"], 2)
            self.assertEqual(len(assistant_calls), first_count)
            jobs = first.state.list_jobs("assistant")
            full_set = max(jobs, key=lambda job: len(job["payload"]["confirmed_vulns"]))
            ids = [claim["vuln_id"] for claim in full_set["payload"]["confirmed_vulns"]]
            self.assertEqual(len(ids), 2)
            self.assertEqual(len(set(ids)), 2)

    def test_confirmation_requires_executed_evidence(self):
        claim = {"vuln_id": "VULN-1", "source_task_id": "poc_1",
                 "trigger_confirmed": True}
        result = {"task_id": "poc_1", "status": "completed", "findings": [],
                  "evidence": ["local output"], "inferences": [],
                  "vdp_assessment": {"trigger_confirmed": True},
                  "test_results": {"executed": False, "evidence": ""}}
        checked = validate_worker_result(result, "poc_1")
        roadmap = {"confirmed_vulns": [claim.copy()]}
        self.assertEqual(validate_confirmed_vulns(
            roadmap, [{"task_id": "poc_1", "result": checked}])["confirmed_vulns"], [])
        result["test_results"] = {"executed": True, "command": "local-test --fixture",
                                  "exit_code": 0, "evidence": "observed trigger"}
        result["vdp_assessment"]["trigger_confirmed"] = True
        checked = validate_worker_result(result, "poc_1")
        roadmap = {"confirmed_vulns": [claim.copy()]}
        self.assertEqual(len(validate_confirmed_vulns(
            roadmap, [{"task_id": "poc_1", "result": checked}])["confirmed_vulns"]), 1)

    def test_chain_success_requires_an_executed_full_chain_test(self):
        roadmap = {"confirmed_chain": {"chain_tested": True, "chain_working": True}}
        task = {"task_id": "chain_1", "result": {"test_result": {
            "executed": False, "full_chain_success": True,
            "evidence_files": ["expected.txt"],
        }}}
        checked = validate_confirmed_chain(roadmap, [task])
        self.assertFalse(checked["confirmed_chain"]["chain_working"])
        self.assertFalse(checked["confirmed_chain"]["chain_tested"])
        task["result"]["test_result"]["executed"] = True
        checked = validate_confirmed_chain({"confirmed_chain": {
            "chain_tested": True, "chain_working": True,
        }}, [task])
        self.assertFalse(checked["confirmed_chain"]["chain_working"])
        task["result"]["test_result"].update({
            "command": "python3 local-chain.py --fixture", "exit_code": 0})
        checked = validate_confirmed_chain({"confirmed_chain": {
            "chain_tested": True, "chain_working": True,
        }}, [task])
        self.assertTrue(checked["confirmed_chain"]["chain_working"])

    def test_component_claim_requires_local_and_source_evidence(self):
        result = validate_worker_result({
            "task_id": "scan_1", "status": "completed", "findings": [],
            "components": [{"product": "example", "version": "1.0",
                            "advisories_checked": True, "cve_ids": ["CVE-0000-0000"],
                            "applicability": "confirmed"}],
        }, "scan_1")
        component = result["components"][0]
        self.assertFalse(component["advisories_checked"])
        self.assertEqual(component["cve_ids"], [])
        self.assertEqual(component["applicability"], "unknown")

    def test_public_certificate_is_not_static_secret(self):
        checked = validate_worker_result({
            "task_id": "sp_secrets_example", "status": "completed", "findings": [],
            "suspected_findings": [{
                "file_path": "/tmp/server.crt", "line_or_offset": "1",
                "location": "/tmp/server.crt:1", "title": "public certificate",
                "observation": "public certificate in trust store",
                "category": "credential", "input_path": "embedded constant",
                "use_path": "TLS trust store", "evidence": ["server.crt:1 certificate"],
                "disposition": "static_verified",
            }],
        }, "sp_secrets_example")
        self.assertEqual(checked["suspected_findings"][0]["disposition"],
                         "insufficient_evidence")

    def test_cve_string_without_affected_code_cannot_request_detective(self):
        checked = validate_worker_result({
            "task_id": "sp_components_example", "status": "completed", "findings": [],
            "suspected_findings": [{
                "file_path": "/tmp/lib.so", "line_or_offset": "0x10",
                "location": "/tmp/lib.so+0x10", "title": "CVE match",
                "category": "component", "input_path": "network input",
                "use_path": "library parser", "evidence": ["lib.so+0x10"],
                "disposition": "needs_dynamic_verification",
            }],
            "components": [{"product": "example", "version": "1.0",
                            "version_evidence": ["manifest:1"],
                            "configuration_evidence": ["config:2"],
                            "affected_code_evidence": [],
                            "advisories_checked": True,
                            "advisory_sources": ["https://vendor.example/advisory"],
                            "cve_ids": ["CVE-0000-0000"], "applicability": "confirmed"}],
        }, "sp_components_example")
        self.assertEqual(checked["components"][0]["applicability"], "unknown")
        self.assertEqual(checked["suspected_findings"][0]["disposition"],
                         "needs_static_research")

    def test_offline_worker_does_not_claim_external_cve_lookup(self):
        answer = {"task_id": "scan_1", "status": "completed", "findings": [],
                  "components": [{"product": "example", "version": "1.0",
                                  "version_evidence": ["manifest:1"],
                                  "advisories_checked": True,
                                  "advisory_sources": ["https://vendor.example/advisory"],
                                  "cve_ids": ["CVE-0000-0000"],
                                  "applicability": "confirmed"}]}
        worker = InvestigatorWorker("gpt-6-sol", network_access=False)
        with patch.object(worker, "_call_codex", return_value=(json.dumps(answer), None)):
            result = worker.execute({"task_id": "scan_1", "prompt": "review"}, None,
                                    "/tmp/firmware.bin", "/tmp/extracted")
        component = result["components"][0]
        self.assertFalse(component["advisories_checked"])
        self.assertEqual(component["cve_ids"], [])
        self.assertEqual(component["applicability"], "unknown")

    def test_network_enabled_component_check_keeps_primary_source_record(self):
        answer = {"task_id": "scan_1", "status": "completed", "findings": [],
                  "components": [{"product": "example", "version": "1.0",
                                  "version_evidence": ["manifest:1"],
                                  "configuration_evidence": ["config:2"],
                                  "advisories_checked": True,
                                  "advisory_sources": ["https://vendor.example/advisory"],
                                  "cve_ids": ["CVE-0000-0000"],
                                  "applicability": "possible"}]}
        worker = InvestigatorWorker("gpt-6-sol", network_access=True)
        prompts = []

        def fake_call(prompt, session_id):
            prompts.append(prompt)
            return json.dumps(answer), None

        with patch.object(worker, "_call_codex", side_effect=fake_call):
            result = worker.execute({"task_id": "scan_1", "prompt": "review"}, None,
                                    "/tmp/firmware.bin", "/tmp/extracted")
        self.assertTrue(result["components"][0]["advisories_checked"])
        self.assertEqual(result["components"][0]["cve_ids"], ["CVE-0000-0000"])
        self.assertIn("never upload firmware", prompts[0])

    def test_network_flag_is_restricted_to_component_specialist(self):
        worker = InvestigatorWorker("gpt-6-sol", network_access=True)
        answer = {"task_id": "sp_secrets_1", "status": "completed",
                  "findings": [], "suspected_findings": [], "reviewed_files": []}
        with patch.object(worker, "_call_codex", return_value=(json.dumps(answer), None)) as call:
            worker.execute({"task_id": "sp_secrets_1", "specialist_id": "secrets",
                            "prompt": "inspect", "scope_files": []}, None,
                           "/tmp/firmware.bin", "/tmp/extracted")
        self.assertFalse(call.call_args.kwargs["network_access"])
        self.assertIn("do not perform a separate CVE lookup", call.call_args.args[0])

    def test_offline_component_worker_cannot_confirm_a_cve_claim(self):
        answer = {"task_id": "sp_components_1", "status": "completed", "findings": [],
                  "suspected_findings": [{
                      "file_path": "/tmp/lib.so", "line_or_offset": "0x10",
                      "location": "/tmp/lib.so+0x10", "title": "candidate",
                      "category": "component", "input_path": "network input",
                      "use_path": "library parser", "evidence": ["lib.so+0x10"],
                      "disposition": "needs_dynamic_verification",
                  }],
                  "components": [{"product": "example", "version": "1.0",
                                  "version_evidence": ["manifest:1"],
                                  "configuration_evidence": ["config:2"],
                                  "affected_code_evidence": ["lib.so+0x10"],
                                  "advisories_checked": True,
                                  "advisory_sources": ["https://vendor.example/advisory"],
                                  "cve_ids": ["CVE-0000-0000"],
                                  "applicability": "confirmed"}]}
        worker = InvestigatorWorker("gpt-6-sol", network_access=False)
        with patch.object(worker, "_call_codex", return_value=(json.dumps(answer), None)):
            result = worker.execute({"task_id": "sp_components_1",
                                     "specialist_id": "components",
                                     "prompt": "inspect", "scope_files": []}, None,
                                    "/tmp/firmware.bin", "/tmp/extracted")
        self.assertEqual(result["components"][0]["cve_ids"], [])
        self.assertEqual(result["components"][0]["applicability"], "unknown")
        self.assertEqual(result["suspected_findings"][0]["disposition"],
                         "needs_static_research")

    def test_report_includes_integrated_scope_and_stage_status(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            session = root / "session"
            session.mkdir()
            (session / "firmware_info.json").write_text(json.dumps({
                "filename": "fixture.bin", "size_bytes": 12, "hashes": {},
            }))
            (session / "scan_scope.json").write_text(json.dumps({
                "targets": ["/tmp/a.sh", "/tmp/b.conf"],
                "tasks": [{"type": "file_analysis"}],
                "inventory": [{"path": "/tmp/link", "status": "skipped",
                               "reason": "symlink target is not followed"}],
            }))
            (session / "coordinator_status.json").write_text(json.dumps({
                "first_detective_start_seconds": 0.05, "elapsed_seconds": 0.2,
                "stages": {"investigator": {"complete": 1},
                           "detective": {"complete": 1, "failed": 1}},
                "jobs": [{"kind": "detective", "key": "site-key", "status": "complete",
                          "payload": {"stable_id": "site-key"},
                          "result": {"session_path": "/tmp/detective-session",
                                     "confirmed_vulns": [{"title": "verified issue",
                                                           "evidence": ["observed local trigger"]}]}}],
            }))
            with patch("report_generator._call_codex", return_value={"vulnerabilities": []}), \
                 redirect_stdout(io.StringIO()):
                path = generate_report(str(session), str(root / "report"))
            html = Path(path).read_text()
            self.assertIn("탐지된 추출 파일 2개", html)
            self.assertIn("연계 작업 상태", html)
            self.assertIn("작업별 상태", html)
            self.assertIn("detective", html)
            self.assertIn("건너뛴 항목 1개", html)
            self.assertIn("verified issue", html)
            self.assertIn("observed local trigger", html)

    def test_report_distinguishes_static_specialist_finding_and_no_clue(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            session = root / "session"
            session.mkdir()
            file_path = str(root / "secret.conf")
            Path(file_path).write_text("password=strong-value\n")
            (session / "firmware_info.json").write_text(json.dumps({
                "filename": "fixture.bin", "size_bytes": 12, "hashes": {},
            }))
            (session / "scan_scope.json").write_text(json.dumps({
                "mode": "specialists", "targets": [file_path, str(root / "data.dat")],
                "inventory": [],
                "tasks": [{"task_id": "sp_secrets_1", "specialist_id": "secrets"}],
                "specialists": [{"id": "secrets", "name": "비밀정보",
                                 "status": "scheduled", "task_count": 1,
                                 "prompt_version": "abc"}],
                "file_routing": [
                    {"path": file_path, "status": "scheduled", "specialists": ["secrets"]},
                    {"path": str(root / "data.dat"), "status": "no_applicable_clue",
                     "specialists": []},
                ],
            }))
            with (session / "task_results.jsonl").open("w") as stream:
                stream.write(json.dumps({
                    "task_id": "sp_secrets_1", "type": "specialist_analysis",
                    "specialist_id": "secrets", "prompt_version": "abc",
                    "scope_files": [file_path], "result": {
                        "task_id": "sp_secrets_1", "status": "completed",
                        "reviewed_files": [file_path],
                        "suspected_findings": [{
                            "finding_id": "sp_secrets_1-001", "location": file_path + ":1",
                            "file_path": file_path, "line_or_offset": "1",
                            "title": "embedded credential", "category": "credential",
                            "observation": "password=strong-value",
                            "evidence": ["secret.conf:1 password=strong-value"],
                            "disposition": "static_verified", "impact_tags": ["access"],
                        }],
                    },
                }) + "\n")
            with patch("report_generator._call_codex", return_value={
                    "vulnerabilities": [], "executive_summary": "strong-value is embedded"}), \
                 redirect_stdout(io.StringIO()):
                path = generate_report(str(session), str(root / "report"))
            html = Path(path).read_text()
            self.assertIn("정적 근거 확인", html)
            self.assertIn("전담 분야 적용 상태", html)
            self.assertIn("적용 단서 없음은 취약점 없음이 아닙니다", html)
            self.assertNotIn("strong-value", html)

    def test_same_firmware_cannot_run_in_two_coordinators(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, session, extracted = self._fixture(root)
            entered = threading.Event()
            release = threading.Event()

            def fake_analysis(path, settings, **kwargs):
                kwargs["on_extracted"](session, {}, str(extracted))
                entered.set()
                self.assertTrue(release.wait(2))
                return session

            with patch("coordinator.main.run_analysis", side_effect=fake_analysis), \
                 patch("report_generator.generate_report", return_value="report.html"):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    first = pool.submit(Coordinator(firmware, root / "state").run)
                    self.assertTrue(entered.wait(1))
                    with self.assertRaisesRegex(RuntimeError, "already being processed"):
                        Coordinator(firmware, root / "state").run()
                    release.set()
                    first.result(timeout=2)

    def test_extraction_failure_is_persisted_for_resume(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, _, _ = self._fixture(root)

            def fail_extraction(path, settings, **kwargs):
                session = Path(settings["analysis"]["sessions_dir"]) / "fixture" / "attempt"
                session.mkdir(parents=True)
                (session / "extraction.json").write_text(json.dumps({
                    "status": "failed", "error": "missing binwalk",
                }))
                raise ExtractionError("missing binwalk")

            coordinator = Coordinator(firmware, root / "state")
            with patch("coordinator.main.run_analysis", side_effect=fail_extraction):
                with self.assertRaisesRegex(ExtractionError, "missing binwalk"):
                    coordinator.run()
            status = json.loads((coordinator.directory / "pipeline_status.json").read_text())
            self.assertEqual(status["stages"]["investigator"]["failed"], 1)
            self.assertTrue(Path(status["investigator_session"], "extraction.json").exists())

    def test_detective_requests_lab_when_planner_needs_environment(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            firmware, session, _ = self._fixture(root)
            settings = json.loads(Path("detective/settings.json").read_text())
            settings["analysis"]["sessions_dir"] = str(root / "detective-sessions")
            settings["analysis"]["qemu_lock_dir"] = str(root / "locks")
            lab_calls = []
            stops = []
            roadmap = {"status": "complete", "analysis_summary": "environment needed",
                       "new_tasks": [], "confirmed_vulns": [],
                       "lab_required": True, "lab_reason": "boot not verified"}

            def fake_lab(*args):
                lab_calls.append(1)
                with file_lock(root / "locks", "qemu-host-ports") as lease:
                    self.assertTrue(lease)
                    return {"status": "complete", "verification": {"qemu_boots": False}}

            with patch("detective.main.load_investigator_session",
                       return_value=({"path": str(firmware)}, [], "")), \
                 patch("detective.main.QemuRunner.start", return_value={"started": True,
                       "pid": 123, "arch": "arm", "connection_info": "local"}), \
                 patch("detective.main.QemuRunner.stop", side_effect=lambda: stops.append(1)), \
                 patch("detective.main.Detective.decide", return_value=roadmap), \
                 patch("report_generator.generate_report", return_value="report.html"), \
                 redirect_stdout(io.StringIO()):
                result = run_detective(str(session), settings, str(firmware),
                                       lab_request=fake_lab)
            self.assertEqual(len(lab_calls), 1)
            self.assertTrue(stops)
            self.assertFalse(result["lab"]["verification"]["qemu_boots"])


if __name__ == "__main__":
    unittest.main()
