"""Measure pipeline scheduling with synthetic, local-only stage workers."""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from coordinator.main import Coordinator


def main() -> None:
    file_count = 4
    review_delay = 0.04
    detective_delay = 0.08
    with tempfile.TemporaryDirectory() as temporary_dir:
        root = Path(temporary_dir)
        firmware = root / "synthetic.bin"
        firmware.write_bytes(b"synthetic firmware fixture")
        session = root / "investigator-session"
        session.mkdir()
        extracted = session / "extracted"
        extracted.mkdir()
        (session / "firmware_info.json").write_text(json.dumps({
            "filename": firmware.name, "hashes": {"sha256": "fixture"},
        }))

        def fake_analysis(path, settings, **kwargs):
            kwargs["on_extracted"](session, {}, str(extracted))
            for index in range(file_count):
                time.sleep(review_delay)
                kwargs["on_finding"]({
                    "finding_id": f"scan_{index + 1:04d}-001",
                    "location": f"{extracted}/file{index}.sh:1",
                    "title": f"candidate {index}",
                    "evidence": [f"file{index}:1"],
                }, {"task_id": f"scan_{index + 1:04d}"}, session)
            return session

        def fake_detective(*args, **kwargs):
            time.sleep(detective_delay)
            return {"session_path": str(root / "detective"),
                    "confirmed_vulns": []}

        with patch("coordinator.main.run_analysis", side_effect=fake_analysis), \
             patch("coordinator.main.run_detective", side_effect=fake_detective), \
             patch("report_generator.generate_report", return_value="mock-report.html"):
            coordinator = Coordinator(firmware, root / "state",
                                      detective_limit=2, no_qemu=True)
            coordinator.run()

        status = json.loads((coordinator.directory / "pipeline_status.json").read_text())
        print(json.dumps({
            "first_detective_start_seconds": status["first_detective_start_seconds"],
            "elapsed_seconds": status["elapsed_seconds"],
            "serial_sleep_baseline_seconds": round(
                file_count * (review_delay + detective_delay), 3),
            "detective_jobs": status["stages"]["detective"]["complete"],
        }, indent=2))


if __name__ == "__main__":
    main()
