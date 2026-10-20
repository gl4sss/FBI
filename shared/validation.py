"""Validate model output before it changes the analysis state."""


TASK_STATUSES = {"completed", "partial", "failed"}
ROADMAP_STATUSES = {"in_progress", "complete", "blocked"}


def validate_roadmap(roadmap: dict, completed_tasks: list[dict],
                     *, allow_blocked: bool = False) -> dict:
    if not isinstance(roadmap, dict):
        raise ValueError("Orchestrator response must be a JSON object")
    allowed = ROADMAP_STATUSES if allow_blocked else ROADMAP_STATUSES - {"blocked"}
    if roadmap.get("status") not in allowed:
        raise ValueError("Orchestrator returned an invalid status")
    if not isinstance(roadmap.get("analysis_summary"), str):
        raise ValueError("Orchestrator response needs analysis_summary")
    tasks = roadmap.get("new_tasks")
    if not isinstance(tasks, list):
        raise ValueError("Orchestrator response needs a new_tasks list")
    if roadmap["status"] != "in_progress" and tasks:
        raise ValueError("A finished or blocked roadmap cannot dispatch tasks")

    seen = {task.get("task_id") for task in completed_tasks}
    for task in tasks:
        if not isinstance(task, dict):
            raise ValueError("Each new task must be an object")
        task_id = task.get("task_id")
        if not isinstance(task_id, str) or not task_id or task_id in seen:
            raise ValueError(f"Duplicate or invalid task ID: {task_id}")
        if not isinstance(task.get("prompt"), str) or not task["prompt"].strip():
            raise ValueError(f"Task {task_id} needs a prompt")
        seen.add(task_id)

    return roadmap


def validate_worker_result(result: dict, task_id: str) -> dict:
    if not isinstance(result, dict):
        raise ValueError("Worker response must be a JSON object")
    if result.get("task_id") != task_id:
        raise ValueError(f"Worker returned a different task ID for {task_id}")
    if result.get("status") not in TASK_STATUSES:
        raise ValueError(f"Task {task_id} returned an invalid status")
    for field in ("findings", "evidence", "inferences"):
        value = result.setdefault(field, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"Task {task_id} needs a list of strings for {field}")
    if not isinstance(result.get("analysis", ""), str):
        raise ValueError(f"Task {task_id} needs analysis text")
    for field in ("test_results", "test_result", "vdp_assessment",
                  "environment_update", "verification"):
        if result.get(field) is not None and not isinstance(result[field], dict):
            raise ValueError(f"Task {task_id} needs an object for {field}")

    if result["findings"] and not result["evidence"]:
        if result["status"] == "completed":
            result["status"] = "partial"
        result["follow_up_needed"] = True
        result["follow_up_reason"] = "Findings have no cited observation or artifact"

    assessment = result.get("vdp_assessment")
    if isinstance(assessment, dict) and assessment.get("trigger_confirmed") is True:
        test = result.get("test_results") or {}
        if test.get("executed") is not True or not test.get("evidence"):
            assessment.update(trigger_confirmed=None, evidence_strength="None",
                              cve_worthy=False, vdp_suitable=False)
            if result["status"] == "completed":
                result["status"] = "partial"
            result["follow_up_needed"] = True
            result["follow_up_reason"] = "Trigger claim lacks an executed test and observed evidence"

    return result


def validate_confirmed_vulns(roadmap: dict, completed_tasks: list[dict]) -> dict:
    claims = roadmap.get("confirmed_vulns", [])
    if not isinstance(claims, list):
        raise ValueError("confirmed_vulns must be a list")
    tested = {}
    for task in completed_tasks:
        result = task.get("result") or {}
        assessment = result.get("vdp_assessment") or {}
        test = result.get("test_results") or {}
        if (assessment.get("trigger_confirmed") is True and
                test.get("executed") is True and test.get("evidence")):
            tested[task.get("task_id")] = result

    confirmed = []
    warnings = []
    for claim in claims:
        if not isinstance(claim, dict) or not isinstance(claim.get("vuln_id"), str):
            raise ValueError("Each confirmed vulnerability needs a vuln_id")
        source = claim.get("source_task_id")
        result = tested.get(source)
        if claim.get("trigger_confirmed") is not True or result is None:
            warnings.append(f"{claim['vuln_id']}: no matching executed test with evidence")
            continue
        claim["evidence"] = result.get("evidence", []) + [result["test_results"]["evidence"]]
        claim["inferences"] = result.get("inferences", [])
        confirmed.append(claim)

    roadmap["confirmed_vulns"] = confirmed
    if warnings:
        roadmap["validation_warnings"] = warnings
    return roadmap


def validate_report(report: dict, completed_tasks: list[dict]) -> dict:
    if not isinstance(report, dict) or not isinstance(report.get("vulnerabilities"), list):
        raise ValueError("Report needs a vulnerabilities list")
    sources = {task["task_id"]: task for task in completed_tasks if task.get("task_id")}
    accepted = []
    for vulnerability in report["vulnerabilities"]:
        if not isinstance(vulnerability, dict):
            continue
        source = sources.get(vulnerability.get("source_task"))
        evidence = source.get("evidence") if source else None
        if not isinstance(evidence, list) or not evidence:
            continue
        vulnerability["evidence"] = "; ".join(evidence)
        accepted.append(vulnerability)
    report["vulnerabilities"] = accepted
    severity_order = ["critical", "high", "medium", "low", "info"]
    risk_names = {"critical": "Critical", "high": "High", "medium": "Medium",
                  "low": "Low", "info": "Informational"}
    highest = next((level for level in severity_order
                    if any(v.get("severity") == level for v in accepted)), "info")
    report["overall_risk"] = risk_names[highest]
    return report
