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


def validate_worker_result(result: dict, task_id: str,
                           *, expected_finding_id: str | None = None) -> dict:
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
    suspected = result.setdefault("suspected_findings", [])
    if not isinstance(suspected, list):
        raise ValueError(f"Task {task_id} needs a suspected_findings list")
    for index, item in enumerate(suspected, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Task {task_id} has an invalid suspected finding")
        item["finding_id"] = f"{task_id}-{index:03d}"
        for field in ("location", "title", "category", "observation", "inference",
                      "recommendation"):
            if not isinstance(item.get(field, ""), str):
                raise ValueError(f"Task {task_id} has invalid {field} in suspected finding")
        item_evidence = item.setdefault("evidence", [])
        if not isinstance(item_evidence, list) or any(
                not isinstance(value, str) for value in item_evidence):
            raise ValueError(f"Task {task_id} has invalid suspected finding evidence")
        for value in item_evidence:
            if value and value not in result["evidence"]:
                result["evidence"].append(value)
    reviewed = result.setdefault("reviewed_files", [])
    if not isinstance(reviewed, list) or any(not isinstance(path, str) for path in reviewed):
        raise ValueError(f"Task {task_id} needs a reviewed_files list")
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
    if any(not item["evidence"] or not item.get("location") for item in suspected):
        if result["status"] == "completed":
            result["status"] = "partial"
        result["follow_up_needed"] = True
        result["follow_up_reason"] = "A suspected code site lacks a location or direct evidence"

    investigation = result.get("investigation")
    if investigation is not None:
        if not isinstance(investigation, dict):
            raise ValueError(f"Task {task_id} needs an investigation object")
        if investigation.get("assessment") not in {"supported", "weakened", "undetermined"}:
            raise ValueError(f"Task {task_id} has an invalid investigation assessment")
        for field in ("entry_points", "data_flow", "controls", "counterevidence",
                      "evidence", "unknowns"):
            values = investigation.get(field, [])
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                raise ValueError(f"Task {task_id} needs a list of strings for investigation.{field}")
            investigation[field] = values
        if not isinstance(investigation.get("impact", ""), str):
            raise ValueError(f"Task {task_id} has an invalid investigation impact")
    if expected_finding_id and (
            not investigation or investigation.get("source_finding_id") != expected_finding_id):
        if result["status"] == "completed":
            result["status"] = "partial"
        result["follow_up_needed"] = True
        result["follow_up_reason"] = "Investigation did not identify its source finding"

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


REPORT_FINDING_TYPES = {
    "vulnerability_scan", "code_analysis", "crypto_analysis",
    "network_analysis", "filesystem_analysis", "patch_diff_analysis",
}
REPORT_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def collect_report_candidates(completed_tasks: list[dict]) -> list[dict]:
    """Preserve each worker code site as a separate report candidate."""
    candidates = []
    for task in completed_tasks:
        task_id = task.get("task_id")
        if not task_id:
            continue
        structured = task.get("suspected_findings") or []
        if structured:
            for index, item in enumerate(structured, 1):
                if not isinstance(item, dict):
                    continue
                evidence = item.get("evidence") or []
                candidates.append({
                    "finding_id": item.get("finding_id") or f"{task_id}-{index:03d}",
                    "source_task": task_id,
                    "location": item.get("location") or "위치 미기록",
                    "title": item.get("title") or "제목 미기록 의심 위치",
                    "category": item.get("category") or "추가 분류 필요",
                    "observation": item.get("observation") or "",
                    "evidence": [value for value in evidence if isinstance(value, str) and value],
                    "inference": item.get("inference") or "",
                    "recommendation": item.get("recommendation") or "",
                })
        elif task.get("type") in REPORT_FINDING_TYPES:
            evidence = task.get("evidence") or []
            for index, finding in enumerate(task.get("findings") or [], 1):
                if not isinstance(finding, str) or not finding.strip():
                    continue
                candidates.append({
                    "finding_id": f"{task_id}-legacy-{index:03d}",
                    "source_task": task_id,
                    "location": "위치 미기록",
                    "title": finding,
                    "category": "추가 분류 필요",
                    "observation": "",
                    "evidence": [value for value in evidence if isinstance(value, str) and value],
                    "inference": "작업 전체의 근거와 개별 발견사항의 연결은 재검토가 필요합니다.",
                    "recommendation": "정확한 코드 위치와 근거를 확인하세요.",
                })
    return candidates


def _report_verification(source: dict, evidence: list[str]) -> str:
    if not evidence:
        return "근거 미기록"
    assessment = source.get("vdp_assessment")
    test = source.get("test_results")
    assessment = assessment if isinstance(assessment, dict) else {}
    test = test if isinstance(test, dict) else {}
    if (test.get("executed") is True and test.get("evidence") and
            assessment.get("trigger_confirmed") is True):
        return "재현 확인"
    if test.get("executed") is True:
        return "이번 테스트 미재현"
    return "재현 미실시"


def validate_report(report: dict, completed_tasks: list[dict]) -> dict:
    if not isinstance(report, dict) or not isinstance(report.get("vulnerabilities"), list):
        raise ValueError("Report needs a vulnerabilities list")
    sources = {task["task_id"]: task for task in completed_tasks if task.get("task_id")}
    candidates = collect_report_candidates(completed_tasks)
    by_id = {candidate["finding_id"]: candidate for candidate in candidates}
    by_task = {}
    for candidate in candidates:
        by_task.setdefault(candidate["source_task"], []).append(candidate)

    accepted = []
    seen = set()
    omitted = 0
    for vulnerability in report["vulnerabilities"]:
        if not isinstance(vulnerability, dict):
            omitted += 1
            continue
        source_id = vulnerability.get("source_task")
        source = sources.get(source_id)
        matched = by_id.get(vulnerability.get("source_finding_id"))
        if matched and matched["source_task"] != source_id:
            matched = None
        if not matched and vulnerability.get("location"):
            at_location = [candidate for candidate in by_task.get(source_id, [])
                           if candidate["location"] == vulnerability["location"]]
            if len(at_location) == 1:
                matched = at_location[0]
        if not matched and len(by_task.get(source_id, [])) == 1:
            matched = by_task[source_id][0]
        if matched:
            finding_id = matched["finding_id"]
            if finding_id in seen:
                continue
            seen.add(finding_id)
            evidence = matched["evidence"]
            vulnerability.update({
                "source_finding_id": finding_id,
                "location": matched["location"],
                "title": matched["title"],
                "category": matched["category"],
                "evidence": "; ".join(evidence),
            })
            vulnerability["description"] = vulnerability.get("description") or matched["observation"]
            vulnerability["inference"] = vulnerability.get("inference") or matched["inference"]
            vulnerability["recommendation"] = vulnerability.get("recommendation") or matched["recommendation"]
        elif by_task.get(source_id):
            omitted += 1
            continue
        else:
            evidence = source.get("evidence") if source else None
            if (not isinstance(evidence, list) or not evidence or
                    any(not isinstance(item, str) for item in evidence)):
                omitted += 1
                continue
            vulnerability["evidence"] = "; ".join(evidence)
        if vulnerability.get("severity") not in REPORT_SEVERITIES or not evidence:
            vulnerability["severity"] = "info"
        vulnerability["verification_status"] = _report_verification(source, evidence)
        vulnerability["id"] = f"FBI-{len(accepted) + 1:03d}"
        accepted.append(vulnerability)

    backfilled = 0
    for candidate in candidates:
        if candidate["finding_id"] in seen:
            continue
        backfilled += 1
        source = sources[candidate["source_task"]]
        evidence = candidate["evidence"]
        accepted.append({
            "id": f"FBI-{len(accepted) + 1:03d}",
            "source_task": candidate["source_task"],
            "source_finding_id": candidate["finding_id"],
            "location": candidate["location"],
            "title": candidate["title"],
            "category": candidate["category"],
            "severity": "info",
            "description": candidate["observation"],
            "evidence": "; ".join(evidence),
            "inference": candidate["inference"],
            "impact": "영향 미평가",
            "recommendation": candidate["recommendation"],
            "verification_status": _report_verification(source, evidence),
        })
    reported_by_finding = {item.get("source_finding_id"): item for item in accepted
                           if item.get("source_finding_id")}
    for task in completed_tasks:
        research = task.get("investigation")
        if not isinstance(research, dict):
            continue
        target = reported_by_finding.get(research.get("source_finding_id"))
        if target:
            target["research"] = research
    report["vulnerabilities"] = accepted
    report["candidate_count"] = len(candidates)
    limitations = report.get("limitations")
    if not isinstance(limitations, list):
        limitations = []
    limitations = [item for item in limitations if isinstance(item, str) and item.strip()]
    if not completed_tasks:
        limitations.append("저장된 작업 결과가 없어 발견사항을 검증할 수 없습니다.")
    elif not any(v["verification_status"] == "재현 확인" for v in accepted):
        limitations.append("실행 결과와 증거로 확인된 취약점 트리거가 없습니다.")
    unfinished = sum(task.get("status") in {"partial", "failed"} for task in completed_tasks)
    if unfinished:
        limitations.append(f"부분 완료 또는 실패한 작업 {unfinished}건은 검증이 끝나지 않았습니다.")
    if omitted:
        limitations.append(f"출처 작업 또는 개별 근거가 확인되지 않은 보고 항목 {omitted}건을 제외했습니다.")
    if backfilled:
        limitations.append(f"모델 요약에서 빠진 의심 위치 {backfilled}건을 작업 기록에서 보완했습니다. 심각도는 미평가입니다.")
    if any(not candidate["evidence"] for candidate in candidates):
        limitations.append("일부 의심 위치에는 관찰 근거가 기록되지 않았습니다.")
    unresearched = sum(bool(item.get("source_finding_id")) and not item.get("research")
                       for item in accepted)
    if unresearched:
        limitations.append(f"의심 위치 {unresearched}건은 위치별 심층 조사 기록이 없습니다.")
    report["limitations"] = list(dict.fromkeys(limitations))
    severity_order = ["critical", "high", "medium", "low", "info"]
    risk_names = {"critical": "Critical", "high": "High", "medium": "Medium",
                  "low": "Low", "info": "Informational"}
    highest = next((level for level in severity_order
                    if any(v.get("severity") == level for v in accepted)), "info")
    report["overall_risk"] = risk_names[highest]
    return report
