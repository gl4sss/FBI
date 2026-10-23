"""Create required system and finding research tasks from saved observations."""

from shared.validation import collect_report_candidates


def baseline_tasks() -> list[dict]:
    return [
        {
            "task_id": "research_surface",
            "type": "other",
            "priority": "high",
            "prompt": (
                "Map the extracted firmware's attack surface. Inspect boot and init paths, "
                "service configuration, network listeners, web handlers, authentication, "
                "privilege boundaries, writable paths, and secret storage where present. "
                "Cite the exact files and lines or offsets supporting each observed entry "
                "point and trust boundary. Distinguish enabled services from installed "
                "components, and state what cannot be established statically. Record each "
                "distinct suspicious site in suspected_findings. Finish with concrete gaps "
                "and follow-up questions, not a generic summary."
            ),
        },
        {
            "task_id": "research_components",
            "type": "other",
            "priority": "high",
            "prompt": (
                "Inventory executables, third-party components, version evidence, "
                "cryptographic settings, update and signature checks, and relevant default "
                "configuration. Inspect the extracted artifacts rather than inferring from "
                "a filename or isolated string. For any possible known issue, state the "
                "precise version/configuration evidence and what remains unverified; do "
                "not invent CVE matches or consult the network unless it is enabled. "
                "Record distinct suspicious sites in suspected_findings with locations "
                "and direct evidence. Summarize concrete next checks and limitations."
            ),
        },
    ]


def finding_research_tasks(completed_tasks: list[dict]) -> list[dict]:
    """Give every initial code finding its own stable investigation task."""
    initial_results = []
    for task in completed_tasks:
        if (str(task.get("task_id", "")).startswith("scan_") or
                task.get("task_id") in {"research_surface", "research_components"}):
            result = task.get("result") or {}
            initial_results.append({"task_id": task["task_id"],
                                    "type": task.get("type"), **result})
    tasks = []
    for candidate in collect_report_candidates(initial_results):
        finding_id = candidate["finding_id"]
        task_id = f"research_{finding_id}"
        evidence = "; ".join(candidate["evidence"]) or "No direct evidence recorded"
        tasks.append({
            "task_id": task_id,
            "type": "finding_investigation",
            "priority": "high",
            "source_finding_id": finding_id,
            "prompt": (
                f"Investigate this saved suspicious location: {finding_id}. "
                f"Location: {candidate['location']}. Title: {candidate['title']}. "
                f"Initial observation: {candidate['observation']}. Evidence: {evidence}. "
                "Inspect the surrounding implementation and relevant callers, entry "
                "points, input origin, transformations, guards, sink, runtime/configuration "
                "prerequisites, and plausible impact. Seek counterevidence and alternative "
                "explanations. Cite exact file:line or binary offsets for each conclusion. "
                "Use read-only checks; do not perform an exploit or claim runtime reachability "
                "without an executed test. Fill investigation with an assessment and explicit "
                "unknowns. If a question cannot be answered, report the blocker and a "
                "focused next check. Record any newly discovered distinct sites separately."
            ),
        })
    return tasks
