"use strict";

const SVG = "http://www.w3.org/2000/svg";
const graph = document.getElementById("graph");
const statusNames = {
  waiting: "대기 중", no_clue: "적용 단서 없음", pending: "대기",
  running: "실행 중", partial: "부분 완료", complete: "완료", failed: "실패",
};
let latest = null;
let selected = null;
let loading = false;
let confirmedFingerprint = "";
let currentRunFingerprint = "";

function svg(tag, attrs = {}, parent = graph) {
  const element = document.createElementNS(SVG, tag);
  for (const [name, value] of Object.entries(attrs)) element.setAttribute(name, String(value));
  parent.appendChild(element);
  return element;
}

function label(x, y, value, className, parent = graph) {
  const element = svg("text", {x, y, class: className}, parent);
  element.textContent = value;
  return element;
}

function edge(x1, y1, x2, y2, className = "") {
  const middle = (x1 + x2) / 2;
  svg("path", {d: `M ${x1} ${y1} C ${middle} ${y1}, ${middle} ${y2}, ${x2} ${y2}`,
               class: `edge ${className}`});
}

function node(x, y, width, title, meta, status, details, count = "") {
  const group = svg("g", {class: `node ${status}`, tabindex: 0, role: "button",
                          "aria-label": `${title}, ${statusNames[status] || status}`});
  svg("rect", {x, y, width, height: 54, rx: 11}, group);
  svg("circle", {cx: x + 17, cy: y + 19, r: 4.5, class: `status-dot ${status}`}, group);
  label(x + 29, y + 24, title, "node-title", group);
  label(x + 17, y + 43, meta, "node-meta", group);
  if (count) label(x + width - 41, y + 23, count, "node-count", group);
  const activate = () => showDetails(title, status, details);
  group.addEventListener("click", activate);
  group.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      activate();
    }
  });
}

function showDetails(title, status, lines) {
  selected = title;
  document.getElementById("detail-title").textContent = title;
  const body = document.getElementById("detail-body");
  body.replaceChildren();
  for (const line of [statusNames[status] || status, ...lines]) {
    const part = document.createElement("span");
    part.textContent = line;
    body.appendChild(part);
  }
}

function stageStatus(items) {
  if (!items.length) return "waiting";
  if (items.some(item => item.status === "running")) return "running";
  if (items.some(item => item.status === "failed")) return "failed";
  if (items.some(item => item.status === "partial")) return "partial";
  if (items.some(item => item.status === "pending")) return "pending";
  return "complete";
}

function renderCurrentRun(data) {
  const run = data.current_run || {status: "waiting", active_count: 0, active_jobs: []};
  const fingerprint = JSON.stringify(run);
  if (fingerprint === currentRunFingerprint) return;
  currentRunFingerprint = fingerprint;
  const running = run.status === "running" || run.active_count > 0;
  document.getElementById("current-run").classList.toggle("running", running);
  document.getElementById("current-run-title").textContent = run.status === "running"
    ? (run.resumed ? "기존 세션 이어서 분석 중" : "새 분석 실행 중")
    : running ? "후속 작업 실행 중" : "저장된 분석 결과";
  document.getElementById("current-run-meta").textContent = run.started_at
    ? `${new Date(run.started_at).toLocaleTimeString("ko-KR")} 시작 · ${run.attempt}번째 실행`
    : running ? "Investigator가 끝난 뒤 후속 작업을 진행하고 있습니다."
      : "지금 실행 중인 분석이 없습니다. 아래 그래프는 저장된 작업을 표시합니다.";
  document.getElementById("current-run-count").textContent =
    `${run.active_count || 0}개 작업 실행 중`;
  const list = document.getElementById("current-run-jobs");
  list.replaceChildren();
  for (const job of run.active_jobs || []) {
    const item = document.createElement("div");
    item.className = "current-run-job";
    const name = document.createElement("strong");
    name.textContent = job.name;
    item.appendChild(name);
    const file = document.createElement("span");
    file.textContent = job.file || "위치 미기록";
    item.appendChild(file);
    list.appendChild(item);
  }
  if (!list.childElementCount) {
    const empty = document.createElement("p");
    empty.className = "current-run-empty";
    empty.textContent = running ? "다음 작업을 준비 중입니다." : "";
    list.appendChild(empty);
  }
}

function renderConfirmed(data) {
  const findings = data.confirmed_vulnerabilities || [];
  const total = data.confirmed_count || 0;
  const fingerprint = JSON.stringify([total, findings]);
  if (fingerprint === confirmedFingerprint) return;
  confirmedFingerprint = fingerprint;
  document.getElementById("confirmed-count").textContent = String(total);
  const list = document.getElementById("confirmed-list");
  list.replaceChildren();
  if (!findings.length) {
    const empty = document.createElement("p");
    empty.className = "confirmed-empty";
    empty.textContent = "확인된 항목이 없습니다.";
    list.appendChild(empty);
    return;
  }
  for (const finding of findings) {
    const item = document.createElement("article");
    item.className = "confirmed-item";
    const main = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = finding.title;
    main.appendChild(title);
    const meta = document.createElement("div");
    meta.className = "confirmed-meta";
    for (const value of [finding.category,
      `${finding.file || "위치 미기록"}${finding.line ? `:${finding.line}` : ""}`,
      finding.cvss_score == null ? "위험도 미평가" : `CVSS ${finding.cvss_score.toFixed(1)}`]) {
      const part = document.createElement("span");
      part.textContent = value;
      meta.appendChild(part);
    }
    main.appendChild(meta);
    item.appendChild(main);
    const badge = document.createElement("span");
    badge.className = `confirmed-badge ${finding.verification === "dynamic" ? "dynamic" : "static"}`;
    badge.textContent = finding.verification === "dynamic" ? "실행 재현 확인" : "정적 근거 확인";
    item.appendChild(badge);
    list.appendChild(item);
  }
  if (total > findings.length) {
    const more = document.createElement("p");
    more.className = "confirmed-more";
    more.textContent = `목록에 표시하지 않은 항목 ${total - findings.length}건`;
    list.appendChild(more);
  }
}

function render(data) {
  latest = data;
  document.getElementById("firmware-id").textContent = data.firmware_id;
  document.getElementById("investigator-status").textContent =
    statusNames[data.investigator_status] || data.investigator_status;
  document.getElementById("file-count").textContent = String(data.total_files);
  document.getElementById("running-count").textContent = String(
    data.specialists.reduce((sum, item) => sum + (item.counts.running || 0), 0));
  document.getElementById("detective-count").textContent = String(data.detectives.length);
  document.getElementById("updated-at").textContent = new Date(data.observed_at).toLocaleTimeString("ko-KR");
  document.getElementById("connection-label").textContent = "실시간 연결";
  document.getElementById("connection").classList.remove("offline");
  renderCurrentRun(data);
  renderConfirmed(data);

  const visible = data.detectives.slice(0, 12);
  const height = Math.max(865, 125 + 68 * Math.max(data.specialists.length, visible.length) + 30);
  graph.setAttribute("viewBox", `0 0 1300 ${height}`);
  graph.replaceChildren();
  label(35, 111, "INVESTIGATOR · 10개 전담 분야", "section-label");
  label(445, 111, "DETECTIVE · 동적 검증", "section-label");
  label(825, 111, "LAB", "section-label");
  label(1060, 111, "ASSISTANT", "section-label");

  // Draw connections first so cards remain readable.
  edge(360, 51, 400, 51, "guide");
  svg("path", {d: `M 400 51 L 400 ${130 + 68 * 9}`, class: "edge guide"});
  data.specialists.forEach((item, index) => edge(360, 147 + index * 68,
                                                  400, 147 + index * 68, "guide"));
  visible.forEach((item, index) => {
    const sourceIndex = data.specialists.findIndex(source => source.id === item.source_specialist);
    if (sourceIndex >= 0) edge(360, 147 + sourceIndex * 68, 445, 147 + index * 68,
                               item.status === "running" ? "active" : "");
  });
  if (data.detectives.length) edge(715, 153, 825, 337, "guide");
  if (data.lab.length) edge(995, 337, 1060, 337, "guide");
  else if (data.detectives.length) edge(715, 175, 1060, 337, "guide");

  node(35, 19, 325, "추출 및 파일 목록", data.scope_ready ? `${data.total_files}개 항목 목록화` : "스캔 범위 대기",
       data.scope_ready ? "complete" : data.investigator_status,
       [data.extraction_ready ? "추출 완료" : "추출 대기", `목록 항목 ${data.total_files}개`]);
  data.specialists.forEach((item, index) => {
    const counts = item.counts;
    const meta = item.task_count
      ? `${counts.running || 0} 실행 · ${counts.pending || 0} 대기 · ${counts.complete || 0} 완료 · ${counts.partial || 0} 부분 · ${counts.failed || 0} 실패`
      : statusNames[item.status];
    node(35, 120 + index * 68, 325, item.name, meta, item.status,
         item.task_count
           ? [...item.tasks.map(task => `${task.file || "파일 미기록"}: ${statusNames[task.status] || task.status}`),
              ...(item.hidden_task_count ? [`추가 ${item.hidden_task_count}개 작업`] : [])]
           : ["분야별 작업이 생성되지 않았습니다."], String(item.task_count || ""));
  });
  if (!visible.length) {
    node(445, 120, 270, "Detective 대기", "동적 검증 후보를 기다리는 중", "waiting", []);
  } else {
    visible.forEach((item, index) => node(
      445, 120 + index * 68, 270, `Detective ${item.id.slice(0, 8)}`,
      `${item.file || "위치 미기록"}${item.line ? `:${item.line}` : ""} · ${statusNames[item.status] || item.status}`,
      item.status, [`담당 분야 ${item.source_specialist}`, `시도 ${item.attempts}회`]));
  }
  if (data.detectives.length > visible.length) {
    node(445, 120 + visible.length * 68, 270, `추가 ${data.detectives.length - visible.length}건`,
         "최근 12건을 그림에 표시", "waiting", ["총 Detective 작업 " + data.detectives.length + "건"]);
  }
  const lab = stageStatus(data.lab);
  const assistant = stageStatus(data.assistant);
  node(825, 310, 170, "Lab", `${data.lab.length}개 환경 작업`, lab,
       data.lab.map(item => `${item.id}: ${statusNames[item.status] || item.status}`));
  node(1060, 310, 185, "Assistant", `${data.assistant.length}개 후속 작업`, assistant,
       data.assistant.map(item => `${item.id}: ${statusNames[item.status] || item.status}`));
}

async function refresh() {
  if (loading) return;
  loading = true;
  try {
    const response = await fetch("/api/status", {cache: "no-store"});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (_error) {
    document.getElementById("connection-label").textContent = "연결 끊김";
    document.getElementById("connection").classList.add("offline");
  } finally {
    loading = false;
  }
}

refresh();
setInterval(refresh, 1000);
