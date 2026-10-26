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
      ? `${counts.running || 0} 실행 · ${counts.pending || 0} 대기 · ${counts.complete || 0} 완료 · ${counts.failed || 0} 실패`
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
