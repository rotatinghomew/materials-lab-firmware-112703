/* 固件上线双边放行工作台前端（无框架，直接调 /api）。 */
const $ = (sel) => document.querySelector(sel);

const ACTION_DEFS = {
  facility_approve: { label: "设施批准（组或单节点，绑定包号）", fields: [
    { name: "image", kind: "image", required: true },
    { name: "group", kind: "group", required: false },
    { name: "node", kind: "node", required: false }] },
  suspend: { label: "暂停单节点（值班审批人）", fields: [
    { name: "node", kind: "node", required: true }, { name: "image", kind: "image", required: true }] },
  resume: { label: "恢复单节点", fields: [
    { name: "node", kind: "node", required: true }, { name: "image", kind: "image", required: true }] },
  install_plan: { label: "建立安装计划（当班安装人）", fields: [
    { name: "node", kind: "node", required: true }, { name: "image", kind: "image", required: true }] },
  install_plan_revoke: { label: "撤销最近一次安装计划（管理员）", fields: [
    { name: "node", kind: "node", required: true }, { name: "image", kind: "image", required: true }] },
  receipt: { label: "现场节点回执（办理账号填节点号）", fields: [
    { name: "image", kind: "image", required: true },
    { name: "result", kind: "result", required: true },
    { name: "actor", kind: "installer", required: false, hint: "接收时的实际安装人，如 F-31" }] },
  writeoff: { label: "核销（完成或安全退回之后）", fields: [
    { name: "node", kind: "node", required: true }, { name: "image", kind: "image", required: true }] },
  trust_freeze: { label: "信任冻结（registry）", fields: [
    { name: "authority", kind: "text", value: "vendor", required: true }] },
  trust_thaw: { label: "信任恢复（registry）", fields: [
    { name: "authority", kind: "text", value: "vendor", required: true }] },
  identity_disable: { label: "人员离组/停用（管理事件）", fields: [
    { name: "subject", kind: "text", required: true },
    { name: "authority", kind: "text", value: "facility", required: true }] },
  identity_enable: { label: "人员重新启用", fields: [
    { name: "subject", kind: "text", required: true },
    { name: "authority", kind: "text", value: "facility", required: true }] },
  note: { label: "合规备注", fields: [{ name: "text", kind: "text", required: true }] },
};

let state = null;
let latestMode = true;

async function fetchState(at) {
  const qs = at == null ? "" : `?at=${encodeURIComponent(at)}`;
  const resp = await fetch("/api/state" + qs);
  state = await resp.json();
  render();
}

function badgeClass(status) {
  if (/可|进行中/.test(status)) return "b-ok";
  if (/等待/.test(status)) return "b-wait";
  if (/暂停|挂起/.test(status)) return "b-hold";
  if (/不可|失效|拒绝/.test(status)) return "b-bad";
  return "b-done";
}

function uniq(items) { return [...new Set(items)]; }

function render() {
  const nodes = uniq(state.cases.map(c => c.node_id));
  const images = uniq(state.cases.map(c => c.image));
  const groups = Object.fromEntries(state.cases.map(c => [c.node_id, c.facts.group]));

  // 工艺视图
  const tbody = $("#case-table tbody");
  tbody.innerHTML = "";
  for (const c of state.cases) {
    const failed = c.bases.filter(b => b.status === "失效").map(b => b.title).join("、") || "—";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${c.node_id}</td><td>${c.facts.group}</td><td>${c.image}</td>
      <td>${c.facts.version}<br><span class="muted">${c.facts.basename}</span></td>
      <td><code>${c.facts.digest.slice(0, 16)}</code></td>
      <td>${phaseText(c.phase)}</td>
      <td><span class="badge ${badgeClass(c.status)}">${c.status}</span></td>
      <td>${failed}</td>
      <td><button data-node="${c.node_id}" data-image="${c.image}" class="btn-detail">复查</button></td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll(".btn-detail").forEach(btn => btn.addEventListener("click", () => {
    $("#pick-node").value = btn.dataset.node;
    $("#pick-image").value = btn.dataset.image;
    showCase(btn.dataset.node, btn.dataset.image);
  }));

  // 下拉
  fillSelect("#pick-node", nodes, x => [x, `${x}（组 ${groups[x]}）`]);
  fillSelect("#pick-image", images, x => [x, x]);

  // 事件流
  const eb = $("#event-table tbody");
  eb.innerHTML = "";
  for (const e of state.events) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${e.seq}</td><td>t=${e.at}</td>
      <td class="src-${e.origin}">${e.origin === "source" ? "来源只读" : "工作台"}</td>
      <td>${e.kind}</td><td>${e.actor}</td>
      <td><code>${escapeHtml(JSON.stringify(e.facts))}</code></td>`;
    eb.appendChild(tr);
  }
  $("#clock").max = Math.max(200, state.clock_max);
  if (latestMode) {
    $("#clock").value = $("#clock").max;
    $("#clock-value").textContent = "最新";
  }
}

function phaseText(phase) {
  return { none: "未开始", accepted: "已接收", started: "已开始",
    finished: "已完成", rolled_back: "已退回", written_off: "已核销" }[phase] || phase;
}

function fillSelect(sel, values, labeler) {
  const el = $(sel);
  const prev = el.value;
  el.innerHTML = values.map(v => {
    const [val, label] = labeler(v);
    return `<option value="${val}">${escapeHtml(label)}</option>`;
  }).join("");
  if (values.includes(prev)) el.value = prev;
}

function showCase(nodeId, image) {
  const c = state.cases.find(x => x.node_id === nodeId && x.image === image);
  if (!c) return;
  const failed = c.bases.filter(b => b.status === "失效");
  const html = [`<p><span class="badge ${badgeClass(c.status)}">${c.status}</span>
      阶段：<strong>${phaseText(c.phase)}</strong>
      可办动作：${c.allowed_actions.length ? c.allowed_actions.map(a => `<code>${a}</code>`).join(" ") : "无"}</p>`];
  html.push(`<h3>放行依据（${c.bases.length} 项，失效 ${failed.length} 项）</h3>`);
  for (const b of c.bases) {
    html.push(`<details class="basis ${b.status === "失效" ? "fail" : b.status === "不适用" ? "na" : "pass"}"
        ${b.status === "失效" ? "open" : ""}>
      <summary><span class="badge b-${b.status === "失效" ? "bad" : b.status === "不适用" ? "done" : "ok"}">${b.status}</span>
        <span class="side">${sideText(b.side)}</span><strong>${b.title}</strong>
        <code>${b.code}</code></summary>
      <div class="body">
        <div>${escapeHtml(b.detail)}</div>
        <div class="kv">证据：${escapeHtml(b.evidence)}</div>
        ${b.remedy ? `<div class="remedy">处置：${escapeHtml(b.remedy)}</div>` : ""}
      </div></details>`);
  }
  if (c.remediation.length) {
    html.push("<h3>当前应采取的处理</h3><ul class='clean'>" +
      c.remediation.map(r => `<li>${escapeHtml(r)}</li>`).join("") + "</ul>");
  }
  if (c.history.length) {
    html.push("<h3>链上事件（含已发生的失效/越权）</h3><ul class='clean'>" +
      c.history.map(h => `<li>t=${h.at} <code>${h.event}</code>：${escapeHtml(h.detail)}</li>`).join("") + "</ul>");
  }
  if (c.receipts.length) {
    html.push("<h3>节点回执</h3><ul class='clean'>" +
      c.receipts.map(r => `<li>t=${r.at} ${r.result}，安装人 ${r.installer || "—"}（${r.origin}）</li>`).join("") + "</ul>");
  }
  $("#case-detail").innerHTML = html.join("");
}

function sideText(side) {
  return { vendor: "厂商侧", facility: "设施侧", node: "节点侧" }[side] || side;
}

function buildFactFields() {
  const def = ACTION_DEFS[$("#f-kind").value];
  const images = uniq(state.cases.map(c => c.image));
  const nodes = uniq(state.cases.map(c => c.node_id));
  $("#f-facts").innerHTML = def.fields.map(f => {
    let input;
    if (f.kind === "image") input = selectHtml(f.name, images, f.required);
    else if (f.kind === "node") input = selectHtml(f.name, nodes, f.required);
    else if (f.kind === "group") input = selectHtml(f.name, uniq(state.cases.map(c => c.facts.group)), f.required);
    else if (f.kind === "result") input = selectHtml(f.name, ["accept", "start", "finish", "rollback"], true);
    else input = `<input name="${f.name}" ${f.value ? `value="${f.value}"` : ""} ${f.required ? "required" : ""}>`;
    return `<label>${f.hint || f.name}${input}</label>`;
  }).join("");
}

function selectHtml(name, values, required) {
  return `<select name="${name}" ${required ? "required" : ""}>
    ${required ? "" : '<option value="">（不指定）</option>'}
    ${values.map(v => `<option value="${v}">${v}</option>`).join("")}</select>`;
}

async function submitApply(ev) {
  ev.preventDefault();
  const form = new FormData(ev.target);
  const kind = form.get("kind");
  const actor = String(form.get("actor") || "").trim();
  const atRaw = String(form.get("at") || "").trim();
  const facts = {};
  for (const f of ACTION_DEFS[kind].fields) {
    const v = String(form.get(f.name) || "").trim();
    if (v) facts[f.name] = v;
  }
  const payload = { kind, actor, facts };
  if (atRaw) payload.at = Number(atRaw);
  const out = $("#apply-result");
  const resp = await fetch("/api/apply", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  out.className = "result " + (resp.ok ? "ok" : "error");
  if (resp.ok) {
    out.textContent = "已写入工作台日志：\n" + JSON.stringify(data.stored, null, 2);
    latestMode = true;
    await fetchState(null);
  } else {
    out.textContent = "办理被拒绝：" + data.error;
  }
}

function currentAt() {
  return latestMode ? null : Number($("#clock").value);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, ch =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

// 初始化
$("#f-kind").innerHTML = Object.entries(ACTIONS_DEFS)
  .map(([k, v]) => `<option value="${k}">${v.label}</option>`).join("");
$("#f-kind").addEventListener("change", buildFactFields);
$("#apply-form").addEventListener("submit", submitApply);
$("#btn-pick").addEventListener("click", () =>
  showCase($("#pick-node").value, $("#pick-image").value));
$("#clock").addEventListener("input", () => {
  latestMode = Number($("#clock").value) >= Number($("#clock").max);
  $("#clock-value").textContent = latestMode ? "最新" : "t=" + $("#clock").value;
  fetchState(currentAt());
});
$("#btn-latest").addEventListener("click", () => {
  latestMode = true;
  $("#clock").value = $("#clock").max;
  $("#clock-value").textContent = "最新";
  fetchState(null);
});

fetchState(null).then(buildFactFields);
