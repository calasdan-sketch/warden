// warden fleet command — vanilla JS, no build step.
const $ = (id) => document.getElementById(id);
const tokenInput = $("token");
tokenInput.value = sessionStorage.getItem("warden_token") || "";
tokenInput.addEventListener("change", () => {
  sessionStorage.setItem("warden_token", tokenInput.value.trim());
  connectLive();
});

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  const tok = sessionStorage.getItem("warden_token");
  if (tok) headers["Authorization"] = "Bearer " + tok;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

const money = (n) => "$" + Number(n || 0).toFixed(2);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));
const elapsed = (iso) => {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return (h ? h + "h " : "") + m + "m " + (s % 60) + "s";
};

let currentRuns = [];

function renderLive(d) {
  // burn bar
  $("burn-net").textContent = money(d.net_usd);
  $("burn-detail").textContent = `${money(d.gross_usd)} gross · ${money(d.saved_usd)} saved`;
  $("live-count").textContent = (d.live_runs || []).length;
  // budget coloring comes from /api/v1/burn (has budget_usd); SSE keeps it simple
  currentRuns = d.live_runs || [];
  const tb = document.querySelector("#runs tbody");
  tb.innerHTML = "";
  $("runs-empty").style.display = currentRuns.length ? "none" : "";
  for (const r of currentRuns) {
    const tr = document.createElement("tr");
    const last = (r._last_span) || "";
    tr.innerHTML = `<td class="mono">${esc(r.agent_id)}</td><td>${esc(r.fleet_id)}</td>` +
      `<td class="mono">${elapsed(r.started_at)}</td><td class="cost">${r.tool_calls}</td>` +
      `<td class="cost">${money(r.cost_usd)}</td><td class="mono">${esc(last)}</td>` +
      `<td><button class="small danger" data-kill="${esc(r.run_id)}">kill</button></td>`;
    tr.addEventListener("click", (e) => {
      if (e.target.dataset.kill) { killRun(e.target.dataset.kill); return; }
      openDrawer(r.run_id);
    });
    tb.appendChild(tr);
  }
  // alerts
  const alerts = d.alerts || [];
  $("alerts-empty").style.display = alerts.length ? "none" : "";
  const ul = $("alerts");
  ul.innerHTML = "";
  for (const a of alerts) {
    const li = document.createElement("li");
    li.className = "alert " + a.severity;
    li.innerHTML = `<span class="rule">${esc(a.rule)}</span> — ${esc(a.message)}` +
      `<div class="obs">threshold: ${esc(a.threshold)} · observed: ${esc(a.observed)}</div>`;
    li.addEventListener("click", () => a.run_id && openDrawer(a.run_id));
    ul.appendChild(li);
  }
  // approvals
  const apprs = d.approvals || [];
  $("approvals-empty").style.display = apprs.length ? "none" : "";
  $("appr-count").textContent = apprs.length || "";
  const au = $("approvals");
  au.innerHTML = "";
  for (const p of apprs) {
    const li = document.createElement("li");
    li.className = "approval";
    li.innerHTML = `<span class="mono">${esc(p.gate)}</span><span class="obs">run ${esc(p.run_id.slice(0, 8))}…</span>` +
      `<span style="margin-left:auto"></span>` +
      `<button class="small" data-appr="${p.id}" data-dec="approved">approve</button>` +
      `<button class="small danger" data-appr="${p.id}" data-dec="denied">deny</button>`;
    au.appendChild(li);
  }
  au.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => decideApproval(b)));
}

async function killRun(runID) {
  const reason = prompt("Kill reason (required — empty cancels):", "");
  if (reason === null || !reason.trim()) return;
  try {
    await api("/api/v1/kill", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope: "run", target: runID, reason: reason.trim() }),
    });
  } catch (e) { alert("kill failed: " + e.message); }
}

async function decideApproval(btn) {
  const reason = prompt(`Reason for ${btn.dataset.dec} (optional):`, "") || "";
  try {
    await api("/api/v1/approvals/" + btn.dataset.appr, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision: btn.dataset.dec, reason }),
    });
  } catch (e) { alert("approval failed: " + e.message); }
}

async function openDrawer(runID) {
  $("drawer").classList.remove("hidden");
  $("drawer-title").textContent = runID;
  $("drawer-body").innerHTML = "loading…";
  $("drawer-kill").onclick = () => killRun(runID);
  let d;
  try { d = await api("/api/v1/runs/" + runID); }
  catch (e) { $("drawer-body").innerHTML = "failed: " + esc(e.message); return; }
  const r = d.run;
  $("drawer-sub").textContent = `${r.agent_id} · ${r.fleet_id} · ${r.status}`;
  const stats = [
    ["status", r.status], ["cost gross", money(r.cost_usd)], ["saved", money(r.cost_saved_usd)],
    ["net", money(r.cost_usd - r.cost_saved_usd)], ["tool calls", r.tool_calls],
    ["files", r.files_touched], ["egress hosts", r.net_egress_hosts],
    ["spawns", r.subagents_spawned], ["tokens in/out", `${r.tokens_in}/${r.tokens_out}`],
    ["model", r.model || "—"],
  ];
  let html = `<div class="stat-grid">` + stats.map(([k, v]) =>
    `<div class="stat"><div class="k">${k}</div><div class="v mono">${esc(v)}</div></div>`).join("") + `</div>`;
  // waterfall
  const spans = d.spans || [];
  if (spans.length) {
    const t0 = new Date(r.started_at).getTime();
    const t1 = Math.max(...spans.map((s) => new Date(s.ended_at || s.started_at).getTime()), t0 + 1);
    html += `<h3>trace waterfall (${spans.length} spans)</h3><div class="waterfall">`;
    for (const s of spans.slice(0, 300)) {
      const a = Math.max(0, (new Date(s.started_at).getTime() - t0) / (t1 - t0) * 100);
      const b = Math.min(100, (new Date(s.ended_at || s.started_at).getTime() - t0) / (t1 - t0) * 100);
      const cls = s.status === "denied" ? "denied" : (s.status === "awaiting_approval" ? "await" : "");
      const label = s.tool || s.host || s.path || s.model || s.kind;
      const extra = s.policy_decision && s.policy_decision !== "allow" ? ` ⚠ ${esc(s.policy_decision)}` : "";
      const red = s.redacted ? " ·redacted" : "";
      html += `<div class="span-row"><span class="span-label mono" title="${esc(s.args_summary || "")}">${esc(label)}${extra}${red}</span>` +
        `<span class="span-track"><span class="span-bar ${cls}" style="left:${a}%;width:${Math.max(b - a, 0.6)}%"></span></span>` +
        `<span class="span-kind">${esc(s.kind)}</span></div>`;
    }
    html += `</div>`;
    if (spans.length > 300) html += `<div class="obs">showing first 300 of ${spans.length}</div>`;
  }
  const events = d.events || [];
  if (events.length) {
    html += `<h3>events</h3>` + events.map((e) =>
      `<div class="event"><span class="sev-${esc(e.severity)}">[${esc(e.severity)}]</span> ` +
      `<span class="mono">${esc(e.kind)}</span> — ${esc(e.message)}</div>`).join("");
  }
  if (d.receipt) {
    html += `<h3>sealed receipt</h3><pre class="receipt">${esc(JSON.stringify(d.receipt.receipt, null, 1))}</pre>`;
  }
  $("drawer-body").innerHTML = html;
}
$("drawer-close").addEventListener("click", () => $("drawer").classList.add("hidden"));

$("export-btn").addEventListener("click", () => {
  const tok = sessionStorage.getItem("warden_token");
  const url = "/api/v1/export" + (tok ? "" : "");
  // token goes via header; use fetch+blob so the header is sent
  const headers = tok ? { "Authorization": "Bearer " + tok } : {};
  fetch(url, { headers }).then((res) => res.blob()).then((blob) => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "warden-export.jsonl";
    a.click();
  });
});
$("scan-btn").addEventListener("click", async () => {
  try { await api("/api/v1/scan", { method: "POST" }); } catch (e) { alert("scan failed: " + e.message); }
});

let es = null;
function connectLive() {
  if (es) es.close();
  const tok = sessionStorage.getItem("warden_token");
  // EventSource can't set headers; pass token as query when required
  const url = "/api/v1/live" + (tok ? "?token=" + encodeURIComponent(tok) : "");
  es = new EventSource(url);
  es.onmessage = (ev) => renderLive(JSON.parse(ev.data));
  es.onerror = () => { /* reconnects automatically */ };
}
// budget-aware burn bar coloring
async function refreshBurn() {
  try {
    const b = await api("/api/v1/burn");
    if (b.budget_usd > 0) {
      const pct = Math.min(100, (b.gross_usd / b.budget_usd) * 100);
      const fill = $("burn-fill");
      fill.style.width = pct + "%";
      fill.style.background = pct >= 100 ? "var(--crit)" : pct >= 75 ? "var(--warn)" : "var(--ok)";
      $("burn-detail").textContent = `${money(b.gross_usd)} / ${money(b.budget_usd)} budget · ${money(b.saved_usd)} saved`;
    }
  } catch (e) { /* solo/no-auth differences are fine */ }
}
connectLive();
setInterval(refreshBurn, 10000);
refreshBurn();
