"use strict";
let accessKey = "";
let activeTask = null;
let activeRun = null;
const byId = id => document.getElementById(id);
function element(tag, text, className) { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (className) el.className = className; return el; }
function notice(text) { byId("notice").textContent = text; byId("notice").hidden = !text; }
async function api(path, method = "GET", body) {
  const headers = {Authorization: "Bearer " + accessKey};
  const options = {method, headers};
  if (body !== undefined) { headers["Content-Type"] = "application/json"; options.body = JSON.stringify(body); }
  const response = await fetch(path, options);
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || "Request failed");
  return value;
}
function renderTask(task) {
  activeTask = task;
  byId("task-id").replaceChildren(document.createTextNode(task.task_id + " "), element("span", "/ v" + task.contract_version));
  byId("objective").textContent = task.objective;
  byId("expiry").textContent = new Date(task.expires_at).toLocaleString([], {dateStyle: "short", timeStyle: "short"});
  byId("operations").replaceChildren(...task.allowed_operations.map(op => element("li", op)));
  byId("contract-json").textContent = JSON.stringify(task, null, 2);
}
function renderResult(result) {
  activeRun = result.run.capsule_id;
  byId("business-metric").textContent = result.run.outcome.charAt(0).toUpperCase() + result.run.outcome.slice(1);
  byId("blocked-metric").textContent = result.assessment.findings.filter(f => f.classification === "Blocked").length.toString().padStart(2, "0");
  byId("assessment-empty").hidden = true;
  byId("assessment-content").hidden = false;
  byId("classification-pills").replaceChildren(...result.assessment.classifications.map(label => element("span", label, "pill " + label)));
  byId("findings").replaceChildren(...result.assessment.findings.map(f => {
    const row = element("div", undefined, "finding");
    const content = element("div");
    content.append(element("p", f.reason));
    if (f.evidence_reference) content.append(element("small", f.source + " · " + f.evidence_reference));
    row.append(element("span", f.classification, "pill " + f.classification), content);
    return row;
  }));
  byId("events").replaceChildren(...result.events.map(e => {
    const row = element("tr");
    const when = element("td", new Date(e.observed_at).toLocaleTimeString()); when.title = e.observed_at;
    const source = element("td", e.source);
    const operation = element("td", e.operation);
    const effect = element("td", e.policy_verdict + " / " + e.effect_status, e.effect_status);
    const ref = element("td"); const shortened = element("small", e.event_id.slice(0, 12) + "…"); shortened.title = e.evidence_reference; ref.append(shortened);
    row.append(when, source, operation, effect, ref); return row;
  }));
  byId("report-panel").hidden = !result.report;
  if (result.report) byId("report").replaceChildren(...result.report.departments.map(item => {
    const card = element("article"); card.append(element("span", item.department), element("strong", "₹ " + item.total.toLocaleString("en-IN"))); return card;
  }));
}
async function refresh(preferredRun) {
  const snapshot = await api("/api/v1/snapshot");
  byId("integrity-metric").textContent = "Verified";
  byId("integrity-detail").textContent = snapshot.integrity.verified_events + " events · local HMAC chain";
  if (snapshot.tasks.length) renderTask(snapshot.tasks.find(task => task.task_id === "FIN-001") || snapshot.tasks[0]);
  const runs = snapshot.runs.filter(run => activeTask && run.task_id === activeTask.task_id);
  byId("run-select").replaceChildren(...runs.map(run => { const option = element("option", new Date(run.created_at).toLocaleString() + " · " + run.capsule_id.slice(0, 19)); option.value = run.capsule_id; return option; }));
  const selected = preferredRun || (runs.find(run => run.capsule_id === activeRun) || runs[0])?.capsule_id;
  if (selected) { byId("run-select").value = selected; renderResult(await api("/api/v1/runs/" + encodeURIComponent(selected))); }
}
byId("login-form").addEventListener("submit", async event => {
  event.preventDefault(); accessKey = byId("access-key").value.trim();
  const button = event.currentTarget.querySelector("button"); button.disabled = true; notice("");
  try { await refresh(); byId("access-key").value = ""; byId("login").hidden = true; byId("connected").hidden = false; byId("refresh").hidden = false; }
  catch (error) { accessKey = ""; notice(error.message); } finally { button.disabled = false; }
});
byId("run-harness").addEventListener("click", async () => {
  const button = byId("run-harness"); button.disabled = true; button.textContent = "Running broker policy checks…"; notice("");
  try { const result = await api("/api/v1/tasks/" + encodeURIComponent(activeTask.task_id) + "/harness", "POST", {}); await refresh(result.run.capsule_id); }
  catch (error) { notice(error.message); } finally { button.disabled = false; button.replaceChildren(document.createTextNode("Run policy harness "), element("span", "→")); }
});
byId("refresh").addEventListener("click", () => refresh().catch(error => notice(error.message)));
byId("run-select").addEventListener("change", async event => { try { renderResult(await api("/api/v1/runs/" + encodeURIComponent(event.target.value))); } catch (error) { notice(error.message); } });
