"use strict";

let csrfToken = "";
let latestResults = [];

const $ = (id) => document.getElementById(id);

function showMessage(id, message, type = "") {
  const el = $(id);
  el.textContent = message || "";
  el.className = `message ${type}`.trim();
}
function setBusy(button, busy, busyText) {
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.disabled = true;
    button.textContent = busyText;
  } else {
    button.disabled = false;
    button.textContent = button.dataset.originalText || button.textContent;
  }
}
async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (csrfToken && options.method && options.method.toUpperCase() !== "GET") {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(url, { credentials: "same-origin", ...options, headers });
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}
function setAuthenticated(authenticated) {
  $("login-panel").classList.toggle("hidden", authenticated);
  $("dashboard-content").classList.toggle("hidden", !authenticated);
  $("logout-button").classList.toggle("hidden", !authenticated);
}
async function refreshSession() {
  try {
    const data = await api("/api/session");
    csrfToken = data.csrf_token || "";
    $("model-status").textContent = data.model_loaded ? "Ready" : "Error";
    $("model-status").style.color = data.model_loaded ? "var(--green)" : "var(--red)";
    if (data.model_loaded) {
      $("feature-count").textContent = `${data.features.length} model features`;
      $("feature-list").textContent = data.features.join(" · ");
    } else {
      $("feature-list").textContent = data.model_error || "Model not loaded. Check model/ folder and restart the app.";
    }
    setAuthenticated(data.authenticated);
    if (!data.authenticated && data.model_error) {
      showMessage("login-message", `Model loading issue: ${data.model_error}`, "error");
    }
  } catch (error) {
    setAuthenticated(false);
    showMessage("login-message", error.message, "error");
  }
}
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter || $("login-form").querySelector("button");
  setBusy(button, true, "Signing in…");
  showMessage("login-message", "");
  try {
    const data = await api("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("username").value, password: $("password").value })
    });
    csrfToken = data.csrf_token || "";
    $("password").value = "";
    showMessage("login-message", "Signed in successfully.", "success");
    setAuthenticated(true);
    await refreshSession();
  } catch (error) {
    showMessage("login-message", error.message, "error");
  } finally {
    setBusy(button, false);
  }
});
$("logout-button").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); }
  catch (error) { showMessage("analysis-message", error.message, "error"); }
  await refreshSession();
});
$("traffic-file").addEventListener("change", () => {
  const file = $("traffic-file").files[0];
  $("selected-file").textContent = file ? `${file.name} · ${(file.size / 1024 / 1024).toFixed(2)} MB` : "No file selected";
  showMessage("analysis-message", "");
});
function updateSummary(data) {
  $("stat-total").textContent = Number(data.total).toLocaleString();
  $("stat-benign").textContent = Number(data.benign).toLocaleString();
  $("stat-ddos").textContent = Number(data.ddos).toLocaleString();
  $("stat-rate").textContent = `${Number(data.detection_rate).toFixed(2)}%`;
  $("donut-total").textContent = Number(data.total).toLocaleString();
  $("legend-benign").textContent = Number(data.benign).toLocaleString();
  $("legend-ddos").textContent = Number(data.ddos).toLocaleString();
  const benignDegrees = data.total ? (data.benign / data.total) * 360 : 0;
  $("donut").style.background = `conic-gradient(var(--green) 0deg ${benignDegrees}deg, var(--red) ${benignDegrees}deg 360deg)`;
}
function renderResults(results) {
  const tbody = $("results-body");
  tbody.replaceChildren();
  latestResults = Array.isArray(results) ? results : [];
  if (!latestResults.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6; cell.className = "empty-state"; cell.textContent = "No results to display.";
    row.appendChild(cell); tbody.appendChild(row);
  } else {
    for (const item of latestResults) {
      const row = document.createElement("tr");
      const values = [
        String(item.record ?? ""),
        String(item.source_ip ?? "—"),
        String(item.destination_ip ?? "—")
      ];
      for (const value of values) {
        const cell = document.createElement("td"); cell.textContent = value; row.appendChild(cell);
      }
      const prediction = document.createElement("td");
      const pill = document.createElement("span");
      const isAttack = String(item.prediction).toLowerCase().includes("ddos") || String(item.prediction).toLowerCase().includes("attack");
      pill.className = `pill ${isAttack ? "pill-ddos" : "pill-benign"}`;
      pill.textContent = String(item.prediction ?? "Unknown");
      prediction.appendChild(pill); row.appendChild(prediction);
      const confidence = document.createElement("td");
      confidence.textContent = item.confidence == null ? "Not available" : `${Number(item.confidence).toFixed(2)}%`;
      row.appendChild(confidence);
      const severity = document.createElement("td");
      severity.className = isAttack ? "severity-high" : "severity-info";
      severity.textContent = String(item.severity ?? (isAttack ? "HIGH" : "INFO"));
      row.appendChild(severity);
      tbody.appendChild(row);
    }
  }
  $("download-results").disabled = !latestResults.length;
}
$("analyze-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("traffic-file").files[0];
  if (!file) { showMessage("analysis-message", "Choose a CSV file first.", "error"); return; }
  if (!file.name.toLowerCase().endsWith(".csv")) { showMessage("analysis-message", "Only .csv files are allowed.", "error"); return; }
  if (file.size > 25 * 1024 * 1024) { showMessage("analysis-message", "File exceeds the 25 MB limit.", "error"); return; }
  const button = $("analyze-button");
  setBusy(button, true, "Analyzing…");
  showMessage("analysis-message", "Validating CSV and running the saved model…");
  try {
    const form = new FormData(); form.append("file", file);
    const data = await api("/api/analyze", { method: "POST", body: form });
    updateSummary(data); renderResults(data.results);
    showMessage("analysis-message", `Analysis complete: ${data.total.toLocaleString()} records processed.`, "success");
  } catch (error) {
    showMessage("analysis-message", error.message, "error");
  } finally { setBusy(button, false); }
});
$("download-results").addEventListener("click", () => {
  if (!latestResults.length) return;
  const columns = ["record", "source_ip", "destination_ip", "prediction", "confidence", "severity"];
  const quote = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const csv = [columns.join(","), ...latestResults.map(row => columns.map(col => quote(row[col])).join(","))].join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a"); link.href = url; link.download = "ddos_detection_results.csv";
  document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
});
$("evaluation-file").addEventListener("change", () => showMessage("evaluation-message", ""));
$("evaluate-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("evaluation-file").files[0];
  if (!file) { showMessage("evaluation-message", "Choose a labelled CSV first.", "error"); return; }
  if (!file.name.toLowerCase().endsWith(".csv")) { showMessage("evaluation-message", "Only .csv files are allowed.", "error"); return; }
  if (file.size > 25 * 1024 * 1024) { showMessage("evaluation-message", "File exceeds the 25 MB limit.", "error"); return; }
  const button = $("evaluate-button"); setBusy(button, true, "Evaluating…");
  showMessage("evaluation-message", "Comparing model predictions with the provided labels…");
  try {
    const form = new FormData(); form.append("file", file);
    const data = await api("/api/evaluate", { method: "POST", body: form });
    $("metric-accuracy").textContent = `${data.accuracy}%`;
    $("metric-precision").textContent = `${data.precision}%`;
    $("metric-recall").textContent = `${data.recall}%`;
    $("metric-f1").textContent = `${data.f1_score}%`;
    $("cm-00").textContent = data.confusion_matrix[0][0];
    $("cm-01").textContent = data.confusion_matrix[0][1];
    $("cm-10").textContent = data.confusion_matrix[1][0];
    $("cm-11").textContent = data.confusion_matrix[1][1];
    $("evaluation-results").classList.remove("hidden");
    showMessage("evaluation-message", `Evaluation complete on ${data.records.toLocaleString()} labelled rows. Metrics reflect this test file only.`, "success");
  } catch (error) {
    showMessage("evaluation-message", error.message, "error");
  } finally { setBusy(button, false); }
});
refreshSession();
