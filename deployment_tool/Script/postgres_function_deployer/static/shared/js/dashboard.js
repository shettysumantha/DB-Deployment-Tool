async function loadDashboardMetrics() {
  const response = await fetch("/api/dashboard/metrics", { credentials: "same-origin" });
  if (!response.ok) throw new Error("Dashboard metrics could not be loaded.");
  const data = await response.json();
  document.getElementById("webHealth").textContent = data.health.web;
  document.getElementById("databaseHealth").textContent = data.health.application_database;
  document.getElementById("requestCount").textContent = data.performance.requests;
  document.getElementById("requestErrors").textContent = data.performance.errors;
  document.getElementById("requestLatency").textContent =
    `${data.performance.average_ms} / ${data.performance.p95_ms}`;
  const slowEndpoints = document.getElementById("slowEndpoints");
  slowEndpoints.replaceChildren();
  if (data.performance.slowest_endpoints.length) {
    data.performance.slowest_endpoints.forEach((item) => {
      const row = document.createElement("li");
      const endpoint = document.createElement("code");
      const timing = document.createElement("span");
      endpoint.textContent = item.endpoint;
      timing.textContent = `${item.average_ms} ms avg · ${item.p95_ms} ms p95 · ${item.requests} requests`;
      row.append(endpoint, timing);
      slowEndpoints.append(row);
    });
  } else {
    const empty = document.createElement("li");
    empty.textContent = "No recent request samples.";
    slowEndpoints.append(empty);
  }
  document.getElementById("performanceAdvice").textContent =
    data.performance.recommendations.join(" ");
  const seconds = data.uptime_seconds;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  document.getElementById("processUptime").textContent = `${hours}h ${minutes}m`;
}

function showMetricsUnavailable() {
  document.getElementById("webHealth").textContent = "Unavailable";
  document.getElementById("databaseHealth").textContent = "Unavailable";
  document.getElementById("requestCount").textContent = "—";
  document.getElementById("requestErrors").textContent = "—";
  document.getElementById("requestLatency").textContent = "—";
}

loadDashboardMetrics().catch(showMetricsUnavailable);
window.setInterval(() => loadDashboardMetrics().catch(showMetricsUnavailable), 30000);
