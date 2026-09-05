const state = {
  results: [],
  filter: "ALL",
  query: "",
  comparisonType: "functions",
  pendingKeys: [],
  tdConnected: false,
  liveConnected: false,
  generatedSql: "",
};
const $ = (id) => document.getElementById(id);
const json = async (url, options = {}) => {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) throw Error(data.error || "Request failed");
  return data;
};
function showNotice(message, error = false) {
  const el = $("notice");
  el.textContent = message;
  el.className = `notice ${error ? "error" : ""}`;
  el.classList.remove("d-none");
  setTimeout(() => el.classList.add("d-none"), 7000);
}
function formData(form) {
  return Object.fromEntries(new FormData(form).entries());
}
function updateActions() {
  const changed = state.results.filter(
    (x) => x.status === "MISSING" || x.status === "MODIFIED",
  );
  const selected = state.results.filter((x) => x.selected);
  const ready = state.tdConnected && state.liveConnected;
  $("compareDashboardBtn").disabled = !ready;
  $("generateBtn").disabled = !selected.length;
  $("generateBtnBottom").disabled = !selected.length;
  $("deployBtn").disabled = !selected.length;
  if (typeof updateTableActions === "function") updateTableActions();
}
function statusCount(status) {
  return state.results.filter((x) => x.status === status).length;
}
function renderSummary() {
  const label = state.comparisonType === "both" ? "Comparison summary" : `${state.comparisonType === "tables" ? "Tables" : "Functions"} (${state.results.length})`;
  const statuses = ["ALL", "NEW", "MODIFIED", "IDENTICAL", "MISSING"];
  const buttons = statuses.map((status) => {
    const count = status === "ALL" ? state.results.length : statusCount(status);
    return `<button type="button" class="summary-card${state.filter === status ? " active" : ""}" data-summary-status="${status}"><span>${status}</span><strong>${count}</strong></button>`;
  }).join("");
  $("comparisonSummary").innerHTML = `<div class="comparison-summary-group"><strong>${label}</strong><div class="summary-cards">${buttons}</div></div>`;
}
function renderResults() {
  const body = $("resultsBody");
  const visible = state.results.filter(
    (item) =>
      (state.filter === "ALL" || item.status === state.filter) &&
      `${item.name} ${item.signature || ""} ${item.key}`.toLowerCase().includes(state.query),
  );
  if (!visible.length) {
    body.innerHTML =
      '<tr><td colspan="6" class="empty-state">No objects match this view.</td></tr>';
    return;
  }
  body.innerHTML = visible
    .map((item) => {
      const deployable =
        item.status === "MISSING" || item.status === "MODIFIED";
      const objectName = item.objectType === "TABLE" ? item.key : item.name;
      const actionLabel = item.objectType === "TABLE" ? "View Changes" : "View Code";
      return `<tr><td>${deployable ? `<input class="row-check" type="checkbox" data-key="${encodeURIComponent(item.key)}" ${item.selected ? "checked" : ""}>` : ""}</td><td><button class="fn-name function-link" type="button" data-diff="${encodeURIComponent(item.key)}" data-object-type="${item.objectType}">${escapeHtml(objectName)}</button></td><td><span class="object-type object-type-${item.objectType.toLowerCase()}">${item.objectType}</span></td><td><span class="badge-status badge-${item.status.replace(" ", "-")}">${item.status}</span></td><td><div class="row-actions"><button data-diff="${encodeURIComponent(item.key)}" data-object-type="${item.objectType}">${actionLabel}</button>${deployable ? `<button data-deploy="${encodeURIComponent(item.key)}" data-object-type="${item.objectType}">Move to Live</button>` : ""}</div></td></tr>`;
    })
    .join("");
  body.querySelectorAll(".row-check").forEach((el) =>
    el.addEventListener("change", () => {
      const item = state.results.find(
        (x) => x.key === decodeURIComponent(el.dataset.key),
      );
      item.selected = el.checked;
      renderSummary();
      updateActions();
    }),
  );
  body
    .querySelectorAll("[data-diff]")
    .forEach((el) =>
      el.addEventListener("click", () =>
        el.dataset.objectType === "TABLE"
          ? openTableDiff(decodeURIComponent(el.dataset.diff))
          : openDiff(decodeURIComponent(el.dataset.diff)),
      ),
    );
  body
    .querySelectorAll("[data-deploy]")
    .forEach((el) =>
      el.addEventListener("click", () =>
        openConfirm([decodeURIComponent(el.dataset.deploy)]),
      ),
    );
}
function setConnection(role, connected) {
  state[`${role}Connected`] = connected;
  const el = $(role === "td" ? "tdStatus" : "liveStatus");
  el.textContent = connected ? "CONNECTED" : "NOT CONNECTED";
  el.classList.toggle("connected", connected);
  updateActions();
}
function setCredentialMode(form, record, editing = false) {
  const existing = Boolean(record);
  const fields = form.querySelector(".database-fields");
  const summary = form.querySelector(".connection-summary");
  form.dataset.record = record?.id || "";
  form.dataset.alias = record?.databaseAlias || "";
  const alias = form.querySelector("[name=database_alias]");
  alias.value = record?.databaseAlias || "";
  alias.readOnly = existing && !editing;
  alias.required = !existing || editing;
  ["host", "port", "database", "username"].forEach((name) => {
    const field = form.querySelector(`[name=${name}]`);
    if (record && !editing)
      field.value = record[{ database: "databaseName" }[name] || name];
    if (!record) {
      field.value = name === "port" ? "5432" : "";
    }
    field.readOnly = existing && !editing;
    field.required = true;
  });
  form.querySelector("[name=password]").value = "";
  summary.querySelector("strong").textContent = record?.databaseAlias || "";
  fields.classList.remove("d-none");
  summary.classList.add("d-none");
  form
    .querySelector(".edit-database")
    .classList.toggle("d-none", !existing || editing);
  form
    .querySelector(".cancel-edit")
    .classList.toggle("d-none", !existing || !editing);
  form
    .querySelector(".test-database")
    .classList.toggle("d-none", existing && !editing);
  form
    .querySelector(".save-connect")
    .classList.toggle("d-none", existing && !editing);
  form
    .querySelector(".connect-database")
    .classList.toggle("d-none", !existing || editing);
}
function showConnected(form) {
  form.querySelector(".database-fields").classList.add("d-none");
  form.querySelector(".connection-summary").classList.remove("d-none");
  form.querySelector(".edit-database").classList.remove("d-none");
  form.querySelector(".cancel-edit").classList.add("d-none");
  form.querySelector(".test-database").classList.add("d-none");
  form.querySelector(".save-connect").classList.add("d-none");
  form.querySelector(".connect-database").classList.remove("d-none");
  form.querySelector("[name=password]").value = "";
}
async function loadDatabases() {
  try {
    const data = await json("/databases");
    document.querySelectorAll(".database-select").forEach((select) => {
      select.innerHTML =
        '<option value="">Add New Database</option>' +
        data.databases
          .map(
            (item) =>
              `<option value="${item.id}">${escapeHtml(item.databaseAlias)}</option>`,
          )
          .join("");
      select.addEventListener("change", async () => {
        const form = select.form;
        setConnection(form.id === "tdForm" ? "td" : "live", false);
        if (!select.value) {
          setCredentialMode(form, null);
          return;
        }
        try {
          setCredentialMode(form, await json(`/databases/${select.value}`));
        } catch (error) {
          showNotice(error.message, true);
        }
      });
      setCredentialMode(select.form, null);
    });
  } catch (error) {
    showNotice(error.message, true);
  }
}
async function connect(form, role, url) {
  let attempted;
  try {
    let payload = formData(form);
    attempted = payload;
    if (!payload.database_id) {
      const saved = await json("/databases", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      payload = { database_id: saved.database.id, password: payload.password };
      form.querySelector("[name=database_id]").value = saved.database.id;
      setCredentialMode(form, saved.database);
      await loadDatabases();
      form.querySelector("[name=database_id]").value = saved.database.id;
    }
    const data = await json(url, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setConnection(role, true);
    showConnected(form);
    showNotice(
      `${role === "td" ? "T&D" : "Live"} connected: ${data.database} on ${data.server_address || "server"}`,
    );
  } catch (error) {
    setConnection(role, false);
    await loadDatabases();
    if (error.message.includes("already exists") && attempted) {
      const data = await json("/databases");
      const match = data.databases.find(
        (item) =>
          item.host === attempted.host &&
          String(item.port) === String(attempted.port) &&
          item.databaseName === attempted.database &&
          item.username === attempted.username,
      );
      if (match) {
        form.querySelector("[name=database_id]").value = match.id;
        setCredentialMode(form, await json(`/databases/${match.id}`));
      }
    }
    showNotice(error.message, true);
  }
}
async function testDatabase(form) {
  try {
    await json("/databases/test-connection", {
      method: "POST",
      body: JSON.stringify(formData(form)),
    });
    showNotice("Connection validated successfully.");
  } catch (error) {
    showNotice(error.message, true);
  }
}
async function saveEdit(form) {
  try {
    const data = await json(`/databases/${form.dataset.record}`, {
      method: "PUT",
      body: JSON.stringify(formData(form)),
    });
    setCredentialMode(form, data.database);
    await loadDatabases();
    showNotice("Database configuration updated.");
  } catch (error) {
    showNotice(error.message, true);
  }
}
async function compare() {
  try {
    const data = await json("/api/compare", {
      method: "POST",
      body: JSON.stringify({
        function_search: $("comparisonSearch").value.trim(),
      }),
    });
    state.comparisonType = "functions";
    state.results = data.results.map((x) => ({
      ...x,
      objectType: "FUNCTION",
      selected: x.status === "NEW" || x.status === "MODIFIED",
    }));
    renderSummary();
    renderResults();
    updateActions();
    showNotice(`Compared ${state.results.length} function definitions.`);
  } catch (error) {
    showNotice(error.message, true);
  }
}
async function compareDashboard() {
  const source = $("tdForm").querySelector("[name=database_id]").value;
  const target = $("liveForm").querySelector("[name=database_id]").value;
  if (!source || !target || source === target) {
    showNotice("Select two different saved databases before comparing.", true);
    return;
  }
  const type = document.querySelector("[name=comparisonType]:checked").value;
  const search = $("comparisonSearch").value.trim();
  try {
    let combined = [];
    if (type === "functions" || type === "both") {
      const data = await json("/api/compare", {
        method: "POST",
        body: JSON.stringify({ function_search: search }),
      });
      combined = combined.concat(data.results.map((x) => ({
        ...x,
        objectType: "FUNCTION",
        selected: x.status === "MISSING" || x.status === "MODIFIED",
      })));
    }
    if (type === "tables" || type === "both") {
      const data = await json("/api/tables/compare", {
        method: "POST",
        body: JSON.stringify({ table_search: search }),
      });
      combined = combined.concat(data.results.map((x) => ({
        ...x,
        objectType: "TABLE",
        selected: x.status === "MISSING" || x.status === "MODIFIED",
      })));
    }
    state.comparisonType = type;
    state.results = combined;
    state.filter = "ALL";
    state.query = search.toLowerCase();
    $("resultSearch").value = search;
    document.querySelectorAll("[data-filter]").forEach((button) => button.classList.toggle("active", button.dataset.filter === "ALL"));
    renderSummary();
    renderResults();
    updateActions();
    showNotice(`Comparison complete for ${type}.`);
  } catch (error) {
    showNotice(error.message, true);
  }
}
function openDiff(key) {
  const item = state.results.find((x) => x.key === key);
  if (!item) return;
  $("diffTitle").textContent = item.signature;
  const left = item.live?.definition || "Function does not exist in Live";
  const right =
    item.source?.definition ||
    "Function is not present in the selected T&D scope";
  const parts = Diff.diffLines(left, right);
  let leftHtml = "",
    rightHtml = "";
  parts.forEach((part) => {
    const lines = part.value.replace(/\n$/, "").split("\n");
    lines.forEach((line) => {
      const cls = part.added ? "added" : part.removed ? "removed" : "";
      if (!part.added)
        leftHtml += `<div class="diff-line ${cls}">${escapeHtml(line) || " "}</div>`;
      else leftHtml += '<div class="diff-line empty"> </div>';
      if (!part.removed)
        rightHtml += `<div class="diff-line ${cls}">${escapeHtml(line) || " "}</div>`;
      else rightHtml += '<div class="diff-line empty"> </div>';
    });
  });
  $("diffView").innerHTML =
    `<div class="diff-column">${leftHtml}</div><div class="diff-column">${rightHtml}</div>`;
  bootstrap.Modal.getOrCreateInstance($("diffModal")).show();
}
function escapeHtml(value) {
  return value.replace(
    /[&<>"']/g,
    (ch) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
      })[ch],
  );
}
function openConfirm(keys) {
  state.pendingKeys = keys;
  const items = keys
    .map((key) => state.results.find((x) => x.key === key))
    .filter(Boolean);
  $("confirmTitle").textContent =
    `Deploy ${items.length} selected object${items.length === 1 ? "" : "s"}?`;
  $("confirmCopy").textContent = items.some((x) => x.status === "MODIFIED")
    ? "Modified Live objects will be replaced. New objects will be created after confirmation."
    : "New objects will be created in Live after confirmation.";
  $("confirmList").innerHTML = items
    .map((x) => `${x.status}  ${x.key}`)
    .join("<br>");
  bootstrap.Modal.getOrCreateInstance($("confirmModal")).show();
}
async function deploy() {
  try {
    const selected = state.pendingKeys
      .map((key) => state.results.find((item) => item.key === key))
      .filter(Boolean);
    const groups = ["FUNCTION", "TABLE"].map((objectType) => ({
      objectType,
      items: selected.filter((item) => item.objectType === objectType),
    })).filter((group) => group.items.length);
    const responses = await Promise.all(groups.map((group) => json(
      group.objectType === "TABLE" ? "/api/tables/deploy-selected" : "/api/deploy-selected",
      {
        method: "POST",
        body: JSON.stringify({
          keys: group.items.map((item) => item.key),
          ...(group.objectType === "TABLE" ? { confirm_destructive: true } : {}),
        }),
      },
    )));
    bootstrap.Modal.getInstance($("confirmModal")).hide();
    showNotice(`Deployment committed for ${selected.length} selected object(s).`);
    await compareDashboard();
    await loadHistory();
  } catch (error) {
    showNotice(error.message, true);
  }
}
async function generate() {
  try {
    const selected = state.results.filter((item) => item.selected);
    const groups = ["FUNCTION", "TABLE"].map((objectType) => ({
      objectType,
      items: selected.filter((item) => item.objectType === objectType),
    })).filter((group) => group.items.length);
    const scripts = await Promise.all(groups.map(async (group) => {
      const data = await json(
        group.objectType === "TABLE" ? "/api/tables/generate-script" : "/api/generate-script",
        { method: "POST", body: JSON.stringify({ keys: group.items.map((item) => item.key), ...(group.objectType === "TABLE" ? { confirm_destructive: true } : {}) }) },
      );
      const sql = data.sql || await fetch(data.download).then((response) => response.text());
      return `${sql}\n`;
    }));
    state.generatedSql = scripts.join("\n");
    $("sqlPreview").textContent = state.generatedSql;
    $("downloadSqlBtn").disabled = false;
    showNotice(`${selected.length} selected object(s) written to the SQL preview.`);
  } catch (error) {
    showNotice(error.message, true);
  }
}
function visibleFunctionItems() {
  return state.results.filter(
    (item) =>
      (state.filter === "ALL" || item.status === state.filter) &&
      `${item.name} ${item.signature || ""} ${item.key}`.toLowerCase().includes(state.query),
  );
}
function setSelectedForVisible(value) {
  visibleFunctionItems().forEach((item) => {
    if (item.status === "MISSING" || item.status === "MODIFIED")
      item.selected = value;
  });
  renderResults();
  updateActions();
}
function selectStatus(status) {
  state.results
    .filter((item) => item.status === status)
    .forEach((item) => {
      item.selected = true;
    });
  renderResults();
  updateActions();
}
async function loadHistory() {
  try {
    const data = await json("/api/deployment-history");
    $("historyBody").innerHTML = data.history.length
      ? data.history
          .map(
            (x) =>
              `<tr><td class="signature">${x.timestamp}</td><td>${x.key}</td><td><span class="badge-status badge-${x.status_before}">${x.status_before}</span></td><td class="${x.result === "SUCCESS" ? "result-success" : "result-failed"}">${x.result}</td><td>${escapeHtml(x.error || "")}</td></tr>`,
          )
          .join("")
      : '<tr><td colspan="5" class="empty-state">No deployments in this session.</td></tr>';
  } catch (error) {
    showNotice(error.message, true);
  }
}
["td", "live"].forEach((role) => {
  const form = $(`${role}Form`);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    connect(
      form,
      role,
      role === "td" ? "/api/connect-td" : "/api/test-live-connection",
    );
  });
  form
    .querySelector(".test-database")
    .addEventListener("click", () => testDatabase(form));
  form
    .querySelector(".connect-database")
    .addEventListener("click", () =>
      connect(
        form,
        role,
        role === "td" ? "/api/connect-td" : "/api/test-live-connection",
      ),
    );
  form.querySelector(".edit-database").addEventListener("click", () => {
    setCredentialMode(
      form,
      {
        id: form.dataset.record,
        databaseAlias: form.dataset.alias,
        host: form.querySelector("[name=host]").value,
        port: form.querySelector("[name=port]").value,
        databaseName: form.querySelector("[name=database]").value,
        username: form.querySelector("[name=username]").value,
      },
      true,
    );
  });
  form.querySelector(".cancel-edit").addEventListener("click", async () => {
    try {
      setCredentialMode(form, await json(`/databases/${form.dataset.record}`));
    } catch (error) {
      showNotice(error.message, true);
    }
  });
  form.querySelector(".save-connect").addEventListener("click", () => {
    if (form.dataset.record) saveEdit(form);
    else
      connect(
        form,
        role,
        role === "td" ? "/api/connect-td" : "/api/test-live-connection",
      );
  });
});
$("generateBtn").addEventListener("click", generate);
$("deployBtn").addEventListener("click", () =>
  openConfirm(state.results.filter((x) => x.selected).map((x) => x.key)),
);
$("confirmDeploy").addEventListener("click", deploy);
$("deselectAll").addEventListener("click", () => {
  setSelectedForVisible(false);
});
$("selectAll").addEventListener("click", () => setSelectedForVisible(true));
$("selectNew").addEventListener("click", () => selectStatus("NEW"));
$("selectModified").addEventListener("click", () => selectStatus("MODIFIED"));
$("selectMissing").addEventListener("click", () => selectStatus("MISSING"));
document.querySelectorAll("[data-filter]").forEach((btn) =>
  btn.addEventListener("click", () => {
    document
      .querySelectorAll("[data-filter]")
      .forEach((x) => x.classList.remove("active"));
    btn.classList.add("active");
    state.filter = btn.dataset.filter;
    renderResults();
  }),
);
loadHistory();
loadDatabases();
document
  .querySelectorAll(".save-connect")
  .forEach((button) => (button.type = "button"));
$("compareDashboardBtn").addEventListener("click", compareDashboard);
document.querySelectorAll("[name=comparisonType]").forEach((input) =>
  input.addEventListener("change", () => {
    $("comparisonSearch").placeholder =
      input.value === "tables"
        ? "Partial table name"
        : input.value === "functions"
          ? "Partial function name"
          : "Partial table or function name";
  }),
);
$("comparisonSummary").addEventListener("click", (event) => {
  const button = event.target.closest("[data-summary-status]");
  if (!button) return;
  state.filter = button.dataset.summaryStatus;
  document.querySelectorAll("[data-filter]").forEach((item) => item.classList.toggle("active", item.dataset.filter === state.filter));
  renderSummary();
  renderResults();
});
$("resultSearch").addEventListener("input", (event) => {
  state.query = event.target.value.trim().toLowerCase();
  renderResults();
});
$("generateBtnBottom").addEventListener("click", generate);
$("downloadSqlBtn").addEventListener("click", () => {
  if (!state.generatedSql) return;
  const blob = new Blob([state.generatedSql], { type: "text/sql" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `database_comparison_${new Date().toISOString().replace(/[-:]/g, "").slice(0, 15)}.sql`;
  link.click();
  URL.revokeObjectURL(link.href);
});
loadHistory();
loadDatabases();
