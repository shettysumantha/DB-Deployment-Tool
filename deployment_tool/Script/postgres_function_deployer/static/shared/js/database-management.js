const connectionForm = document.getElementById("databaseConnectionForm");
const connectionNotice = document.getElementById("connectionNotice");
const saveConnectionButton = document.getElementById("saveDatabaseConnection");
const cancelEditButton = document.getElementById("cancelDatabaseEdit");
const connectionCsrf = document.querySelector('meta[name="csrf-token"]').content;

function showConnectionNotice(message, error = false) {
  connectionNotice.textContent = message;
  connectionNotice.className = `notice ${error ? "error" : ""}`;
  connectionNotice.classList.remove("d-none");
}

function resetConnectionForm() {
  connectionForm.reset();
  connectionForm.elements.database_id.value = "";
  connectionForm.elements.port.value = "5432";
  connectionForm.elements.password.required = true;
  connectionForm.elements.password.placeholder = "";
  saveConnectionButton.textContent = "Test and add connection";
  cancelEditButton.classList.add("d-none");
  document.getElementById("connectionFormTitle").textContent = "Add connection";
}

async function sendConnectionRequest(url, method, body) {
  const response = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": connectionCsrf,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Database connection request failed.");
  return result;
}

connectionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  saveConnectionButton.disabled = true;
  const databaseId = connectionForm.elements.database_id.value;
  const payload = Object.fromEntries(new FormData(connectionForm));
  try {
    await sendConnectionRequest(
      databaseId
        ? `/api/admin/database-connections/${encodeURIComponent(databaseId)}`
        : "/api/admin/database-connections",
      databaseId ? "PUT" : "POST",
      payload,
    );
    showConnectionNotice(databaseId ? "Connection updated." : "Connection saved.");
    resetConnectionForm();
    window.location.reload();
  } catch (error) {
    showConnectionNotice(error.message, true);
  } finally {
    saveConnectionButton.disabled = false;
  }
});

cancelEditButton.addEventListener("click", () => {
  resetConnectionForm();
  connectionNotice.classList.add("d-none");
});

document.querySelectorAll("[data-edit-connection]").forEach((button) => {
  button.addEventListener("click", () => {
    const row = button.closest("[data-connection-id]");
    connectionForm.elements.database_id.value = row.dataset.connectionId;
    connectionForm.elements.host.value = row.dataset.host;
    connectionForm.elements.port.value = row.dataset.port;
    connectionForm.elements.database.value = row.dataset.database;
    connectionForm.elements.username.value = row.dataset.username;
    connectionForm.elements.sslmode.value = row.dataset.sslmode || "require";
    connectionForm.elements.environment.value = row.dataset.environment;
    connectionForm.elements.password.value = "";
    connectionForm.elements.password.required = false;
    connectionForm.elements.password.placeholder = "Leave blank to keep saved password";
    saveConnectionButton.textContent = "Test and save changes";
    cancelEditButton.classList.remove("d-none");
    document.getElementById("connectionFormTitle").textContent = "Edit connection";
    connectionForm.scrollIntoView({ behavior: "smooth", block: "start" });
    connectionForm.elements.host.focus();
  });
});

document.querySelectorAll("[data-connect-connection], [data-disconnect-connection]").forEach((button) => {
  button.addEventListener("click", async () => {
    const row = button.closest("[data-connection-id]");
    const action = button.hasAttribute("data-connect-connection") ? "connect" : "disconnect";
    button.disabled = true;
    try {
      await sendConnectionRequest(
        `/api/database-connections/${encodeURIComponent(row.dataset.connectionId)}/${action}`,
        "POST",
      );
      window.location.reload();
    } catch (error) {
      showConnectionNotice(error.message, true);
      button.disabled = false;
    }
  });
});

document.querySelectorAll("[data-remove-connection]").forEach((button) => {
  button.addEventListener("click", async () => {
    const row = button.closest("[data-connection-id]");
    const identity = `${row.dataset.host} → ${row.dataset.database}`;
    if (!window.confirm(`Remove saved connection ${identity}? The database itself will not be deleted.`)) return;
    button.disabled = true;
    try {
      await sendConnectionRequest(
        `/api/admin/database-connections/${encodeURIComponent(row.dataset.connectionId)}`,
        "DELETE",
      );
      window.location.reload();
    } catch (error) {
      showConnectionNotice(error.message, true);
      button.disabled = false;
    }
  });
});
