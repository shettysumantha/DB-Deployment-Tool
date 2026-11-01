const activeDatabaseSelector = document.getElementById("activeDatabaseSelector");
const activeDatabaseSelect = document.getElementById("activeDatabaseSelect");
const activeDatabaseStatus = document.getElementById("activeDatabaseStatus");
const activeDatabaseCsrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

if (activeDatabaseSelector && activeDatabaseSelect) {
  async function loadActiveDatabase() {
    try {
      const response = await fetch("/api/active-database", {
        credentials: "same-origin",
      });
      if (response.status === 403) return;
      if (!response.ok) {
        throw new Error(`Saved connections could not be loaded (HTTP ${response.status}).`);
      }
      const data = await response.json();
      activeDatabaseSelect.replaceChildren();

      const noConnection = document.createElement("option");
      noConnection.value = "";
      noConnection.textContent = "Select a connection";
      activeDatabaseSelect.append(noConnection);

      data.connections.forEach((connection) => {
        const option = document.createElement("option");
        option.value = connection.id;
        option.textContent = `${connection.host} → ${connection.databaseName}`;
        activeDatabaseSelect.append(option);
      });

      if (data.active_connection) {
        activeDatabaseSelect.value = String(data.active_connection.id);
        activeDatabaseStatus.textContent =
          `Active: ${data.active_connection.host} → ${data.active_connection.databaseName}`;
      } else {
        activeDatabaseStatus.textContent = "Select a connection for single-database tools.";
      }
      activeDatabaseSelector.hidden = false;
    } catch (error) {
      activeDatabaseSelector.hidden = false;
      activeDatabaseStatus.textContent = error.message || "Saved connections could not be loaded.";
    }
  }

  activeDatabaseSelect.addEventListener("change", async () => {
    activeDatabaseSelect.disabled = true;
    activeDatabaseStatus.textContent = "Switching connection…";
    try {
      const response = await fetch("/api/active-database", {
        method: "PUT",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": activeDatabaseCsrf,
        },
        body: JSON.stringify({
          database_id: activeDatabaseSelect.value || null,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Connection could not be selected.");
      activeDatabaseStatus.textContent = data.active_connection
        ? `Active: ${data.active_connection.host} → ${data.active_connection.databaseName}`
        : "Select a connection for single-database tools.";
      document.dispatchEvent(new CustomEvent("active-database-changed", {
        detail: { connection: data.active_connection },
      }));
      window.location.reload();
    } catch (error) {
      activeDatabaseStatus.textContent = error.message;
      await loadActiveDatabase();
    } finally {
      activeDatabaseSelect.disabled = false;
    }
  });

  loadActiveDatabase();
}
