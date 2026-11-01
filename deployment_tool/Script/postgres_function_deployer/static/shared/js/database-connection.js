(() => {
  const panel = document.querySelector("[data-database-connection]");
  if (!panel) return;

  const select = panel.querySelector("#databaseConnectionSelect");
  const connectButton = panel.querySelector("[data-connect-selected]");
  const disconnectButton = panel.querySelector("[data-disconnect-selected]");
  const status = panel.querySelector("[data-connection-status]");
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  let connectedId = panel.dataset.connectedId;

  const updateControls = () => {
    if (connectButton) connectButton.disabled = !select || !select.value;
    if (disconnectButton) disconnectButton.disabled = !connectedId;
  };

  const send = async (id, action) => {
    const response = await fetch(`/api/database-connections/${encodeURIComponent(id)}/${action}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken },
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Unable to ${action} database connection.`);
    return result;
  };

  if (connectButton) {
    connectButton.addEventListener("click", async () => {
      if (!select?.value) return;
      connectButton.disabled = true;
      status.textContent = "Connecting…";
      try {
        await send(select.value, "connect");
        window.location.reload();
      } catch (error) {
        status.textContent = error.message;
        connectButton.disabled = false;
      }
    });
  }

  if (disconnectButton) {
    disconnectButton.addEventListener("click", async () => {
      if (!connectedId) return;
      disconnectButton.disabled = true;
      status.textContent = "Disconnecting…";
      try {
        await send(connectedId, "disconnect");
        window.location.reload();
      } catch (error) {
        status.textContent = error.message;
        disconnectButton.disabled = false;
      }
    });
  }

  if (select) select.addEventListener("change", updateControls);
  updateControls();
})();
