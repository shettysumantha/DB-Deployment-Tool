function openTableDiff(key) {
  const item = state.results.find((entry) => entry.key === key && entry.objectType === "TABLE");
  if (!item) return;
  $("diffTitle").textContent = `Table: ${item.key}`;
  const changes = item.changes
    .map((change) => `<div class="change-row">${escapeHtml(change)}</div>`)
    .join("");
  $("diffView").innerHTML =
    `<div class="schema-summary"><strong>Changes Found: ${item.changes.length}</strong>${changes}</div><div class="diff-column"><h4>LIVE / CURRENT</h4><pre>${escapeHtml(item.live?.definition || "Table does not exist in Live")}</pre></div><div class="diff-column"><h4>T&amp;D / PROPOSED</h4><pre>${escapeHtml(item.source?.definition || "Table is not present in selected T&D scope")}</pre></div>`;
  bootstrap.Modal.getOrCreateInstance($("diffModal")).show();
}
async function loadBackups() {
  try {
    const data = await json(
      "/api/backups?" +
        new URLSearchParams({ backup_file_name: $("backupSearch").value }),
    );
    $("backupBody").innerHTML = data.backups.length
      ? data.backups
          .map(
            (item) =>
              `<tr><td>${item.backup_id}</td><td>${escapeHtml(item.backup_file_name || "No file")}</td><td>${item.object_type}</td><td>${escapeHtml(`${item.schema_name}.${item.object_name}`)}</td><td>${escapeHtml(item.deployment_version)}</td><td>${escapeHtml(item.backup_created_at || "")}</td><td>${item.deployment_status}</td><td>${item.backup_file_name ? `<a href="/api/backups/${item.backup_id}/view" target="_blank">View</a>` : ""}</td></tr>`,
          )
          .join("")
      : '<tr><td colspan="8" class="empty-state">No backup metadata found.</td></tr>';
  } catch (error) {
    showNotice(error.message, true);
  }
}
$("backupSearch").addEventListener("input", loadBackups);
loadBackups();
