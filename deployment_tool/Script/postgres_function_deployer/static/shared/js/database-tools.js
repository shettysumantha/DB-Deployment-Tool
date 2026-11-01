(() => {
  const queryStatus = document.getElementById("queryStatus");
  const sqlInput = document.getElementById("databaseSql");
  const resultsTable = document.getElementById("queryResults");
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";

  const addCell = (row, value, tag = "td") => {
    const cell = document.createElement(tag);
    cell.textContent = value === null || value === undefined ? "—" : String(value);
    row.appendChild(cell);
  };

  const renderResults = (result) => {
    const head = resultsTable.querySelector("thead");
    const body = resultsTable.querySelector("tbody");
    head.replaceChildren();
    body.replaceChildren();
    if (!result.columns) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.className = "empty-state";
      cell.textContent = result.message;
      return;
    }
    const header = head.insertRow();
    result.columns.forEach((column) => addCell(header, column, "th"));
    result.rows.forEach((values) => {
      const row = body.insertRow();
      values.forEach((value) => addCell(row, value));
    });
    if (result.truncated) {
      queryStatus.textContent = result.truncation_reason === "row_limit"
        ? `Showing the first ${result.row_limit} rows. Narrow the query to see fewer results.`
        : "Results exceeded the response-size limit and were truncated.";
    } else {
      queryStatus.textContent = `${result.rows.length} row(s) returned.`;
    }
  };

  const submit = async (operation) => {
    const sql = sqlInput.value.trim();
    if (!sql) {
      queryStatus.textContent = "Enter a SQL statement first.";
      return;
    }
    const confirmVacuum = operation !== "vacuum_analyze"
      || window.confirm("Run this targeted VACUUM ANALYZE on the active database?");
    if (!confirmVacuum) return;
    queryStatus.textContent = "Running database operation…";
    try {
      const response = await fetch("/api/database-query", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({
          operation,
          sql,
          confirm_vacuum: confirmVacuum,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Database operation failed.");
      renderResults(result);
    } catch (error) {
      queryStatus.textContent = error.message;
    }
  };

  document.getElementById("runReadQuery").addEventListener("click", () => submit("query"));
  document.getElementById("runVacuumAnalyze").addEventListener("click", () => submit("vacuum_analyze"));
})();
