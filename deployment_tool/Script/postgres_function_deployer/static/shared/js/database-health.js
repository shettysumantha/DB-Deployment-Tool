(() => {
  const status = document.getElementById("healthStatus");
  const factsTarget = document.getElementById("healthFacts");
  const chartsTarget = document.getElementById("healthCharts");
  const tablesTarget = document.getElementById("healthTables");
  const sectionsTarget = document.getElementById("healthSections");
  const refresh = document.getElementById("refreshHealth");

  const display = (value, field = "") => {
    if (value === null || value === undefined || value === "") return "Not available";
    if (typeof value === "number" && field.includes("size")) {
      const units = ["B", "KB", "MB", "GB", "TB"];
      let size = value;
      let unit = 0;
      while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit += 1;
      }
      return `${size.toFixed(2)} ${units[unit]}`;
    }
    if (typeof value === "number" && field.includes("percent")) return `${value}%`;
    if (typeof value === "number") return value.toLocaleString();
    return String(value);
  };

  const renderFacts = (facts) => {
    factsTarget.replaceChildren();
    Object.entries(facts).forEach(([label, value]) => {
      const wrapper = document.createElement("dl");
      wrapper.className = "health-fact";
      const term = document.createElement("dt");
      term.textContent = label.replaceAll("_", " ");
      const detail = document.createElement("dd");
      detail.textContent = display(value, label);
      wrapper.append(term, detail);
      factsTarget.append(wrapper);
    });
  };

  const renderTable = (target, columns, rows, emptyMessage) => {
    target.replaceChildren();
    if (!rows.length) {
      const row = target.insertRow();
      const cell = row.insertCell();
      cell.colSpan = columns.length;
      cell.className = "empty-state";
      cell.textContent = emptyMessage;
      return;
    }
    rows.forEach((item) => {
      const row = target.insertRow();
      columns.forEach((column) => {
        const cell = row.insertCell();
        cell.textContent = display(item[column], column);
      });
    });
  };

  const renderSections = (sections) => {
    sectionsTarget.replaceChildren();
    Object.entries(sections).forEach(([title, section]) => {
      const wrapper = document.createElement("section");
      wrapper.className = "admin-section";
      const heading = document.createElement("h2");
      heading.textContent = title;
      wrapper.append(heading);
      if (Array.isArray(section.columns) && Array.isArray(section.rows)) {
        const container = document.createElement("div");
        container.className = "table-wrap admin-table-wrap";
        const table = document.createElement("table");
        table.className = "admin-databases-table";
        const head = table.createTHead().insertRow();
        section.columns.forEach((column) => {
          const cell = document.createElement("th");
          cell.textContent = column.label;
          head.append(cell);
        });
        const body = table.createTBody();
        renderTable(body, section.columns.map((column) => column.key), section.rows, section.empty_message);
        container.append(table);
        wrapper.append(container);
      } else if (Object.values(section).some(Array.isArray)) {
        Object.entries(section).forEach(([name, rows]) => {
          if (!Array.isArray(rows)) return;
          const subheading = document.createElement("h3");
          subheading.textContent = name.replaceAll("_", " ");
          wrapper.append(subheading);
          if (!rows.length) {
            const empty = document.createElement("p");
            empty.className = "empty-state";
            empty.textContent = "No records are currently reported.";
            wrapper.append(empty);
            return;
          }
          const table = document.createElement("table");
          table.className = "admin-databases-table";
          const columns = Object.keys(rows[0]);
          const header = table.createTHead().insertRow();
          columns.forEach((column) => {
            const cell = document.createElement("th");
            cell.textContent = column.replaceAll("_", " ");
            header.append(cell);
          });
          const body = table.createTBody();
          rows.forEach((item) => {
            const row = body.insertRow();
            columns.forEach((column) => {
              const cell = row.insertCell();
              cell.textContent = display(item[column], column);
            });
          });
          const container = document.createElement("div");
          container.className = "table-wrap admin-table-wrap";
          container.append(table);
          wrapper.append(container);
        });
      } else {
        const list = document.createElement("dl");
        list.className = "health-facts";
        Object.entries(section).forEach(([label, value]) => {
          const term = document.createElement("dt");
          term.textContent = label.replaceAll("_", " ");
          const detail = document.createElement("dd");
          detail.textContent = display(value, label);
          list.append(term, detail);
        });
        wrapper.append(list);
      }
      sectionsTarget.append(wrapper);
    });
  };

  const loadHealth = async () => {
    status.textContent = "Loading health information…";
    refresh.disabled = true;
    try {
      const response = await fetch("/api/database-health", { credentials: "same-origin" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Unable to load health information.");
      renderFacts({
        ...data.overview,
        host: data.connection.host,
        port: data.connection.port,
        environment: data.connection.environment,
      });
      const maxConnections = Number(data.overview.max_connections);
      const currentConnections = Number(data.overview.current_connections);
      chartsTarget.replaceChildren();
      if (Number.isFinite(maxConnections) && maxConnections > 0 && Number.isFinite(currentConnections)) {
        const chartLabel = document.createElement("p");
        chartLabel.textContent = `Connection utilization: ${display(data.overview.connection_utilization_percent, "percent")}`;
        const bar = document.createElement("progress");
        bar.max = maxConnections;
        bar.value = Math.min(currentConnections, maxConnections);
        bar.setAttribute("aria-label", "Database connection utilization");
        chartsTarget.append(chartLabel, bar);
      }
      renderTable(
        tablesTarget,
        ["schema", "table", "live_rows", "dead_rows", "table_size_bytes", "index_size_bytes", "last_vacuum", "last_analyze"],
        data.storage.tables,
        "No table statistics are available.",
      );
      renderSections({
        "Largest Databases": {
          columns: [
            { key: "database_name", label: "Database" },
            { key: "size_bytes", label: "Size" },
          ],
          rows: data.storage.databases,
          empty_message: "Database sizes are not available.",
        },
        "Index Analysis": {
          columns: [
            { key: "schema", label: "Schema" },
            { key: "table", label: "Table" },
            { key: "index", label: "Index" },
            { key: "size_bytes", label: "Size" },
            { key: "scans", label: "Scans" },
            { key: "tuples_read", label: "Tuples read" },
            { key: "tuples_fetched", label: "Tuples fetched" },
          ],
          rows: data.storage.indexes,
          empty_message: "No index statistics are available.",
        },
        "Performance": data.performance,
        "Maintenance": data.maintenance,
        "Index Recommendations": {
          potential_unused_indexes: data.storage.unused_indexes,
        },
        "Storage Totals": {
          total_table_size_bytes: data.storage.total_table_size_bytes,
          total_index_size_bytes: data.storage.total_index_size_bytes,
        },
      });
      status.textContent = `Connected to ${data.overview.database_name} at ${data.overview.server}.`;
      refresh.disabled = false;
    } catch (error) {
      status.textContent = error.message;
    }
  };

  if (document.querySelector("[data-database-connection]")?.dataset.connectedId) {
    refresh.disabled = false;
    loadHealth();
  }
  refresh.addEventListener("click", loadHealth);
})();
