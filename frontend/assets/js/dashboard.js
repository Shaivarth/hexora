(function () {
  const content = document.getElementById("pageContent");

  content.innerHTML = `
    <div class="stat-grid" id="statGrid">
      ${statCardSkeleton()}${statCardSkeleton()}${statCardSkeleton()}${statCardSkeleton()}
    </div>

    <div class="grid-2 mt-16">
      <div class="panel">
        <div class="panel-title">Risk Distribution</div>
        <div style="height:260px;"><canvas id="riskChart"></canvas></div>
      </div>
      <div class="panel">
        <div class="panel-title">File Category Breakdown</div>
        <div style="height:260px;"><canvas id="categoryChart"></canvas></div>
      </div>
    </div>

    <div class="panel mt-16">
      <div class="panel-title">Scan Volume — Last 7 Days</div>
      <div style="height:200px;"><canvas id="volumeChart"></canvas></div>
    </div>

    <div class="panel mt-16">
      <div class="panel-title">Recent Uploads <a href="history.html" style="font-size:12px;font-weight:500;">View all →</a></div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>File</th><th>Category</th><th>Size</th><th>Risk</th><th>Scanned</th></tr></thead>
          <tbody id="recentBody"><tr><td colspan="5"><div class="skeleton" style="height:120px;"></div></td></tr></tbody>
        </table>
      </div>
    </div>
  `;

  function statCardSkeleton() {
    return `<div class="stat-card"><div class="skeleton" style="height:54px;"></div></div>`;
  }

  function statCard(label, value, sub, iconSvg, color) {
    return `
      <div class="stat-card">
        <div class="stat-label">${label}</div>
        <div class="stat-value">${value}</div>
        <div class="stat-sub">${sub}</div>
        <div class="stat-icon" style="color:${color};">${iconSvg}</div>
      </div>`;
  }

  const ICONS = {
    total: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>',
    risk: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0Z"/></svg>',
    avg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
    critical: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M14.5 9.5l-5 5m0-5 5 5"/></svg>',
  };

  async function load() {
    try {
      const s = await Api.getDashboardStats();
      renderStats(s);
      renderRiskChart(s.risk_distribution);
      renderCategoryChart(s.category_distribution);
      renderVolumeChart(s.scans_last_7_days);
      renderRecent(s.recent_scans);
    } catch (err) {
      Toast.error("Could not load dashboard statistics");
    }
  }

  function renderStats(s) {
    document.getElementById("statGrid").innerHTML =
      statCard("Total Files Scanned", s.total_scans.toLocaleString(), "All-time", ICONS.total, "var(--accent)") +
      statCard("High-Risk Detections", s.high_risk_count.toLocaleString(), "Risk level: High", ICONS.risk, "var(--orange)") +
      statCard("Critical Detections", s.critical_risk_count.toLocaleString(), "Risk level: Critical", ICONS.critical, "var(--red)") +
      statCard("Average Risk Score", s.average_risk_score.toFixed(1), "Out of 100", ICONS.avg, "var(--white)");
  }

  function baseChartOptions(extra) {
    return Object.assign({
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: "#8A99A8", font: { family: "IBM Plex Sans", size: 11.5 } } } },
    }, extra || {});
  }

  function renderRiskChart(dist) {
    const ctx = document.getElementById("riskChart");
    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: Object.keys(dist),
        datasets: [{
          data: Object.values(dist),
          backgroundColor: ["#115c2fff", "#ffbc51ff", "#f38321ff", "#ab181dff"],
          borderColor: "#0A0F14",
          borderWidth: 0.2,
        }],
      },
      options: baseChartOptions({ cutout: "62%", plugins: { legend: { position: "bottom", labels: { color: "#8A99A8" } } } }),
    });
  }

  function renderCategoryChart(dist) {
    const ctx = document.getElementById("categoryChart");
    const labels = Object.keys(dist);
    new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
        datasets: [{
          data: Object.values(dist),
          backgroundColor: "#2da5d4ff",
          borderRadius: 5,
          maxBarThickness: 34,
        }],
      },
      options: baseChartOptions({
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#8A99A8" }, grid: { display: false } },
          y: { ticks: { color: "#8A99A8", precision: 0 }, grid: { color: "#1E2A35" } },
        },
      }),
    });
  }

  function renderVolumeChart(daily) {
    const ctx = document.getElementById("volumeChart");
    const labels = Object.keys(daily).map(d => new Date(d).toLocaleDateString(undefined, { weekday: "short" }));
    new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          data: Object.values(daily),
          borderColor: "#4aa1e0ff",
          backgroundColor: "rgba(45, 181, 212, 0.12)",
          fill: true,
          tension: 0.35,
          pointRadius: 3,
          pointBackgroundColor: "#2da5d4ff",
        }],
      },
      options: baseChartOptions({
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#8A99A8" }, grid: { display: false } },
          y: { ticks: { color: "#8A99A8", precision: 0 }, grid: { color: "#1E2A35" }, beginAtZero: true },
        },
      }),
    });
  }

  function renderRecent(items) {
    const body = document.getElementById("recentBody");
    if (!items.length) {
      body.innerHTML = `<tr><td colspan="5"><div class="table-wrap-empty">No scans yet.</div></td></tr>`;
      return;
    }
    body.innerHTML = items.map(item => `
      <tr onclick="window.location.href='result.html?id=${item.id}'">
        <td><div class="filename-cell">${categoryIcon(item.category)}<span>${Fmt.escapeHtml(Fmt.truncate(item.original_filename, 36))}</span></div></td>
        <td><span class="tag">${item.category}</span></td>
        <td class="mono text-muted">${Fmt.bytes(item.file_size)}</td>
        <td><span class="${Fmt.riskBadgeClass(item.risk_level)}">${item.risk_level} · ${item.risk_score}</span></td>
        <td class="text-muted">${Fmt.relativeTime(item.uploaded_at)}</td>
      </tr>
    `).join("");
  }

  load();
})();
