(function () {
  const content = document.getElementById("pageContent");

  content.innerHTML = `
    <div class="stat-grid" id="statGrid">
      ${statCardSkeleton()}${statCardSkeleton()}${statCardSkeleton()}${statCardSkeleton()}
    </div>

    <div class="grid-2 mt-20">
      <div class="panel">
        <div class="panel-title">Fleet Risk Posture</div>
        <div style="height:250px;position:relative;"><canvas id="riskChart"></canvas></div>
      </div>
      <div class="panel">
        <div class="panel-title">File Category Breakdown</div>
        <div style="height:250px;position:relative;"><canvas id="categoryChart"></canvas></div>
      </div>
    </div>

    <div class="panel mt-20">
      <div class="panel-title">Scan Activity — 7-Day Trend</div>
      <div style="height:210px;position:relative;"><canvas id="volumeChart"></canvas></div>
    </div>

    <div class="panel mt-20">
      <div class="panel-title">
        <span>Recent Analyzed Artifacts</span>
        <a href="history.html" style="font-size:12.5px;font-weight:600;">View All History →</a>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>File</th><th>Category</th><th>Size</th><th>Risk Score</th><th>Analyzed</th></tr></thead>
          <tbody id="recentBody"><tr><td colspan="5"><div class="skeleton" style="height:120px;"></div></td></tr></tbody>
        </table>
      </div>
    </div>
  `;

  let chartInstances = {};

  function statCardSkeleton() {
    return `<div class="stat-card"><div class="skeleton" style="height:60px;"></div></div>`;
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

  let cachedStatsData = null;

  async function load() {
    try {
      cachedStatsData = await Api.getDashboardStats();
      renderAll(cachedStatsData);
    } catch (err) {
      Toast.error("Could not load fleet statistics");
    }
  }

  function getThemeColors() {
    const isLight = document.body.getAttribute("data-theme") === "light";
    return {
      textColor: isLight ? "#475569" : "#94a3b8",
      gridColor: isLight ? "rgba(2, 132, 199, 0.08)" : "rgba(56, 189, 248, 0.08)",
      borderColor: isLight ? "#ffffff" : "#0b0f17",
      accent: isLight ? "#0284c7" : "#38bdf8",
      accentSoft: isLight ? "rgba(2, 132, 199, 0.12)" : "rgba(56, 189, 248, 0.12)",
    };
  }

  function renderAll(s) {
    renderStats(s);
    renderRiskChart(s.risk_distribution);
    renderCategoryChart(s.category_distribution);
    renderVolumeChart(s.scans_last_7_days);
    renderRecent(s.recent_scans);
  }

  function renderStats(s) {
    document.getElementById("statGrid").innerHTML =
      statCard("Total Files Inspected", s.total_scans.toLocaleString(), "All-time total", ICONS.total, "var(--accent)") +
      statCard("High-Risk Threats", s.high_risk_count.toLocaleString(), "Severity: High", ICONS.risk, "var(--orange)") +
      statCard("Critical Detections", s.critical_risk_count.toLocaleString(), "Severity: Critical", ICONS.critical, "var(--red)") +
      statCard("Average Risk Score", s.average_risk_score.toFixed(1), "Out of 100", ICONS.avg, "var(--text)");
  }

  function baseChartOptions(colors, extra) {
    return Object.assign({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: colors.textColor,
            font: { family: "Inter", size: 12 }
          }
        }
      },
    }, extra || {});
  }

  function renderRiskChart(dist) {
    const colors = getThemeColors();
    if (chartInstances.risk) chartInstances.risk.destroy();
    const ctx = document.getElementById("riskChart");
    chartInstances.risk = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: Object.keys(dist),
        datasets: [{
          data: Object.values(dist),
          backgroundColor: ["#10b981", "#f59e0b", "#f97316", "#ef4444"],
          borderColor: colors.borderColor,
          borderWidth: 2,
        }],
      },
      options: baseChartOptions(colors, {
        cutout: "68%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: colors.textColor, padding: 14 }
          }
        }
      }),
    });
  }

  function renderCategoryChart(dist) {
    const colors = getThemeColors();
    if (chartInstances.category) chartInstances.category.destroy();
    const ctx = document.getElementById("categoryChart");
    const labels = Object.keys(dist);
    chartInstances.category = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
        datasets: [{
          data: Object.values(dist),
          backgroundColor: colors.accent,
          borderRadius: 6,
          maxBarThickness: 36,
        }],
      },
      options: baseChartOptions(colors, {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: colors.textColor }, grid: { display: false } },
          y: { ticks: { color: colors.textColor, precision: 0 }, grid: { color: colors.gridColor } },
        },
      }),
    });
  }

  function renderVolumeChart(daily) {
    const colors = getThemeColors();
    if (chartInstances.volume) chartInstances.volume.destroy();
    const ctx = document.getElementById("volumeChart");
    const labels = Object.keys(daily).map(d => new Date(d).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }));
    chartInstances.volume = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          data: Object.values(daily),
          borderColor: colors.accent,
          backgroundColor: colors.accentSoft,
          fill: true,
          tension: 0.35,
          pointRadius: 4,
          pointBackgroundColor: colors.accent,
        }],
      },
      options: baseChartOptions(colors, {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: colors.textColor }, grid: { display: false } },
          y: { ticks: { color: colors.textColor, precision: 0 }, grid: { color: colors.gridColor }, beginAtZero: true },
        },
      }),
    });
  }

  function renderRecent(items) {
    const body = document.getElementById("recentBody");
    if (!items.length) {
      body.innerHTML = `<tr><td colspan="5"><div class="text-center text-muted p-4">No inspection records found yet.</div></td></tr>`;
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

  window.addEventListener("themeChanged", () => {
    if (cachedStatsData) renderAll(cachedStatsData);
  });

  load();
})();
