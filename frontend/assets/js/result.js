(function () {
  const content = document.getElementById("pageContent");
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get("id");

  const RISK_COLOR = { Low: "#10b981", Medium: "#f59e0b", High: "#f97316", Critical: "#ef4444" };

  if (!scanId) {
    content.innerHTML = `<div class="panel"><div class="text-center p-4">
      <div style="font-weight:700;font-size:16px;margin-bottom:8px;">No Target Scan Specified</div>
      <div class="text-muted">Return to <a href="history.html">Scan History</a> to select a file.</div>
    </div></div>`;
    return;
  }

  content.innerHTML = `<div id="resultBody"><div class="skeleton" style="height:520px;"></div></div>`;

  async function load() {
    try {
      const r = await Api.getScan(scanId);
      render(r);
    } catch (err) {
      document.getElementById("resultBody").innerHTML = `<div class="panel"><div class="text-center p-4">
        <div style="font-weight:700;font-size:16px;color:var(--red);margin-bottom:8px;">Report Not Found</div>
        <div class="text-muted">${Fmt.escapeHtml(err.message || "This report may have been deleted or expired.")}</div>
      </div></div>`;
    }
  }

  function gaugeSvg(score, level) {
    const color = RISK_COLOR[level] || "#38bdf8";
    const r = 80;
    const circumference = Math.PI * r;
    const pct = Math.max(0, Math.min(100, score)) / 100;
    const offset = circumference * (1 - pct);
    return `
      <svg class="gauge-svg" viewBox="0 0 220 130">
        <path class="gauge-track" d="M30,110 A80,80 0 0 1 190,110" />
        <path class="gauge-fill" d="M30,110 A80,80 0 0 1 190,110"
          style="stroke:${color};stroke-dasharray:${circumference};stroke-dashoffset:${offset};filter:drop-shadow(0 0 10px ${color});" />
      </svg>`;
  }

  function hashRow(label, value) {
    return `
      <div class="hash-row">
        <div class="hash-label">${label}</div>
        <div class="hash-value mono" title="${value}">${value}</div>
        <button class="copy-btn" data-copy="${value}" title="Copy ${label}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
      </div>`;
  }

  function infoRow(label, value) {
    return `<div class="flex-between" style="padding:10px 0;border-bottom:1px solid var(--border);">
      <span class="text-faint" style="font-size:13px;">${label}</span>
      <span class="mono" style="font-size:13px;text-align:right;">${value}</span>
    </div>`;
  }

  function renderEntropyVisualizer(r) {
    const meta = r.metadata || {};
    const sections = (meta.pe && meta.pe.sections) || [];
    
    let sectionBars = '';
    if (sections.length) {
      sectionBars = sections.map(s => {
        const ent = s.entropy || 0;
        const pct = (ent / 8.0) * 100;
        const isHigh = ent >= 7.2;
        const color = isHigh ? "var(--red)" : ent >= 6.0 ? "var(--amber)" : "var(--accent)";
        return `
          <div class="entropy-bar-row">
            <div class="entropy-bar-label">${Fmt.escapeHtml(s.name)}</div>
            <div class="entropy-bar-track">
              <div class="entropy-bar-fill" style="width:${pct}%;background:${color};"></div>
            </div>
            <div class="entropy-bar-val" style="color:${color};font-weight:600;">${ent}/8.0</div>
          </div>`;
      }).join('');
    } else {
      const overallEnt = r.entropy || 0;
      const pct = (overallEnt / 8.0) * 100;
      const color = overallEnt >= 7.2 ? "var(--red)" : overallEnt >= 6.0 ? "var(--amber)" : "var(--accent)";
      sectionBars = `
        <div class="entropy-bar-row">
          <div class="entropy-bar-label">Overall Entropy</div>
          <div class="entropy-bar-track">
            <div class="entropy-bar-fill" style="width:${pct}%;background:${color};"></div>
          </div>
          <div class="entropy-bar-val" style="color:${color};font-weight:600;">${overallEnt}/8.0</div>
        </div>`;
    }

    return `
      <div class="panel">
        <div class="panel-title">Entropy &amp; Binary Structure Matrix</div>
        <p class="text-muted" style="font-size:13px;margin-top:-6px;">
          Entropy values (&gt; 7.2 / 8.0) indicate compressed payloads, binary obfuscation, or packed code.
        </p>
        <div class="entropy-bar-wrap">${sectionBars}</div>
      </div>`;
  }

  function renderStringsTab(r) {
    const s = (r.metadata && r.metadata.strings) || {};
    const matches = s.suspicious_matches || [];
    const urls = s.urls_found || [];
    const ips = s.ips_found || [];
    const sampleStrings = s.sample_strings || [];

    return `
      <div class="panel">
        <div class="panel-title">
          <span>Static String Telemetry</span>
          ${s.scan_truncated ? '<span class="tag">Truncated</span>' : ''}
        </div>
        
        <div class="chip-group mb-16">
          <div class="chip active" onclick="filterStringsTab('all', this)">All Indicators (${matches.length + urls.length + ips.length})</div>
          <div class="chip" onclick="filterStringsTab('matches', this)">Suspicious Patterns (${matches.length})</div>
          <div class="chip" onclick="filterStringsTab('urls', this)">URLs (${urls.length})</div>
          <div class="chip" onclick="filterStringsTab('ips', this)">IP Addresses (${ips.length})</div>
        </div>

        <div id="stringsContainer">
          ${matches.length ? `
            <div class="mb-16 string-block" data-type="matches">
              <label class="field-label">Matched Threat Rules</label>
              <div class="ledger">
                ${matches.map(m => `
                  <div class="ledger-row">
                    <div class="ledger-tick sev-high"></div>
                    <div class="ledger-text">
                      <strong>${Fmt.escapeHtml(m.description)}</strong>
                      <div class="mono text-muted" style="font-size:12px;margin-top:2px;">${Fmt.escapeHtml(m.matched_text)}</div>
                    </div>
                  </div>`).join('')}
              </div>
            </div>` : ''}

          ${urls.length ? `
            <div class="mb-16 string-block" data-type="urls">
              <label class="field-label">URLs Found</label>
              <div class="hash-row" style="flex-direction:column;align-items:flex-start;gap:6px;">
                ${urls.map(u => `<div class="mono text-muted" style="font-size:12.5px;word-break:break-all;">${Fmt.escapeHtml(u)}</div>`).join('')}
              </div>
            </div>` : ''}

          ${ips.length ? `
            <div class="mb-16 string-block" data-type="ips">
              <label class="field-label">IP Addresses Found</label>
              <div class="flex-row" style="flex-wrap:wrap;gap:6px;">
                ${ips.map(ip => `<span class="tag mono">${Fmt.escapeHtml(ip)}</span>`).join('')}
              </div>
            </div>` : ''}

          ${!matches.length && !urls.length && !ips.length ? `
            <div class="text-muted text-center p-4">No suspicious string indicators matched.</div>
          ` : ''}

          ${sampleStrings.length ? `
            <div class="mt-24">
              <label class="field-label">Sample ASCII Strings</label>
              <div class="hex-container" style="max-height:260px;overflow-y:auto;">
                ${sampleStrings.map(st => `<div style="padding:2px 0;">${Fmt.escapeHtml(st)}</div>`).join('')}
              </div>
            </div>` : ''}
        </div>
      </div>`;
  }

  function render(r) {
    const color = RISK_COLOR[r.risk_level] || "#38bdf8";

    document.getElementById("resultBody").innerHTML = `
      <div class="flex-between mb-16" style="flex-wrap:wrap;gap:12px;">
        <div class="flex-row">
          <div style="width:44px;height:44px;border-radius:10px;background:var(--bg-panel);border:1px solid var(--border-strong);display:flex;align-items:center;justify-content:center;color:var(--accent);">
            ${categoryIcon(r.category)}
          </div>
          <div>
            <div style="font-weight:700;font-size:18px;">${Fmt.escapeHtml(r.original_filename)}</div>
            <div class="text-faint" style="font-size:12.5px;">Analyzed ${Fmt.dateTime(r.uploaded_at)}</div>
          </div>
        </div>
        <div class="flex-row">
          <a class="btn btn-primary" href="${Api.reportUrl(r.id)}" target="_blank">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 15V3m0 12-4-4m4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>
            Download PDF Report
          </a>
          <button class="btn btn-secondary" id="copyAllBtn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy SHA-256
          </button>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="tab-bar">
        <div class="tab-item active" onclick="switchTab('overviewTab', this)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>
          Overview &amp; Score
        </div>
        <div class="tab-item" onclick="switchTab('hexTab', this)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>
          Raw Hex Inspector
        </div>
        <div class="tab-item" onclick="switchTab('entropyTab', this)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>
          Entropy Heatmap
        </div>
        <div class="tab-item" onclick="switchTab('stringsTab', this)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/></svg>
          Strings &amp; Indicators
        </div>
      </div>

      <!-- Tab Pane 1: Overview -->
      <div id="overviewTab" class="tab-pane active">
        <div class="grid-2">
          <div>
            <div class="panel" style="text-align:center;padding:28px 20px 20px;">
              <div class="gauge-wrap">
                ${gaugeSvg(r.risk_score, r.risk_level)}
                <div class="gauge-center">
                  <div class="gauge-score" style="color:${color};">${r.risk_score}</div>
                  <div class="gauge-level" style="color:${color};">${r.risk_level} Risk</div>
                </div>
              </div>
              <div class="flex-row" style="justify-content:center;margin-top:12px;">
                <span class="tag">${r.category}</span>
                <span class="tag">${Fmt.escapeHtml(r.mime_type)}</span>
                <span class="tag">Entropy ${r.entropy}/8.0</span>
              </div>
            </div>

            <div class="panel mt-16">
              <div class="panel-title">Cryptographic Fingerprints</div>
              ${hashRow("SHA-256", r.sha256)}
              ${hashRow("SHA-1", r.sha1)}
              ${hashRow("MD5", r.md5)}
              ${infoRow("File size", Fmt.bytes(r.file_size))}
              ${infoRow("Extension", "." + (r.file_extension || "—"))}
              ${infoRow("MIME type", Fmt.escapeHtml(r.mime_type))}
            </div>
          </div>

          <div>
            <div class="panel">
              <div class="panel-title">Heuristic Risk Breakdown</div>
              <div class="ledger">
                ${r.risk_reasons.map(reason => `
                  <div class="ledger-row">
                    <div class="ledger-tick sev-${reason.severity || "low"}"></div>
                    <div class="ledger-text">${Fmt.escapeHtml(reason.text)}</div>
                    <div class="ledger-points">+${reason.points}</div>
                  </div>`).join('') || `<div class="text-muted">No penalty points assigned.</div>`}
              </div>
            </div>

            <div class="panel mt-16">
              <div class="panel-title">Security Recommendations</div>
              <div class="ledger">
                ${r.recommendations.map(rec => `
                  <div class="ledger-row">
                    <div class="ledger-tick" style="background:var(--accent);box-shadow:0 0 6px var(--accent-glow);"></div>
                    <div class="ledger-text">${Fmt.escapeHtml(rec)}</div>
                  </div>`).join('')}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab Pane 2: Hex Inspector -->
      <div id="hexTab" class="tab-pane">
        <div class="panel">
          <div class="panel-title">Header Byte Hex &amp; ASCII Inspection</div>
          <p class="text-muted" style="font-size:13px;margin-top:-6px;margin-bottom:16px;">
            Previewing raw initial file header bytes (offset, hex, ASCII).
          </p>
          ${Fmt.hexTable(r.metadata && r.metadata.hex_sample)}
        </div>
      </div>

      <!-- Tab Pane 3: Entropy Heatmap -->
      <div id="entropyTab" class="tab-pane">
        ${renderEntropyVisualizer(r)}
      </div>

      <!-- Tab Pane 4: Strings -->
      <div id="stringsTab" class="tab-pane">
        ${renderStringsTab(r)}
      </div>
    `;

    document.querySelectorAll(".copy-btn").forEach(btn => {
      btn.addEventListener("click", () => copyToClipboard(btn.dataset.copy, "Hash"));
    });
    document.getElementById("copyAllBtn").addEventListener("click", () => copyToClipboard(r.sha256, "SHA-256"));
  }

  window.switchTab = function (tabId, element) {
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    document.querySelectorAll(".tab-item").forEach(t => t.classList.remove("active"));
    
    document.getElementById(tabId).classList.add("active");
    element.classList.add("active");
  };

  window.filterStringsTab = function (filter, element) {
    document.querySelectorAll(".chip-group .chip").forEach(c => c.classList.remove("active"));
    element.classList.add("active");

    const blocks = document.querySelectorAll(".string-block");
    blocks.forEach(b => {
      if (filter === "all" || b.dataset.type === filter) {
        b.style.display = "block";
      } else {
        b.style.display = "none";
      }
    });
  };

  load();
})();
