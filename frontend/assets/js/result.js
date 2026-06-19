(function () {
  const content = document.getElementById("pageContent");
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get("id");

  const RISK_COLOR = { Low: "#2ECC71", Medium: "#F5A623", High: "#F2994A", Critical: "#E5484D" };

  if (!scanId) {
    content.innerHTML = `<div class="panel"><div class="table-wrap-empty">
      <div class="empty-title">No scan selected</div>
      <div>Go to <a href="history.html">Scan History</a> to pick a file.</div>
    </div></div>`;
    return;
  }

  content.innerHTML = `<div id="resultBody"><div class="skeleton" style="height:480px;"></div></div>`;

  async function load() {
    try {
      const r = await Api.getScan(scanId);
      render(r);
    } catch (err) {
      document.getElementById("resultBody").innerHTML = `<div class="panel"><div class="table-wrap-empty">
        <div class="empty-title">Scan not found</div>
        <div>${Fmt.escapeHtml(err.message || "This scan may have been removed.")}</div>
      </div></div>`;
    }
  }

  function gaugeSvg(score, level) {
    const color = RISK_COLOR[level] || "#2DD4BF";
    const r = 80;
    const circumference = Math.PI * r; // half circle arc length
    const pct = Math.max(0, Math.min(100, score)) / 100;
    const offset = circumference * (1 - pct);
    return `
      <svg class="gauge-svg" viewBox="0 0 220 130">
        <path class="gauge-track" d="M30,110 A80,80 0 0 1 190,110" />
        <path class="gauge-fill" d="M30,110 A80,80 0 0 1 190,110"
          style="stroke:${color};stroke-dasharray:${circumference};stroke-dashoffset:${offset};" />
      </svg>`;
  }

  function severityTick(sev) {
    return `<div class="ledger-tick sev-${sev}"></div>`;
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
    return `<div class="flex-between" style="padding:9px 0;border-bottom:1px solid var(--border);">
      <span class="text-faint" style="font-size:12.5px;">${label}</span>
      <span class="mono" style="font-size:12.5px;text-align:right;">${value}</span>
    </div>`;
  }

  function metadataSection(meta) {
    if (!meta || Object.keys(meta).length === 0) return "";
    const blocks = [];

    if (meta.pe) blocks.push(peBlock(meta.pe));
    if (meta.elf) blocks.push(kvBlock("ELF Binary", meta.elf));
    if (meta.office_legacy) blocks.push(macroBlock(meta.office_legacy));
    if (meta.office_ooxml) blocks.push(macroBlock(meta.office_ooxml));
    if (meta.pdf) blocks.push(kvBlock("PDF Document", meta.pdf));
    if (meta.archive) blocks.push(archiveBlock(meta.archive));
    if (meta.image) blocks.push(kvBlock("Image", meta.image));
    if (meta.script) blocks.push(kvBlock("Script", meta.script));
    if (meta.strings) blocks.push(stringsBlock(meta.strings));

    return blocks.join("");
  }

  function kvBlock(title, obj) {
    const rows = Object.entries(obj)
      .filter(([k]) => k !== "sections")
      .map(([k, v]) => infoRow(prettyKey(k), Fmt.escapeHtml(formatVal(v))))
      .join("");
    return `<div class="panel mt-16"><div class="panel-title">${title}</div>${rows}</div>`;
  }

  function peBlock(pe) {
    const rows = Object.entries(pe)
      .filter(([k]) => !["sections", "characteristics"].includes(k))
      .map(([k, v]) => infoRow(prettyKey(k), Fmt.escapeHtml(formatVal(v))))
      .join("");
    const chars = (pe.characteristics || []).map(c => `<span class="tag">${c}</span>`).join(" ");
    const sections = (pe.sections || []).map(s => `
      <tr>
        <td class="mono">${Fmt.escapeHtml(s.name)}</td>
        <td class="mono text-muted">${s.raw_size.toLocaleString()} B</td>
        <td class="mono ${s.entropy >= 7.4 ? "" : "text-muted"}" style="${s.entropy >= 7.4 ? "color:var(--red);font-weight:600;" : ""}">${s.entropy ?? "—"}</td>
      </tr>`).join("");
    return `
      <div class="panel mt-16">
        <div class="panel-title">PE Executable Structure</div>
        ${rows}
        ${chars ? `<div class="mt-12">${chars}</div>` : ""}
        ${sections ? `
          <div class="mt-16" style="font-size:11.5px;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Sections</div>
          <table class="data-table"><thead><tr><th>Name</th><th>Raw Size</th><th>Entropy</th></tr></thead><tbody>${sections}</tbody></table>
        ` : ""}
      </div>`;
  }

  function macroBlock(obj) {
    const hasMacro = obj.has_macros;
    return `
      <div class="panel mt-16">
        <div class="panel-title">Office Macro Inspection</div>
        <div class="flex-row mb-12">
          <span class="${hasMacro ? "badge badge-high" : "badge badge-low"}">${hasMacro ? "Macros detected" : "No macros detected"}</span>
        </div>
        ${(obj.indicators || obj.macro_entries || []).map(i => `<div class="tag" style="margin:2px 4px 2px 0;">${Fmt.escapeHtml(i)}</div>`).join("")}
      </div>`;
  }

  function archiveBlock(a) {
    if (a.error) return `<div class="panel mt-16"><div class="panel-title">Archive</div><div class="text-muted">${Fmt.escapeHtml(a.error)}</div></div>`;
    const rows = [
      infoRow("Entries", a.entry_count),
      infoRow("Compression ratio", a.compression_ratio + "x"),
      infoRow("Uncompressed size", Fmt.bytes(a.uncompressed_size)),
      infoRow("Encrypted", a.is_encrypted ? "Yes" : "No"),
    ].join("");
    const dangerous = (a.dangerous_members || []).map(m => `<div class="tag" style="margin:2px 4px 2px 0;color:var(--red);border-color:var(--red);">${Fmt.escapeHtml(m)}</div>`).join("");
    return `
      <div class="panel mt-16">
        <div class="panel-title">Archive Contents</div>
        ${rows}
        ${dangerous ? `<div class="mt-12"><div class="text-faint" style="font-size:11.5px;margin-bottom:6px;">Executable/script members</div>${dangerous}</div>` : ""}
      </div>`;
  }

  function stringsBlock(s) {
    const matches = (s.suspicious_matches || []).map(m => `
      <div class="ledger-row">
        ${severityTick("high")}
        <div class="ledger-text"><strong>${Fmt.escapeHtml(m.description)}</strong><br><span class="mono text-faint">${Fmt.escapeHtml(m.matched_text)}</span></div>
      </div>`).join("");
    const urls = (s.urls_found || []).map(u => `<div class="mono text-muted" style="font-size:12px;padding:3px 0;word-break:break-all;">${Fmt.escapeHtml(u)}</div>`).join("");
    const ips = (s.ips_found || []).map(i => `<span class="tag mono" style="margin:2px 4px 2px 0;">${Fmt.escapeHtml(i)}</span>`).join("");
    return `
      <div class="panel mt-16">
        <div class="panel-title">Static String Analysis ${s.scan_truncated ? '<span class="tag">truncated</span>' : ""}</div>
        ${matches ? `<div class="ledger">${matches}</div>` : `<div class="text-muted" style="font-size:13px;">No attacker-tooling string patterns matched.</div>`}
        ${urls ? `<div class="mt-16"><div class="text-faint" style="font-size:11.5px;margin-bottom:6px;">URLs found</div>${urls}</div>` : ""}
        ${ips ? `<div class="mt-12"><div class="text-faint" style="font-size:11.5px;margin-bottom:6px;">IP addresses found</div>${ips}</div>` : ""}
      </div>`;
  }

  function prettyKey(k) {
    return k.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  }
  function formatVal(v) {
    if (v === null || v === undefined) return "—";
    if (typeof v === "boolean") return v ? "Yes" : "No";
    if (Array.isArray(v)) return v.length ? v.join(", ") : "None";
    return String(v);
  }

  function render(r) {
    const color = RISK_COLOR[r.risk_level] || "#2DD4BF";
    document.getElementById("resultBody").innerHTML = `
      <div class="flex-between mb-16" style="flex-wrap:wrap;gap:12px;">
        <div class="flex-row">
          <div style="width:40px;height:40px;border-radius:10px;background:var(--bg-panel);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;color:var(--accent);">
            ${categoryIcon(r.category)}
          </div>
          <div>
            <div style="font-weight:700;font-size:16px;">${Fmt.escapeHtml(r.original_filename)}</div>
            <div class="text-faint" style="font-size:12.5px;">Scanned ${Fmt.dateTime(r.uploaded_at)}</div>
          </div>
        </div>
        <div class="flex-row">
          <a class="btn btn-secondary" href="${Api.reportUrl(r.id)}" target="_blank">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 15V3m0 12-4-4m4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>
            Download PDF Report
          </a>
          <button class="btn btn-ghost" id="copyAllBtn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy SHA-256
          </button>
        </div>
      </div>

      <div class="grid-2">
        <div>
          <div class="panel" style="text-align:center;padding:28px 20px 18px;">
            <div class="gauge-wrap">
              ${gaugeSvg(r.risk_score, r.risk_level)}
              <div class="gauge-center">
                <div class="gauge-score" style="color:${color};">${r.risk_score}</div>
                <div class="gauge-level" style="color:${color};">${r.risk_level} Risk</div>
              </div>
            </div>
            <div class="flex-row" style="justify-content:center;margin-top:8px;">
              <span class="tag">${r.category}</span>
              <span class="tag">${Fmt.escapeHtml(r.mime_type)}</span>
              <span class="tag">Entropy ${r.entropy}/8.0</span>
            </div>
          </div>

          <div class="panel mt-16">
            <div class="panel-title">File Identification</div>
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
            <div class="panel-title">Why this score?</div>
            <div class="ledger">
              ${r.risk_reasons.map(reason => `
                <div class="ledger-row">
                  ${severityTick(reason.severity)}
                  <div class="ledger-text">${Fmt.escapeHtml(reason.text)}</div>
                  <div class="ledger-points">+${reason.points}</div>
                </div>`).join("")}
            </div>
          </div>

          <div class="panel mt-16">
            <div class="panel-title">Security Recommendations</div>
            <div class="ledger">
              ${r.recommendations.map(rec => `
                <div class="ledger-row">
                  <div class="ledger-tick" style="background:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);"></div>
                  <div class="ledger-text">${Fmt.escapeHtml(rec)}</div>
                </div>`).join("")}
            </div>
          </div>
        </div>
      </div>

      ${metadataSection(r.metadata)}
    `;

    document.querySelectorAll(".copy-btn").forEach(btn => {
      btn.addEventListener("click", () => copyToClipboard(btn.dataset.copy, "Hash"));
    });
    document.getElementById("copyAllBtn").addEventListener("click", () => copyToClipboard(r.sha256, "SHA-256"));
  }

  load();
})();
