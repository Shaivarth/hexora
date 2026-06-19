(function () {
  const content = document.getElementById("pageContent");

  content.innerHTML = `
    <div class="grid-2">
      <div>
        <div class="dropzone" id="dropzone" tabindex="0">
          <input type="file" id="fileInput" />
          <svg class="dropzone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M12 16V4m0 0-4 4m4-4 4 4"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>
          </svg>
          <h2>Drag &amp; drop a file to scan</h2>
          <p>or <span class="browse-link">browse your files</span> — any file type, up to <span id="maxSizeLabel">100&nbsp;MB</span></p>
          <div class="dropzone-meta">SHA-256 / SHA-1 / MD5 · entropy · signature detection · heuristic risk scoring</div>
        </div>

        <div class="panel" style="margin-top: 25px;">
          <div class="panel-title">How this works</div>
          <div class="ledger">
            <div class="ledger-row">
              <div class="ledger-tick sev-low" style="background:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);"></div>
              <div class="ledger-text"><strong>Never executed.</strong> Files are only hashed, parsed, and statically inspected.</div>
            </div>
            <div class="ledger-row">
              <div class="ledger-tick sev-low" style="background:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);"></div>
              <div class="ledger-text"><strong>Signature-based typing.</strong> Detects real file types from content, not extensions.</div>
            </div>
            <div class="ledger-row">
              <div class="ledger-tick sev-low" style="background:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);"></div>
              <div class="ledger-text"><strong>Explainable scoring.</strong> Every point in the 0–100 risk score is tied to a stated reason.</div>
            </div>
            <div class="ledger-row">
              <div class="ledger-tick sev-low" style="background:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);"></div>
              <div class="ledger-text"><strong>Stored for the record.</strong> Every scan is kept in history with a downloadable PDF report.</div>
            </div>
          </div>
        </div>

        <div id="progressArea" style="display:none;" class="panel scan-progress-card mt-16">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--accent);flex:none;">
            <path d="M12 16V4m0 0-4 4m4-4 4 4"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>
          </svg>
          <div style="flex:1;">
            <div style="font-size:13px;margin-bottom:6px;" id="progressLabel">Uploading…</div>
            <div class="scan-progress-bar-track"><div class="scan-progress-bar-fill" id="progressFill" style="width:0%"></div></div>
          </div>
          <div class="scan-progress-pct" id="progressPct">0%</div>
        </div>

        <div id="analyzingArea" style="display:none;" class="panel scanline-card mt-16">
          <div class="scanline-sweep"></div>
          <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" style="color:var(--accent);">
            <circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>
          </svg>
          <div class="scan-status">Running static analysis — hashing, entropy, signature &amp; heuristic checks…</div>
        </div>

        <div id="resultArea"></div>
      </div>

      <div>


        <div class="panel">
          <div class="panel-title">Recent Scans <a href="history.html" style="font-size:12px;font-weight:500;">View all →</a></div>
          <div id="recentList"><div class="skeleton" style="height:160px;"></div></div>
        </div>
      </div>
    </div>
  `;

  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const progressArea = document.getElementById("progressArea");
  const progressFill = document.getElementById("progressFill");
  const progressPct = document.getElementById("progressPct");
  const progressLabel = document.getElementById("progressLabel");
  const analyzingArea = document.getElementById("analyzingArea");
  const resultArea = document.getElementById("resultArea");

  ["dragenter", "dragover"].forEach(evt =>
    dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add("dragover"); })
  );
  ["dragleave", "drop"].forEach(evt =>
    dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove("dragover"); })
  );
  dropzone.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files[0]) handleFile(fileInput.files[0]);
  });

  async function handleFile(file) {
    resultArea.innerHTML = "";
    dropzone.style.display = "none";
    progressArea.style.display = "flex";
    progressFill.style.width = "0%";
    progressPct.textContent = "0%";
    progressLabel.textContent = `Uploading ${file.name}…`;

    try {
      const result = await Api.uploadScan(file, (pct) => {
        progressFill.style.width = pct + "%";
        progressPct.textContent = pct + "%";
        if (pct >= 100) {
          progressArea.style.display = "none";
          analyzingArea.style.display = "block";
        }
      });
      analyzingArea.style.display = "none";
      dropzone.style.display = "block";
      renderResult(result);
      Toast.success(`Scan complete — ${result.original_filename}`);
      loadRecent();
    } catch (err) {
      progressArea.style.display = "none";
      analyzingArea.style.display = "none";
      dropzone.style.display = "block";
      Toast.error(err.message || "Scan failed");
    } finally {
      fileInput.value = "";
    }
  }

  function renderResult(r) {
    const badgeClass = Fmt.riskBadgeClass(r.risk_level);
    const topReasons = (r.risk_reasons || []).slice(0, 3);
    resultArea.innerHTML = `
      <div class="panel mt-16">
        <div class="flex-between mb-12">
          <div class="flex-row">
            ${categoryIcon(r.category)}
            <div>
              <div style="font-weight:600;font-size:14.5px;">${Fmt.escapeHtml(r.original_filename)}</div>
              <div class="text-faint" style="font-size:12px;">${Fmt.bytes(r.file_size)} · ${Fmt.escapeHtml(r.mime_type)}</div>
            </div>
          </div>
          <span class="${badgeClass}">${r.risk_level} · ${r.risk_score}/100</span>
        </div>
        <hr class="divider" style="margin:12px 0;">
        <div class="ledger">
          ${topReasons.map(t => `
            <div class="ledger-row">
              <div class="ledger-tick sev-${t.severity || "low"}"></div>
              <div class="ledger-text">${Fmt.escapeHtml(t.text)}</div>
            </div>`).join("") || `<div class="text-muted" style="font-size:13px;">No heuristic indicators were triggered.</div>`}
        </div>
        <div class="flex-row mt-16">
          <a class="btn btn-primary" href="result.html?id=${r.id}">View full report</a>
          <a class="btn btn-secondary" href="${Api.reportUrl(r.id)}" target="_blank">Download PDF</a>
        </div>
      </div>
    `;
  }

  async function loadRecent() {
    const wrap = document.getElementById("recentList");
    try {
      const data = await Api.listScans({ page: 1, page_size: 6, sort_by: "uploaded_at", sort_dir: "desc" });
      if (!data.items.length) {
        wrap.innerHTML = `<div class="text-muted" style="font-size:13px;padding:10px 0;">No scans yet — upload a file to get started.</div>`;
        return;
      }
      wrap.innerHTML = data.items.map(item => `
        <a href="result.html?id=${item.id}" style="display:flex;align-items:center;gap:10px;padding:9px 4px;border-bottom:1px solid var(--border);text-decoration:none;color:inherit;">
          <span style="color:var(--text-faint);">${categoryIcon(item.category)}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;">${Fmt.escapeHtml(Fmt.truncate(item.original_filename, 28))}</span>
          <span class="${Fmt.riskBadgeClass(item.risk_level)}">${item.risk_level}</span>
        </a>
      `).join("");
    } catch (err) {
      wrap.innerHTML = `<div class="text-muted" style="font-size:13px;">Could not load recent scans.</div>`;
    }
  }

  loadRecent();
})();
