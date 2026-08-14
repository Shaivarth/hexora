(function () {
  const content = document.getElementById("pageContent");

  content.innerHTML = `
    <div class="grid-2">
      <div>
        <div class="dropzone" id="dropzone" tabindex="0">
          <input type="file" id="fileInput" multiple />
          <svg class="dropzone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M12 16V4m0 0-4 4m4-4 4 4"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>
          </svg>
          <h2 class="display-font">Drag &amp; drop file(s) to inspect</h2>
          <p>or <span class="browse-link">browse local filesystem</span> — max 100 MB per file</p>
          <div class="dropzone-meta">SHA-256 · SHA-1 · MD5 · Shannon Entropy · Magic Bytes · Rule Heuristics</div>
        </div>

        <div id="preHashBadge" style="display:none;" class="panel mt-16 flex-between">
          <div class="flex-row">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><path d="M12 2v20M2 12h20"/></svg>
            <div>
              <div style="font-weight:600;font-size:13.5px;" id="preHashFileName">Calculating SHA-256 digest...</div>
              <div class="mono text-muted" style="font-size:12px;" id="preHashVal">SHA-256: Computing...</div>
            </div>
          </div>
          <span class="tag mono">LOCAL DIGEST</span>
        </div>

        <div id="progressArea" style="display:none;" class="panel scan-progress-card mt-16">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" style="flex:none;">
            <path d="M12 16V4m0 0-4 4m4-4 4 4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>
          </svg>
          <div style="flex:1;">
            <div style="font-size:13px;margin-bottom:6px;font-weight:500;" id="progressLabel">Uploading file buffer...</div>
            <div class="scan-progress-bar-track"><div class="scan-progress-bar-fill" id="progressFill" style="width:0%"></div></div>
          </div>
          <div class="scan-progress-pct" id="progressPct">0%</div>
        </div>

        <div id="analyzingArea" style="display:none;" class="panel scanline-card mt-16">
          <div class="scanline-sweep"></div>
          <div class="flex-row mb-12" style="justify-content:center;">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2">
              <circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>
            </svg>
            <span class="display-font" style="font-size:16px;font-weight:700;">Static Analysis Engine Active</span>
          </div>
          <div class="hex-container" style="text-align:left;height:110px;overflow-y:auto;" id="cyberConsoleLog">
            <div style="color:var(--accent);">$ hexora_triage --ingest target.bin</div>
          </div>
        </div>

        <div id="resultArea"></div>

        <div class="panel mt-24">
          <div class="panel-title">Static Triage Guarantees</div>
          <div class="ledger">
            <div class="ledger-row">
              <div class="ledger-tick sev-low"></div>
              <div class="ledger-text"><strong>Zero Code Execution:</strong> Binary content is analyzed via static inspection without virtual sandbox execution.</div>
            </div>
            <div class="ledger-row">
              <div class="ledger-tick sev-low"></div>
              <div class="ledger-text"><strong>Magic Header Dissection:</strong> Content magic bytes are verified independently of spoofed file extensions.</div>
            </div>
            <div class="ledger-row">
              <div class="ledger-tick sev-low"></div>
              <div class="ledger-text"><strong>Transparent Risk Ledger:</strong> Threat scores (0–100) are generated with line-by-line penalty justifications.</div>
            </div>
          </div>
        </div>
      </div>

      <div>
        <div class="panel">
          <div class="panel-title">
            <span>Recent Inspection Feed</span>
            <a href="history.html" style="font-size:12.5px;font-weight:600;">View All →</a>
          </div>
          <div id="recentList"><div class="skeleton" style="height:240px;"></div></div>
        </div>
      </div>
    </div>
  `;

  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const preHashBadge = document.getElementById("preHashBadge");
  const preHashFileName = document.getElementById("preHashFileName");
  const preHashVal = document.getElementById("preHashVal");
  const progressArea = document.getElementById("progressArea");
  const progressFill = document.getElementById("progressFill");
  const progressPct = document.getElementById("progressPct");
  const progressLabel = document.getElementById("progressLabel");
  const analyzingArea = document.getElementById("analyzingArea");
  const cyberConsoleLog = document.getElementById("cyberConsoleLog");
  const resultArea = document.getElementById("resultArea");

  ["dragenter", "dragover"].forEach(evt =>
    dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add("dragover"); })
  );
  ["dragleave", "drop"].forEach(evt =>
    dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove("dragover"); })
  );

  dropzone.addEventListener("drop", (e) => {
    const files = Array.from(e.dataTransfer.files);
    if (files.length) handleFiles(files);
  });

  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });

  fileInput.addEventListener("change", () => {
    const files = Array.from(fileInput.files);
    if (files.length) handleFiles(files);
  });

  async function handleFiles(files) {
    resultArea.innerHTML = "";
    for (let i = 0; i < files.length; i++) {
      await processSingleFile(files[i], i + 1, files.length);
    }
    fileInput.value = "";
    loadRecent();
  }

  function appendConsoleMsg(msg) {
    if (!cyberConsoleLog) return;
    const line = document.createElement("div");
    line.style.color = "var(--accent)";
    line.style.padding = "2px 0";
    line.textContent = `$ ${msg}`;
    cyberConsoleLog.appendChild(line);
    cyberConsoleLog.scrollTop = cyberConsoleLog.scrollHeight;
  }

  async function processSingleFile(file, currentIdx, totalIdx) {
    dropzone.style.display = "none";
    preHashBadge.style.display = "flex";
    preHashFileName.textContent = `TARGET (${currentIdx}/${totalIdx}): ${file.name}`;
    preHashVal.textContent = "Computing SHA-256 digest...";

    const clientHash = await Fmt.calculateClientHash(file);
    if (clientHash) {
      preHashVal.textContent = `SHA-256: ${clientHash.slice(0, 32)}...`;
    } else {
      preHashVal.textContent = `SIZE: ${Fmt.bytes(file.size)}`;
    }

    progressArea.style.display = "flex";
    progressFill.style.width = "0%";
    progressPct.textContent = "0%";
    progressLabel.textContent = `Uploading file buffer (${currentIdx}/${totalIdx})...`;

    try {
      const result = await Api.uploadScan(file, (pct) => {
        progressFill.style.width = pct + "%";
        progressPct.textContent = pct + "%";
        if (pct >= 100) {
          progressArea.style.display = "none";
          preHashBadge.style.display = "none";
          analyzingArea.style.display = "block";
          
          cyberConsoleLog.innerHTML = `<div style="color:var(--accent);">$ hexora_triage --ingest ${file.name}</div>`;
          setTimeout(() => appendConsoleMsg("[SIGNATURE] Dissecting magic header bytes..."), 300);
          setTimeout(() => appendConsoleMsg("[ENTROPY] Calculating Shannon entropy vectors..."), 600);
          setTimeout(() => appendConsoleMsg("[HEURISTICS] Evaluating static threat rules..."), 900);
        }
      });

      analyzingArea.style.display = "none";
      dropzone.style.display = "block";
      renderResultCard(result);
      Toast.success(`Inspection complete: ${result.original_filename}`);
    } catch (err) {
      progressArea.style.display = "none";
      preHashBadge.style.display = "none";
      analyzingArea.style.display = "none";
      dropzone.style.display = "block";
      Toast.error(err.message || `Failed to analyze ${file.name}`);
    }
  }

  function renderResultCard(r) {
    const badgeClass = Fmt.riskBadgeClass(r.risk_level);
    const topReasons = (r.risk_reasons || []).slice(0, 3);

    const card = document.createElement("div");
    card.className = "panel mt-16";
    card.innerHTML = `
      <div class="flex-between mb-12">
        <div class="flex-row">
          <div style="width:40px;height:40px;border-radius:8px;background:var(--bg-elevated);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;color:var(--accent);">
            ${categoryIcon(r.category)}
          </div>
          <div>
            <div style="font-weight:700;font-size:16px;">${Fmt.escapeHtml(r.original_filename)}</div>
            <div class="text-muted mono" style="font-size:12px;">${Fmt.bytes(r.file_size)} · ${Fmt.escapeHtml(r.mime_type)}</div>
          </div>
        </div>
        <span class="${badgeClass}">${r.risk_level} (${r.risk_score}/100)</span>
      </div>
      <hr class="divider" style="margin:12px 0;">
      <div class="ledger">
        ${topReasons.map(t => `
          <div class="ledger-row">
            <div class="ledger-tick sev-${t.severity || "low"}"></div>
            <div class="ledger-text">${Fmt.escapeHtml(t.text)}</div>
          </div>`).join("") || `<div class="text-muted" style="font-size:13px;">No heuristic indicators triggered.</div>`}
      </div>
      <div class="flex-row mt-16">
        <a class="btn btn-primary" href="result.html?id=${r.id}">View Full Report</a>
        <a class="btn btn-secondary" href="${Api.reportUrl(r.id)}" target="_blank">PDF Report</a>
      </div>
    `;

    resultArea.prepend(card);
  }

  async function loadRecent() {
    const wrap = document.getElementById("recentList");
    try {
      const data = await Api.listScans({ page: 1, page_size: 7, sort_by: "uploaded_at", sort_dir: "desc" });
      if (!data.items.length) {
        wrap.innerHTML = `<div class="text-muted" style="font-size:13px;padding:12px 0;">No scan records found.</div>`;
        return;
      }
      wrap.innerHTML = data.items.map(item => `
        <a href="result.html?id=${item.id}" style="display:flex;align-items:center;gap:12px;padding:10px 4px;border-bottom:1px solid var(--border);text-decoration:none;color:inherit;transition:all 0.18s;" class="recent-row">
          <span style="color:var(--accent);">${categoryIcon(item.category)}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13.5px;font-weight:500;">${Fmt.escapeHtml(Fmt.truncate(item.original_filename, 28))}</span>
          <span class="${Fmt.riskBadgeClass(item.risk_level)}">${item.risk_level}</span>
        </a>
      `).join("");
    } catch (err) {
      wrap.innerHTML = `<div class="text-muted" style="font-size:13px;">Could not load recent activity.</div>`;
    }
  }

  loadRecent();
})();
