(function () {
  const content = document.getElementById("pageContent");
  const params = new URLSearchParams(window.location.search);

  const state = {
    page: 1,
    page_size: 15,
    search: params.get("search") || "",
    risk_level: "all",
    category: "all",
    date_from: "",
    date_to: "",
    sort_by: "uploaded_at",
    sort_dir: "desc",
  };

  content.innerHTML = `
    <div class="panel">
      <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;">
        <div style="flex:1;min-width:220px;">
          <label class="field-label">Search</label>
          <div class="input-icon-wrap">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
            <input class="input" id="fSearch" placeholder="Filename, SHA-256, SHA-1, or MD5" value="${Fmt.escapeHtml(state.search)}" />
          </div>
        </div>
        <div>
          <label class="field-label">Risk Level</label>
          <select class="input" id="fRisk" style="width:140px;">
            <option value="all">All levels</option>
            <option value="Low">Low</option>
            <option value="Medium">Medium</option>
            <option value="High">High</option>
            <option value="Critical">Critical</option>
          </select>
        </div>
        <div>
          <label class="field-label">Category</label>
          <select class="input" id="fCategory" style="width:140px;">
            <option value="all">All types</option>
            <option value="executable">Executable</option>
            <option value="document">Document</option>
            <option value="archive">Archive</option>
            <option value="image">Image</option>
            <option value="script">Script</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div>
          <label class="field-label">From</label>
          <input class="input" type="date" id="fFrom" style="width:140px;" />
        </div>
        <div>
          <label class="field-label">To</label>
          <input class="input" type="date" id="fTo" style="width:140px;" />
        </div>
        <button class="btn btn-secondary" id="clearFilters">Clear</button>
      </div>
    </div>

    <div class="panel mt-16">
      <div class="table-scroll">
        <table class="data-table">
          <thead>
            <tr>
              <th data-sort="original_filename">File <span class="sort-arrow"></span></th>
              <th>Category</th>
              <th class="hash-cell">SHA-256</th>
              <th data-sort="file_size">Size <span class="sort-arrow"></span></th>
              <th data-sort="risk_score">Risk <span class="sort-arrow"></span></th>
              <th data-sort="uploaded_at">Scanned <span class="sort-arrow"></span></th>
            </tr>
          </thead>
          <tbody id="rows"><tr><td colspan="6"><div class="skeleton" style="height:280px;"></div></td></tr></tbody>
        </table>
      </div>
      <div class="pagination" id="pagination"></div>
    </div>
  `;

  const els = {
    search: document.getElementById("fSearch"),
    risk: document.getElementById("fRisk"),
    category: document.getElementById("fCategory"),
    from: document.getElementById("fFrom"),
    to: document.getElementById("fTo"),
    rows: document.getElementById("rows"),
    pagination: document.getElementById("pagination"),
  };

  let searchDebounce;
  els.search.addEventListener("input", () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => { state.search = els.search.value.trim(); state.page = 1; load(); }, 350);
  });
  els.risk.addEventListener("change", () => { state.risk_level = els.risk.value; state.page = 1; load(); });
  els.category.addEventListener("change", () => { state.category = els.category.value; state.page = 1; load(); });
  els.from.addEventListener("change", () => { state.date_from = els.from.value; state.page = 1; load(); });
  els.to.addEventListener("change", () => { state.date_to = els.to.value; state.page = 1; load(); });
  document.getElementById("clearFilters").addEventListener("click", () => {
    state.search = ""; state.risk_level = "all"; state.category = "all";
    state.date_from = ""; state.date_to = ""; state.page = 1;
    els.search.value = ""; els.risk.value = "all"; els.category.value = "all";
    els.from.value = ""; els.to.value = "";
    load();
  });

  document.querySelectorAll("th[data-sort]").forEach(th => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      if (state.sort_by === field) {
        state.sort_dir = state.sort_dir === "asc" ? "desc" : "asc";
      } else {
        state.sort_by = field;
        state.sort_dir = "desc";
      }
      load();
    });
  });

  function updateSortArrows() {
    document.querySelectorAll("th[data-sort]").forEach(th => {
      const arrow = th.querySelector(".sort-arrow");
      if (th.dataset.sort === state.sort_by) {
        arrow.textContent = state.sort_dir === "asc" ? "▲" : "▼";
      } else {
        arrow.textContent = "";
      }
    });
  }

  async function load() {
    updateSortArrows();
    els.rows.innerHTML = `<tr><td colspan="6"><div class="skeleton" style="height:280px;"></div></td></tr>`;
    try {
      const data = await Api.listScans(state);
      renderRows(data.items);
      renderPagination(data);
    } catch (err) {
      els.rows.innerHTML = `<tr><td colspan="6"><div class="table-wrap-empty">Failed to load scan history.</div></td></tr>`;
    }
  }

  function renderRows(items) {
    if (!items.length) {
      els.rows.innerHTML = `<tr><td colspan="6">
        <div class="table-wrap-empty">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
          <div class="empty-title">No matching scans</div>
          <div>Try adjusting your filters or search terms.</div>
        </div>
      </td></tr>`;
      return;
    }
    els.rows.innerHTML = items.map(item => `
      <tr onclick="window.location.href='result.html?id=${item.id}'">
        <td><div class="filename-cell">${categoryIcon(item.category)}<span>${Fmt.escapeHtml(Fmt.truncate(item.original_filename, 40))}</span></div></td>
        <td><span class="tag">${item.category}</span></td>
        <td class="hash-cell mono">${item.sha256.slice(0, 16)}…</td>
        <td class="mono text-muted">${Fmt.bytes(item.file_size)}</td>
        <td><span class="${Fmt.riskBadgeClass(item.risk_level)}">${item.risk_level} · ${item.risk_score}</span></td>
        <td class="text-muted">${Fmt.dateTime(item.uploaded_at)}</td>
      </tr>
    `).join("");
  }

  function renderPagination(data) {
    const { page, total_pages } = data;
    if (total_pages <= 1) { els.pagination.innerHTML = ""; return; }
    let html = `<button class="page-btn" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>‹</button>`;
    const pages = new Set([1, total_pages, page, page - 1, page + 1].filter(p => p >= 1 && p <= total_pages));
    let prev = 0;
    [...pages].sort((a, b) => a - b).forEach(p => {
      if (prev && p - prev > 1) html += `<span class="page-btn" style="border:none;cursor:default;">…</span>`;
      html += `<button class="page-btn ${p === page ? "active" : ""}" data-page="${p}">${p}</button>`;
      prev = p;
    });
    html += `<button class="page-btn" data-page="${page + 1}" ${page >= total_pages ? "disabled" : ""}>›</button>`;
    els.pagination.innerHTML = html;
    els.pagination.querySelectorAll("button[data-page]").forEach(btn => {
      btn.addEventListener("click", () => {
        state.page = parseInt(btn.dataset.page, 10);
        load();
      });
    });
  }

  load();
})();
