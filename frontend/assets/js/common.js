/* Hexora shared UI */

const Fmt = {
  bytes(n) {
    if (n === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(n) / Math.log(1024));
    return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  },
  dateTime(iso) {
  if (!iso) return "";

  const normalized =
    iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";

  const d = new Date(normalized);
  if (isNaN(d)) return iso;

  return d.toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
},

relativeTime(iso) {
  if (!iso) return "";

  const normalized =
    iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";

  const d = new Date(normalized);
  if (isNaN(d)) return "";

  const diffSec = Math.round((Date.now() - d.getTime()) / 1000);

  if (diffSec < 60) return "just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
},
  truncate(s, n) {
    if (!s) return "";
    return s.length > n ? s.slice(0, n - 1) + "\u2026" : s;
  },
  riskBadgeClass(level) {
    return `badge badge-${(level || "low").toLowerCase()}`;
  },
  escapeHtml(s) {
    const div = document.createElement("div");
    div.textContent = s == null ? "" : String(s);
    return div.innerHTML;
  },
};

const Toast = (() => {
  let stack;
  function ensureStack() {
    if (!stack) {
      stack = document.createElement("div");
      stack.className = "toast-stack";
      document.body.appendChild(stack);
    }
    return stack;
  }

  const ICONS = {
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>',
    error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>',
  };

  function show(message, type = "info", timeout = 4200) {
    const el = document.createElement("div");
    el.className = `toast toast-${type}`;
    el.innerHTML = `${ICONS[type] || ICONS.info}<span>${Fmt.escapeHtml(message)}</span>`;
    ensureStack().appendChild(el);
    setTimeout(() => {
      el.style.transition = "opacity 0.25s, transform 0.25s";
      el.style.opacity = "0";
      el.style.transform = "translateY(8px)";
      setTimeout(() => el.remove(), 260);
    }, timeout);
  }

  return {
    success: (m) => show(m, "success"),
    error: (m) => show(m, "error"),
    info: (m) => show(m, "info"),
  };
})();

async function copyToClipboard(text, label = "Value") {
  try {
    await navigator.clipboard.writeText(text);
    Toast.success(`${label} copied to clipboard`);
  } catch (_) {
    Toast.error("Could not copy to clipboard");
  }
}

const ThemeCtl = (() => {
  function init() {
    const btn = document.getElementById("themeToggleBtn");

    if (btn) {
      btn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24"
             fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round">
          <path d="M7 17L17 7"/>
          <path d="M8 7h9v9"/>
        </svg>
      `;

      btn.addEventListener("click", () => {
        window.open("https://shaivarth.com", "_blank");
      });
    }
  }

  return { init };
})();

/* ---- Global keyboard shortcuts ---- */
function initShortcuts() {
  document.addEventListener("keydown", (e) => {
    const tag = (document.activeElement && document.activeElement.tagName) || "";
    const typing = tag === "INPUT" || tag === "TEXTAREA";

    if (e.key === "/" && !typing) {
      const search = document.getElementById("globalSearchInput");
      if (search) { e.preventDefault(); search.focus(); }
    }
    if ((e.key === "u" || e.key === "U") && !typing) {
      window.location.href = "index.html";
    }
    if ((e.key === "h" || e.key === "H") && !typing) {
      window.location.href = "history.html";
    }
    if ((e.key === "d" || e.key === "D") && !typing) {
      window.location.href = "dashboard.html";
    }
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-overlay").forEach((m) => m.remove());
    }
  });
}

function initGlobalSearch() {
  const input = document.getElementById("globalSearchInput");
  const btn = document.getElementById("globalSearchBtn");

  if (!input) return;

  function search() {
    const value = input.value.trim();
    if (value) {
      window.location.href =
        `history.html?search=${encodeURIComponent(value)}`;
    }
  }

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      search();
    }
  });

  if (btn) {
    btn.addEventListener("click", search);
  }
}

function categoryIcon(category) {
  const icons = {
    executable: '<svg class="cat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 8h10M7 12h6"/></svg>',
    document: '<svg class="cat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>',
    archive: '<svg class="cat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v11a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8M10 13h4"/></svg>',
    image: '<svg class="cat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>',
    script: '<svg class="cat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/></svg>',
    other: '<svg class="cat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>',
  };
  return icons[category] || icons.other;
}

/* ---- App shell (sidebar + topbar) shared markup, mounted by every page ---- */
const Shell = (() => {
  const NAV = [
    { key: "scan", href: "index.html", label: "Scan File",
      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12m0 0-4-4m4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>' },
    { key: "dashboard", href: "dashboard.html", label: "Dashboard",
      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>' },
    { key: "history", href: "history.html", label: "Scan History",
      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>' },
  ];

function sidebar(active) {
  const links = NAV.map(n => `
    <a href="${n.href}" class="nav-link ${n.key === active ? "active" : ""}">
      ${n.icon}<span>${n.label}</span>
    </a>`).join("");

  return `
    <aside class="sidebar">
      <div class="brand">
        <img
          src="assets/img/logo.png"
          alt="Hexora Logo"
          class="brand-mark"
          style="padding-left:30px; width:140px; height:auto;"
        />
      </div>

      <div class="nav-section-label">Workspace</div>

      <nav class="nav-list" style="display:flex;flex-direction:column;gap:2px;">
        ${links}
      </nav>

      <div class="nav-section-label" style="margin-top:24px;">Contact</div>

      <nav class="nav-list" style="display:flex;flex-direction:column;gap:2px;">

        <a href="https://github.com/Shaivarth" target="_blank" class="nav-link">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 .5A12 12 0 0 0 8.2 23.9c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.4-4-1.4-.6-1.3-1.3-1.7-1.3-1.7-1.1-.8.1-.8.1-.8 1.2.1 1.8 1.2 1.8 1.2 1.1 1.8 2.9 1.3 3.6 1 .1-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6A4.7 4.7 0 0 1 6.1 8c-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.2 1.2a11 11 0 0 1 5.8 0c2.2-1.5 3.2-1.2 3.2-1.2.6 1.6.2 2.8.1 3.1a4.7 4.7 0 0 1 1.3 3.3c0 4.7-2.8 5.7-5.5 6 .5.4.8 1.1.8 2.3v3.4c0 .3.2.7.8.6A12 12 0 0 0 12 .5z"/>
          </svg>
          <span>GitHub</span>
        </a>

        <a href="https://www.linkedin.com/in/shaivarth/" target="_blank" rel="noopener noreferrer" class="nav-link">
        <img src="https://www.svgrepo.com/show/157006/linkedin.svg" alt="LinkedIn" width="18" height="18">
          <span>LinkedIn</span>
        </a>
      </nav>
    </aside>
  `;
}

  function topbar(title, subtitle) {
    return `
      <div class="topbar">
        <div class="page-heading">
          <h1>${title}</h1>
          ${subtitle ? `<p>${subtitle}</p>` : ""}
        </div>
        <div class="topbar-actions">
          <div class="global-search">
            <div class="global-search">
              <div class="input-icon-wrap">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="11" cy="11" r="7"/>
                  <path d="m21 21-4.3-4.3"/>
                </svg>

                <input
                  id="globalSearchInput"
                  placeholder="Search hash or filename"
                />
              </div>

              <button id="globalSearchBtn" class="icon-btn" aria-label="Search">
                <svg width="18" height="18" viewBox="0 0 24 24"
                    fill="none" stroke="currentColor" stroke-width="2"
                    stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="11" cy="11" r="7"/>
                  <path d="m21 21-4.3-4.3"/>
                </svg>
              </button>
            </div>
          </div>
          <button class="icon-btn" id="themeToggleBtn" aria-label="Toggle theme"></button>
        </div>
      </div>`;
  }

  function mount(active, title, subtitle) {
    const root = document.getElementById("shellRoot");
    if (!root) return;
    root.innerHTML = sidebar(active);
    const main = document.createElement("div");
    main.className = "main-col";
    main.innerHTML = `${topbar(title, subtitle)}<div class="content" id="pageContent"></div>`;
    root.parentElement.appendChild(main);

    ThemeCtl.init();
    initShortcuts();
    initGlobalSearch();
  }

  return { mount };
})();
