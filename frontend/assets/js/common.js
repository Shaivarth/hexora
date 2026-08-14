/* Hexora - Theme Switcher & System Utilities */

const Fmt = {
  bytes(n) {
    if (n === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(n) / Math.log(1024));
    return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  },
  dateTime(iso) {
    if (!iso) return "";
    const normalized = iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";
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
    const normalized = iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";
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
  hexTable(hexString) {
    if (!hexString) return '<div class="text-muted p-3">No raw byte sample available.</div>';
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
      bytes.push(hexString.substr(i, 2));
    }
    
    let rowsHtml = '';
    const bytesPerLine = 16;
    
    for (let i = 0; i < bytes.length; i += bytesPerLine) {
      const chunk = bytes.slice(i, i + bytesPerLine);
      const offsetHex = i.toString(16).padStart(8, '0').toUpperCase();
      const hexBytesStr = chunk.map(b => b.toUpperCase()).join(' ');
      
      const asciiStr = chunk.map(b => {
        const charCode = parseInt(b, 16);
        return (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.';
      }).join('');

      rowsHtml += `
        <tr>
          <td class="hex-offset">0x${offsetHex}</td>
          <td class="hex-bytes">${hexBytesStr.padEnd(bytesPerLine * 3 - 1, ' ')}</td>
          <td class="hex-ascii">${Fmt.escapeHtml(asciiStr)}</td>
        </tr>`;
    }

    return `
      <div class="hex-container">
        <table class="hex-table">
          <thead>
            <tr style="color:var(--text-faint);font-size:11px;text-align:left;">
              <th style="padding-bottom:8px;">OFFSET</th>
              <th style="padding-bottom:8px;">HEX BYTES</th>
              <th style="padding-bottom:8px;padding-left:14px;">ASCII</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>`;
  },
  async calculateClientHash(file) {
    try {
      const buffer = await file.slice(0, 1024 * 1024 * 2).arrayBuffer();
      const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (_) {
      return null;
    }
  }
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
      el.style.transform = "translateY(10px)";
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
  const MOON_ICON = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>`;
  const SUN_ICON = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>`;

  function applyTheme(theme) {
    document.body.setAttribute("data-theme", theme);
    localStorage.setItem("hexora_theme", theme);
    const btn = document.getElementById("themeToggleBtn");
    if (btn) {
      btn.innerHTML = theme === "dark" ? SUN_ICON : MOON_ICON;
      btn.title = `Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`;
    }
    window.dispatchEvent(new CustomEvent("themeChanged", { detail: { theme } }));
  }

  function init() {
    const savedTheme = localStorage.getItem("hexora_theme") || "dark";
    applyTheme(savedTheme);

    const btn = document.getElementById("themeToggleBtn");
    if (btn) {
      btn.addEventListener("click", () => {
        const current = document.body.getAttribute("data-theme") || "dark";
        applyTheme(current === "dark" ? "light" : "dark");
      });
    }
  }

  return { init, applyTheme };
})();

function showShortcutsModal() {
  if (document.getElementById("shortcutsModal")) return;

  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "shortcutsModal";
  overlay.innerHTML = `
    <div class="modal-box">
      <div class="flex-between mb-16">
        <h2 style="font-family:var(--font-display);margin:0;font-size:18px;">Keyboard Shortcuts</h2>
        <button class="icon-btn" onclick="document.getElementById('shortcutsModal').remove()">✕</button>
      </div>
      <div style="display:flex;flex-direction:column;gap:12px;">
        <div class="flex-between"><span>Focus Global Search</span><span class="kbd">/</span></div>
        <div class="flex-between"><span>File Ingestion Dock</span><span class="kbd">U</span></div>
        <div class="flex-between"><span>Fleet Dashboard</span><span class="kbd">D</span></div>
        <div class="flex-between"><span>Scan History Log</span><span class="kbd">H</span></div>
        <div class="flex-between"><span>Keyboard Help</span><span class="kbd">?</span></div>
        <div class="flex-between"><span>Close Modals</span><span class="kbd">ESC</span></div>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.remove();
  });
}

function initShortcuts() {
  document.addEventListener("keydown", (e) => {
    const tag = (document.activeElement && document.activeElement.tagName) || "";
    const typing = tag === "INPUT" || tag === "TEXTAREA";

    if (e.key === "/" && !typing) {
      const search = document.getElementById("globalSearchInput");
      if (search) { e.preventDefault(); search.focus(); }
    }
    if ((e.key === "u" || e.key === "U") && !typing) { window.location.href = "index.html"; }
    if ((e.key === "h" || e.key === "H") && !typing) { window.location.href = "history.html"; }
    if ((e.key === "d" || e.key === "D") && !typing) { window.location.href = "dashboard.html"; }
    if (e.key === "?" && !typing) { showShortcutsModal(); }
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
      window.location.href = `history.html?search=${encodeURIComponent(value)}`;
    }
  }

  input.addEventListener("keydown", (e) => { if (e.key === "Enter") search(); });
  if (btn) btn.addEventListener("click", search);
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

const Shell = (() => {
  const NAV = [
    { key: "scan", href: "index.html", label: "Inspect File",
      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12m0 0-4-4m4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>' },
    { key: "dashboard", href: "dashboard.html", label: "Fleet Dashboard",
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
          <img src="assets/img/logo.png" alt="Hexora Logo" class="brand-mark" style="width:130px;height:auto;" />
        </div>

        <div class="nav-section-label">Workspace</div>
        <nav class="nav-list">${links}</nav>

        <div class="nav-section-label" style="margin-top:24px;">Links</div>
        <nav class="nav-list">
          <a href="https://github.com/Shaivarth" target="_blank" rel="noopener noreferrer" class="nav-link">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 .5A12 12 0 0 0 8.2 23.9c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.4-4-1.4-.6-1.3-1.3-1.7-1.3-1.7-1.1-.8.1-.8.1-.8 1.2.1 1.8 1.2 1.8 1.2 1.1 1.8 2.9 1.3 3.6 1 .1-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6A4.7 4.7 0 0 1 6.1 8c-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.2 1.2a11 11 0 0 1 5.8 0c2.2-1.5 3.2-1.2 3.2-1.2.6 1.6.2 2.8.1 3.1a4.7 4.7 0 0 1 1.3 3.3c0 4.7-2.8 5.7-5.5 6 .5.4.8 1.1.8 2.3v3.4c0 .3.2.7.8.6A12 12 0 0 0 12 .5z"/>
            </svg>
            <span>GitHub</span>
          </a>
          <a href="https://www.linkedin.com/in/shaivarth/" target="_blank" rel="noopener noreferrer" class="nav-link">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
              <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.25V10.9H6.46M7.86 6.74a1.64 1.64 0 1 0 0 3.28 1.64 1.64 0 0 0 0-3.28z"/>
            </svg>
            <span>LinkedIn</span>
          </a>
        </nav>

        <div class="sidebar-footer">
          <div class="creator-badge">
            <div class="creator-label">Engine Architect</div>
            <div class="creator-name">Sarthak M.</div>
          </div>
        </div>
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
            <div class="input-icon-wrap">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>
              </svg>
              <input id="globalSearchInput" placeholder="Search hash or filename (/)" />
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
