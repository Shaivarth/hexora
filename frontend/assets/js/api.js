/* Hexora API client thin wrapper around fetch for every backend route. */
const Api = (() => {
  const BASE = "/api";

  async function handle(res) {
    if (!res.ok) {
      let detail = `Request failed (${res.status})`;
      try {
        const body = await res.json();
        if (body && body.detail) detail = body.detail;
      } catch (_) {}
      const err = new Error(detail);
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  return {
    async uploadScan(file, onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        const form = new FormData();
        form.append("file", file);

        xhr.upload.addEventListener("progress", (e) => {
          if (e.lengthComputable && onProgress) {
            onProgress(Math.round((e.loaded / e.total) * 100));
          }
        });

        xhr.addEventListener("load", () => {
          let body = {};
          try { body = JSON.parse(xhr.responseText); } catch (_) {}
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(body);
          } else {
            reject(new Error(body.detail || `Upload failed (${xhr.status})`));
          }
        });

        xhr.addEventListener("error", () => reject(new Error("Network error during upload.")));
        xhr.open("POST", `${BASE}/scans`);
        xhr.send(form);
      });
    },

    async getScan(id) {
      return handle(await fetch(`${BASE}/scans/${id}`));
    },

    async listScans(params = {}) {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "") qs.set(k, v);
      });
      return handle(await fetch(`${BASE}/scans?${qs.toString()}`));
    },

    async getDashboardStats() {
      return handle(await fetch(`${BASE}/dashboard/stats`));
    },

    reportUrl(id) {
      return `${BASE}/scans/${id}/report`;
    },
  };
})();
