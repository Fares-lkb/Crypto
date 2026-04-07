/* ══════════════════════════════════════
   storage.js  —  connected to Flask API
══════════════════════════════════════ */

requireAuth();

async function loadStorageStats() {
  try {
    const res  = await fetch(`${API}/api/storage/stats`, { headers: getAuthHeaders() });
    const data = await res.json();
    if (!data.success) return;

    const usedGB  = (data.used  / (1024 ** 3)).toFixed(1);
    const quotaGB = (data.quota / (1024 ** 3)).toFixed(1);
    const availGB = (data.available / (1024 ** 3)).toFixed(1);
    const pct     = Math.min(data.usage_percentage, 100);

    /* Update header text */
    const hdr = document.querySelector('.storage-header p');
    if (hdr) hdr.innerHTML = `You have used <strong>${usedGB} GB</strong> of your ${quotaGB} GB total capacity.`;

    /* Update donut label */
    const pctEl = document.querySelector('.donut-pct');
    if (pctEl) pctEl.textContent = pct.toFixed(1) + '%';

    /* Update legend */
    const vals = document.querySelectorAll('.legend-val');
    if (vals[0]) vals[0].textContent = usedGB  + ' GB';
    if (vals[1]) vals[1].textContent = availGB + ' GB';

    /* Animate donut */
    const circle = document.getElementById('donutFill');
    if (circle) {
      const offset = 502 - (pct / 100) * 502;
      setTimeout(() => { circle.style.strokeDashoffset = offset; }, 150);
    }
  } catch (_) {
    animateDonut();
  }
}

/* ── Fallback donut animation ── */
function animateDonut() {
  const circle = document.getElementById('donutFill');
  if (!circle) return;
  setTimeout(() => { circle.style.strokeDashoffset = 502 - (50.2 / 100) * 502; }, 150);
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  initTopbar();
  loadStorageStats();
});
