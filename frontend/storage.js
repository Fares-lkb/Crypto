/* ══════════════════════════════════════
   storage.js  —  connected to Flask API
══════════════════════════════════════ */

requireAuth();

async function loadStorageStats() {
  const username = sessionStorage.getItem('vaultUser');
  try {
    const res  = await fetch(`${API}/api/storage/stats?username=${encodeURIComponent(username)}`);
    const data = await res.json();
    if (!data.success) return;

    const usedMB  = (data.used  / (1024 ** 2)).toFixed(1);
    const quotaMB = (data.quota / (1024 ** 2)).toFixed(1);
    const availMB = (data.available / (1024 ** 2)).toFixed(1);
    const pct     = Math.min(data.usage_percentage, 100);

    /* Update header text */
    const hdr = document.querySelector('.storage-header p');
    if (hdr) hdr.innerHTML = `You have used <strong>${usedMB} MB</strong> of your ${quotaMB} MB total capacity.`;

    /* Update donut label */
    const pctEl = document.querySelector('.donut-pct');
    if (pctEl) pctEl.textContent = pct.toFixed(1) + '%';

    /* Update legend */
    const vals = document.querySelectorAll('.legend-val');
    if (vals[0]) vals[0].textContent = usedMB  + ' MB';
    if (vals[1]) vals[1].textContent = availMB + ' MB';

    init_breakdown_card(data);

    /* Animate donut */
    const circle = document.getElementById('donutFill');
    if (circle) {
      const offset = 502 - (pct / 100) * 502;
      setTimeout(() => { circle.style.strokeDashoffset = offset; }, 150);
    }

    return data;

  } catch (_) {
    animateDonut();
  }
}

async function init_breakdown_card(data) {

  const categoryStats = data.category_stats || {};

  /* Update breakdown items */
    /* Documents stats */
    const docCount = document.getElementById('documents');
    if (docCount) docCount.textContent = categoryStats.documents.count + ' files';

    const docSize = document.getElementById('documents-size');
    if (docSize) docSize.textContent = (categoryStats.documents.size / (1024 ** 2)).toFixed(1) + ' MB';

    size_percent = (categoryStats.documents.size / data.quota) * 100;
    filled = document.getElementsByClassName("breakdown-bar-fill bar-blue");
    if (filled) filled[0].style.width = Math.min(size_percent, 100) + '%';

    /* Media stats */
    const mediaCount = document.getElementById('media');
    if (mediaCount) mediaCount.textContent = categoryStats.images.count + 
                                             categoryStats.videos.count + 
                                             categoryStats.audio.count + ' files';

    const total_size = categoryStats.images.size + categoryStats.videos.size + categoryStats.audio.size
    const mediaSize = document.getElementById('media-size');
    if (mediaSize) mediaSize.textContent = (total_size / (1024 ** 2)).toFixed(1) + ' MB';

    size_percent = (total_size / data.quota) * 100;
    filled = document.getElementsByClassName("breakdown-bar-fill bar-purple");
    if (filled) filled[0].style.width = Math.min(size_percent, 100) + '%';
    else console.log("failed");

    /* Archive stats */
    const backupCount = document.getElementById('backups');
    if (backupCount) backupCount.textContent = categoryStats.archives.count + ' files';
    else console.log("failed");

    const backupSize = document.getElementById('backups-size');
    if (backupSize) backupSize.textContent = (categoryStats.archives.size / (1024 ** 2)).toFixed(1) + ' MB';
    else console.log("failed");

    size_percent = (categoryStats.archives.size / data.quota) * 100;
    filled = document.getElementsByClassName("breakdown-bar-fill bar-green");
    if (filled) filled[0].style.width = Math.min(size_percent, 100) + '%';
    else console.log("failed");


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
