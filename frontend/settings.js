/* ══════════════════════════════════════
   settings.js
══════════════════════════════════════ */

requireAuth();

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  initTopbar();

  const versionEl = document.getElementById('aboutVersion');
  if (versionEl) {
    const year = new Date().getFullYear();
    versionEl.textContent = `Digital Vault v1.0 (${year})`;
  }
});
