/* ══════════════════════════════════════
   settings.js
══════════════════════════════════════ */

requireAuth();

/* ── Switch between settings categories ── */
function switchCat(catName) {
  /* Update sidebar items */
  document.querySelectorAll('.settings-cat-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`[data-cat="${catName}"]`).classList.add('active');

  /* Show/hide panels */
  document.getElementById('profilePanel').classList.toggle('hidden', catName !== 'profile');
  document.getElementById('billingPanel').classList.toggle('hidden', catName !== 'billing');
}

/* ── Save profile ── */
function saveProfile() {
  const name  = document.getElementById('profileName').value.trim();
  const email = document.getElementById('profileEmail').value.trim();

  if (!name)  { showToast('Full name cannot be empty.', 'error');  return; }
  if (!email) { showToast('Work email cannot be empty.', 'error'); return; }

  /* Update live display */
  document.getElementById('displayName').textContent  = name;
  document.getElementById('displayEmail').textContent = email;

  /* Persist to sessionStorage so topbar reflects changes */
  sessionStorage.setItem('vaultUser', name.split(' ')[0]);

  showToast('Profile updated successfully!', 'success');
}

/* ── Delete vault ── */
function deleteVault() {
  showToast('Account deletion requires email confirmation.', 'error');
}

/* ── Manage subscription ── */
function manageSub() {
  showToast('Redirecting to billing portal…', 'success');
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  initTopbar();
});
