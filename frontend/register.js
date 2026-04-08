/* ══════════════════════════════════════
   register.js  —  connected to Flask API
══════════════════════════════════════ */

const API = 'http://127.0.0.1:5000';
let _generatedPrivateKey = '';

function togglePassword() {
  const input = document.getElementById('regPass');
  const icon  = document.getElementById('eyeIcon');
  if (input.type === 'password') {
    input.type = 'text';
    icon.classList.replace('fa-eye', 'fa-eye-slash');
  } else {
    input.type = 'password';
    icon.classList.replace('fa-eye-slash', 'fa-eye');
  }
}

async function registerVault() {
  const username = document.getElementById('regUsername').value.trim();
  const password = document.getElementById('regPass').value.trim();
  const err      = document.getElementById('fieldError');
  err.textContent = '';

  if (!username) { err.textContent = 'Please enter a username.'; return; }
  if (!password) { err.textContent = 'Please enter a password.'; return; }

  try {
    const res  = await fetch(`${API}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (!data.success) { err.textContent = data.message; return; }

    /* Store private key in sessionStorage for demo; show key modal */
    _generatedPrivateKey = data.private_key;
    const b64 = btoa(_generatedPrivateKey);
    sessionStorage.setItem('vaultPrivateKey', b64);

    document.getElementById('keyDisplay').value = _generatedPrivateKey;
    const modal = document.getElementById('keyModal');
    modal.style.display = 'flex';

  } catch (e) {
    err.textContent = 'Cannot reach server. Is server.py running?';
  }
}

function downloadKey() {
  const blob = new Blob([_generatedPrivateKey], { type: 'text/plain' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = 'vault_private_key.pem';
  a.click();
}

function proceedToLogin() {
  window.location.href = 'login.html';
}

/* Toast */
let _toastTimer;
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className   = `toast ${type} show`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
}
