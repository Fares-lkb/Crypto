/* ══════════════════════════════════════
   login.js  —  connected to Flask API
══════════════════════════════════════ */

const API = 'http://127.0.0.1:5000';

function _pemToBase64(pemText) {
  return btoa(pemText);
}

/* Redirect to files if already logged in */
if (sessionStorage.getItem('vaultUser')) {
  window.location.href = 'files.html';
}

/* ── Toggle password visibility ── */
function togglePassword() {
  const input = document.getElementById('vaultPass');
  const icon  = document.getElementById('eyeIcon');
  if (input.type === 'password') {
    input.type = 'text';
    icon.classList.replace('fa-eye', 'fa-eye-slash');
  } else {
    input.type = 'password';
    icon.classList.replace('fa-eye-slash', 'fa-eye');
  }
}

async function _readPrivateKeyFromFile() {
  const fileInput = document.getElementById('privateKeyFile');
  const file = fileInput.files && fileInput.files[0];
  if (!file) return null;
  return await file.text();
}

/* ── Sign challenge using RSA private key in browser ── */
async function signChallenge(nonce, timestamp, privateKeyPem) {
  if (typeof KJUR === 'undefined' || typeof KEYUTIL === 'undefined') {
    throw new Error('Crypto library not loaded. Refresh page and retry.');
  }

  const challenge = nonce + timestamp;
  const prvKeyObj = KEYUTIL.getKey(privateKeyPem);
  const sig = new KJUR.crypto.Signature({ alg: 'SHA256withRSA' });
  sig.init(prvKeyObj);
  sig.updateString(challenge);
  const sigHex = sig.sign();
  return hextob64(sigHex);
}

/* ── Enter vault (2-step: challenge → verify) ── */
async function enterVault() {
  const username = document.getElementById('vaultEmail').value.trim();
  const pass     = document.getElementById('vaultPass').value.trim();
  const err      = document.getElementById('fieldError');

  err.textContent = '';

  if (!username) { err.textContent = 'Please enter your username.'; return; }
  if (!pass)     { err.textContent = 'Please enter your password.'; return; }

  const privateKeyPem = await _readPrivateKeyFromFile();
  if (!privateKeyPem) {
    err.textContent = 'Please choose your private key (.pem) file.';
    return;
  }

  try {
    /* Step 1 — get challenge */
    const chalRes = await fetch(`${API}/api/login/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    const chalData = await chalRes.json();
    if (!chalData.success) { err.textContent = chalData.message; return; }

    const { nonce, timestamp } = chalData;
    const sig_b64 = await signChallenge(nonce, timestamp, privateKeyPem);

    /* Step 2 — verify */
    const verRes = await fetch(`${API}/api/login/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: pass, nonce, timestamp, signature_b64: sig_b64 })
    });
    const verData = await verRes.json();

    if (!verData.success) { err.textContent = verData.message; return; }

    sessionStorage.setItem('vaultUser', verData.username);
    sessionStorage.setItem('vaultPlan', 'Secure Member');
    sessionStorage.setItem('vaultPrivateKey', _pemToBase64(privateKeyPem));
    window.location.href = 'files.html';

  } catch (e) {
    err.textContent = 'Cannot reach server. Is server.py running?';
  }
}

/* ── Toast ── */
let _toastTimer;
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className   = `toast ${type} show`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
}

/* ── Allow Enter key to submit ── */
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('vaultPass').addEventListener('keydown', e => {
    if (e.key === 'Enter') enterVault();
  });
  document.getElementById('vaultEmail').addEventListener('keydown', e => {
    if (e.key === 'Enter') enterVault();
  });
});
