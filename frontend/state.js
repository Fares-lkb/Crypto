/* ══════════════════════════════════════
   state.js  —  shared data & utilities
   loaded by every app page (files, upload,
   storage, settings) via <script src="state.js">
══════════════════════════════════════ */

/* ── API base URL ── */
const API = 'http://127.0.0.1:5000';

function getAuthHeaders() {
  const token = sessionStorage.getItem('vaultToken');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function getPrivateKeyPem() {
  const privateKeyB64 = sessionStorage.getItem('vaultPrivateKey');
  return privateKeyB64 ? atob(privateKeyB64) : null;
}

async function getPublicKeyPem() {
  const cached = sessionStorage.getItem('vaultPublicKey');
  if (cached) return cached;

  const res = await fetch(`${API}/api/users/me/public-key`, { headers: getAuthHeaders() });
  const data = await res.json();
  if (!data.success || !data.public_key) {
    throw new Error(data.message || 'Unable to load public key.');
  }

  sessionStorage.setItem('vaultPublicKey', data.public_key);
  return data.public_key;
}

async function signFileWithPrivateKey(file) {
  if (!window.CryptoModule) {
    throw new Error('Crypto library missing. Refresh page and retry.');
  }

  const pem = getPrivateKeyPem();
  if (!pem) {
    throw new Error('Private key missing in session.');
  }

  return await window.CryptoModule.signFileFromFile(file, pem);
}

async function buildEncryptedUploadPayload(file) {
  if (!window.CryptoModule) {
    throw new Error('Crypto library missing. Refresh page and retry.');
  }

  const privateKeyPem = getPrivateKeyPem();
  if (!privateKeyPem) {
    throw new Error('Private key missing in session.');
  }

  const publicKeyPem = await getPublicKeyPem();
  return await window.CryptoModule.encryptFileForUpload(file, privateKeyPem, publicKeyPem);
}

/* ── File list now comes from the real API (see files.js) ── */
function getFiles() {
  const raw = sessionStorage.getItem('vaultFiles');
  return raw ? JSON.parse(raw) : [];
}

function saveFiles(files) {
  sessionStorage.setItem('vaultFiles', JSON.stringify(files));
}

/* ── Auth guard: redirect to login if not authenticated ── */
function requireAuth() {
  if (!sessionStorage.getItem('vaultUser') || !sessionStorage.getItem('vaultToken')) {
    window.location.href = 'login.html';
  }
}

/* ── Populate the topbar storage info ── */
function initTopbar() {
  const user = sessionStorage.getItem('vaultUser') || 'User';
  const plan = sessionStorage.getItem('vaultPlan') || 'Secure Member';

  const nameEl = document.getElementById('topbarUserName');
  const planEl = document.getElementById('topbarUserPlan');
  if (nameEl) nameEl.textContent = 'Welcome, ' + user;
  if (planEl) planEl.textContent = plan;

  updateStorageBar();
}

/* ── Fetch real storage stats from API ── */
async function updateStorageBar() {
  if (!sessionStorage.getItem('vaultToken')) return;

  try {
    const res  = await fetch(`${API}/api/storage/stats`, { headers: getAuthHeaders() });
    const data = await res.json();
    if (!data.success) return;

    const usedMB  = (data.used  / (1024 * 1024)).toFixed(1);
    const quotaMB = (data.quota / (1024 * 1024)).toFixed(1);
    const pct     = Math.min(data.usage_percentage, 100);

    const valEl  = document.getElementById('storageVal');
    const fillEl = document.getElementById('progressFill');
    if (valEl)  valEl.textContent  = `${usedMB} MB / ${quotaMB} MB`;
    if (fillEl) fillEl.style.width = pct + '%';
  } catch (_) { /* server might not be running */ }
}

/* ── Logout ── */
function logout() {
  sessionStorage.removeItem('vaultUser');
  sessionStorage.removeItem('vaultPrivateKey');
  sessionStorage.removeItem('vaultPublicKey');
  sessionStorage.removeItem('vaultToken');
  sessionStorage.removeItem('vaultPlan');
  window.location.href = 'login.html';
}

/* ── Toast ── */
let _toastTimer;
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className   = `toast ${type} show`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
}

/* ── Upload modal (shared across files.html & upload.html) ── */
let _pendingFile = null;

function openModal() {
  const overlay = document.getElementById('uploadModal');
  if (!overlay) return;
  overlay.classList.add('open');
  _pendingFile = null;
  const lbl = document.getElementById('dropLabel');
  const inp = document.getElementById('fileInput');
  if (lbl) lbl.textContent = 'Drag & drop your file here';
  if (inp) inp.value = '';
}

function closeModal() {
  const overlay = document.getElementById('uploadModal');
  if (overlay) overlay.classList.remove('open');
}

function onDragOver(e)  { e.preventDefault(); document.getElementById('dropZone')?.classList.add('dragover'); }
function onDragLeave()  { document.getElementById('dropZone')?.classList.remove('dragover'); }

function onDrop(e) {
  e.preventDefault();
  document.getElementById('dropZone')?.classList.remove('dragover');
  if (e.dataTransfer.files[0]) _selectModalFile(e.dataTransfer.files[0]);
}

function onFileSelected(input) {
  if (input.files[0]) _selectModalFile(input.files[0]);
}

function _selectModalFile(file) {
  _pendingFile = file;
  const lbl = document.getElementById('dropLabel');
  if (lbl) lbl.textContent = `Selected: ${file.name}`;
}

async function confirmUpload() {
  if (!_pendingFile) { showToast('Please select a file first.', 'error'); return; }

  showToast('Encrypting and uploading…', 'success');

  try {
    const encrypted = await buildEncryptedUploadPayload(_pendingFile);
    const encryptedBlob = new Blob([encrypted.encryptedBlob], { type: 'application/octet-stream' });

    const formData = new FormData();
    formData.append('signature_b64', encrypted.signatureB64);
    formData.append('file_hash_b64', encrypted.fileHashB64);
    formData.append('enc_aes_key_b64', encrypted.encAesKeyB64);
    formData.append('original_filename', _pendingFile.name);
    formData.append('file', encryptedBlob, `${_pendingFile.name}.enc`);

    const res  = await fetch(`${API}/api/files/upload`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: formData,
    });
    const data = await res.json();
    closeModal();
    if (data.success) {
      showToast(`${_pendingFile.name} uploaded successfully!`, 'success');
      _pendingFile = null;
      await updateStorageBar();
      if (typeof loadFiles === 'function') loadFiles();
    } else {
      showToast(data.message, 'error');
    }
  } catch (e) {
    showToast(e?.message || 'Upload failed.', 'error');
  }
}
