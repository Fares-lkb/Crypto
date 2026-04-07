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
    const signatureB64 = await signFileWithPrivateKey(_pendingFile);
    const formData = new FormData();
    formData.append('signature_b64', signatureB64);
    formData.append('file', _pendingFile);

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
