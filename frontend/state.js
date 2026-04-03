/* ══════════════════════════════════════
   state.js  —  shared data & utilities
   loaded by every app page (files, upload,
   storage, settings) via <script src="state.js">
══════════════════════════════════════ */

/* ── API base URL ── */
const API = 'http://127.0.0.1:5000';

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
  if (!sessionStorage.getItem('vaultUser')) {
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
  const username = sessionStorage.getItem('vaultUser');
  if (!username) return;

  try {
    const res  = await fetch(`${API}/api/storage/stats?username=${encodeURIComponent(username)}`);
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

  const username      = sessionStorage.getItem('vaultUser');
  const privateKeyB64 = sessionStorage.getItem('vaultPrivateKey');

  if (!privateKeyB64) {
    showToast('Private key missing — please re-register or re-login.', 'error');
    return;
  }

  showToast('Encrypting and uploading…', 'success');
  const formData = new FormData();
  formData.append('username',        username);
  formData.append('private_key_b64', privateKeyB64);
  formData.append('file',            _pendingFile);

  try {
    const res  = await fetch(`${API}/api/files/upload`, { method: 'POST', body: formData });
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
  } catch (_) {
    showToast('Upload failed — is the server running?', 'error');
  }
}
