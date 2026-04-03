/* ══════════════════════════════════════
   upload.js
══════════════════════════════════════ */

requireAuth();

let _bigFile = null;

/* ── Drag & Drop on big zone ── */
function onBigDragOver(e) {
  e.preventDefault();
  document.getElementById('bigDropZone').classList.add('dragover');
}

function onBigDragLeave() {
  document.getElementById('bigDropZone').classList.remove('dragover');
}

function onBigDrop(e) {
  e.preventDefault();
  document.getElementById('bigDropZone').classList.remove('dragover');
  if (e.dataTransfer.files[0]) _selectBigFile(e.dataTransfer.files[0]);
}

function onBigFileSelected(input) {
  if (input.files[0]) _selectBigFile(input.files[0]);
}

function _selectBigFile(file) {
  _bigFile = file;
  document.getElementById('bigDropLabel').textContent = `Selected: ${file.name}`;
}

/* ── Trigger upload — sends file to real API ── */
async function triggerUpload() {
  if (!_bigFile) {
    document.getElementById('bigFileInput').click();
    return;
  }

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
  formData.append('file',            _bigFile);

  try {
    const res  = await fetch(`${API}/api/files/upload`, { method: 'POST', body: formData });
    const data = await res.json();
    if (data.success) {
      showToast(`${_bigFile.name} encrypted & uploaded!`, 'success');
      clearSelection();
      updateStorageBar();
      setTimeout(() => { window.location.href = 'files.html'; }, 1200);
    } else {
      showToast(data.message, 'error');
    }
  } catch (_) {
    showToast('Upload failed — is the server running?', 'error');
  }
}

/* ── Clear ── */
function clearSelection() {
  _bigFile = null;
  document.getElementById('bigDropLabel').textContent = 'Drag & drop your file here';
  document.getElementById('bigFileInput').value = '';
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  initTopbar();
});
