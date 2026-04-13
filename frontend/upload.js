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

  showToast('Encrypting and uploading…', 'success');

  try {
    const encrypted = await buildEncryptedUploadPayload(_bigFile);
    const encryptedBlob = new Blob([encrypted.encryptedBlob], { type: 'application/octet-stream' });

    const formData = new FormData();
    formData.append('signature_b64', encrypted.signatureB64);
    formData.append('file_hash_b64', encrypted.fileHashB64);
    formData.append('enc_aes_key_b64', encrypted.encAesKeyB64);
    formData.append('original_filename', _bigFile.name);
    formData.append('file', encryptedBlob, `${_bigFile.name}.enc`);

    const res  = await fetch(`${API}/api/files/upload`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: formData,
    });
    const data = await res.json();
    if (data.success) {
      showToast(`${_bigFile.name} encrypted & uploaded!`, 'success');
      clearSelection();
      updateStorageBar();
      setTimeout(() => { window.location.href = 'files.html'; }, 1200);
    } else {
      showToast(data.message, 'error');
    }
  } catch (e) {
    showToast(e?.message || 'Upload failed.', 'error');
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
