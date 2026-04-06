/* ══════════════════════════════════════
   files.js  —  connected to Flask API
══════════════════════════════════════ */

requireAuth();

const PAGE_SIZE = 4;
let currentPage = 1;
let totalPages;
let _allFiles = [];

/* ── Load files from API ── */
async function loadFiles() {
  const username = sessionStorage.getItem('vaultUser');
  try {
    const res  = await fetch(`${API}/api/files?username=${encodeURIComponent(username)}`);
    const data = await res.json();
    if (data.success) {
      _allFiles = data.files;
      saveFiles(_allFiles);
    }
  } catch (_) {
    _allFiles = getFiles(); // fallback to sessionStorage if server is down
  }
  renderTable();
}

/* ── Render file table ── */
function renderTable() {
  const files = _allFiles;
  totalPages  = Math.ceil(files.length / PAGE_SIZE) || 1;

  const tbody = document.getElementById('fileTableBody');
  const start = (currentPage - 1) * PAGE_SIZE;
  const slice = files.slice(start, start + PAGE_SIZE);

  tbody.innerHTML = '';
  if (slice.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#94a3b8;padding:24px">No files uploaded yet.</td></tr>';
  }
  slice.forEach(f => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <div class="file-name-cell">
          <div class="file-icon"><i class="fas fa-file-shield"></i></div>
          <span class="file-name">${f.name}</span>
        </div>
      </td>
      <td class="file-size">${f.size}</td>
      <td class="file-date">${f.date}</td>
      <td>
        <div class="actions-cell">
          <button class="btn-action btn-download" onclick="handleDownload(&quot;${f.name}&quot;)">
            <i class="fas fa-download"></i> Download
          </button>
          <button class="btn-action btn-delete" onclick="handleDelete(&quot;${f.name}&quot;)">
            <i class="fas fa-trash"></i> Delete
          </button>
        </div>
      </td>`;
    tbody.appendChild(tr);
  });

  document.getElementById('pageNum').textContent = currentPage;
  document.getElementById('pageOf').textContent  = `of ${totalPages}`;
  document.getElementById('prevBtn').disabled    = currentPage === 1;
  document.getElementById('nextBtn').disabled    = currentPage === totalPages;
}

/* ── Pagination ── */
function changePage(dir) {
  totalPages  = Math.ceil(_allFiles.length / PAGE_SIZE) || 1;
  currentPage = Math.min(Math.max(1, currentPage + dir), totalPages);
  renderTable();
}

/* ── Download ── */
async function handleDownload(name) {
  const username      = sessionStorage.getItem('vaultUser');
  const privateKeyB64 = sessionStorage.getItem('vaultPrivateKey');
  if (!privateKeyB64) {
    showToast('Private key not found in session. Re-login required.', 'error');
    return;
  }
  try {
    const url = `${API}/api/files/download/${encodeURIComponent(name)}?username=${encodeURIComponent(username)}&private_key_b64=${encodeURIComponent(privateKeyB64)}`;
    const res = await fetch(url);
    if (!res.ok) { const d = await res.json(); showToast(d.message, 'error'); return; }
    const blob  = await res.blob();
    const a     = document.createElement('a');
    a.href      = URL.createObjectURL(blob);
    a.download  = name.replace('.enc', '');
    a.click();
    showToast(`${name} downloaded and decrypted.`, 'success');
  } catch (_) {
    showToast('Download failed — is the server running?', 'error');
  }
}

/* ── Delete ── */
async function handleDelete(name) {
  const username = sessionStorage.getItem('vaultUser');
  try {
    const res  = await fetch(`${API}/api/files/${encodeURIComponent(name)}?username=${encodeURIComponent(username)}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      showToast(`${name} deleted.`, 'error');
      await loadFiles();
      updateStorageBar();
    } else {
      showToast(data.message, 'error');
    }
  } catch (_) {
    showToast('Delete failed — is the server running?', 'error');
  }
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  initTopbar();
  loadFiles();

  document.getElementById('uploadModal').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });
});
