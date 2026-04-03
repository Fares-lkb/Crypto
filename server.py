"""
server.py — Flask REST API
Connects the frontend to UserManager, StorageManager, NonceManager, crypto_module.
"""

import os
import base64
import functools
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import io

from user_manager import UserManager, StorageManager, NonceManager
from user_manager.crypto_module import (
    generate_rsa_keypair,
    sign_file,
    verify_signature,
    compute_file_hash,
    verify_file_integrity,
    encrypt_file_aes,
    decrypt_file_aes,
    encrypt_aes_key_rsa,
    decrypt_aes_key_rsa,
    get_random_bytes,
)
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

app = Flask(__name__)
CORS(app)  # allow browser requests from file:// or different port

# Demo fallback: allow login when frontend cannot generate RSA signatures yet.
# Set to "0" in environment to enforce strict signature-only authentication.
ALLOW_DEMO_SIGNATURE_BYPASS = os.getenv('ALLOW_DEMO_SIGNATURE_BYPASS', '0') == '1'

user_manager    = UserManager()
storage_manager = StorageManager()
nonce_manager   = NonceManager()

CLOUD_DIR = os.path.join(os.path.dirname(__file__), 'cloud')
os.makedirs(CLOUD_DIR, exist_ok=True)

# ──────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────

def _user_dir(username):
    path = os.path.join(CLOUD_DIR, username)
    os.makedirs(path, exist_ok=True)
    return path

def _b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def _b64dec(s: str) -> bytes:
    return base64.b64decode(s)

def _require_json(*fields):
    """Decorator: parse JSON body and ensure required fields are present."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            data = request.get_json(silent=True) or {}
            missing = [f for f in fields if not data.get(f)]
            if missing:
                return jsonify({'success': False, 'message': f'Missing fields: {", ".join(missing)}'}), 400
            return fn(data, *args, **kwargs)
        return wrapper
    return decorator

# ──────────────────────────────────────────
# 1. REGISTER
# POST /api/register
# Body: { username, password }
# Returns: { success, message, public_key, private_key }
# NOTE: private_key is returned ONCE and never stored server-side.
# ──────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
@_require_json('username', 'password')
def register(data):
    username = data['username'].strip()
    password = data['password']

    private_pem, public_pem = generate_rsa_keypair()
    public_key_str  = public_pem.decode('utf-8')
    private_key_str = private_pem.decode('utf-8')

    result = user_manager.register_user(
        username=username,
        password=password,
        public_key=public_key_str
    )

    if not result['success']:
        return jsonify(result), 400

    return jsonify({
        'success': True,
        'message': result['message'],
        'public_key': public_key_str,
        'private_key': private_key_str,   # client must save this locally
    }), 201


# ──────────────────────────────────────────
# 2. LOGIN — step 1: get challenge
# POST /api/login/challenge
# Body: { username }
# Returns: { success, nonce, timestamp }
# ──────────────────────────────────────────
@app.route('/api/login/challenge', methods=['POST'])
@_require_json('username')
def login_challenge(data):
    username = data['username'].strip()

    if user_manager.is_account_locked(username):
        return jsonify({'success': False, 'message': 'Account locked after too many failed attempts'}), 403

    result = nonce_manager.generate_nonce(username)
    if not result['success']:
        return jsonify(result), 400

    return jsonify({
        'success': True,
        'nonce': result['nonce'],
        'timestamp': result['timestamp'],
    })


# ──────────────────────────────────────────
# 3. LOGIN — step 2: verify signature + password
# POST /api/login/verify
# Body: { username, password, nonce, signature_b64 }
# Returns: { success, message, username }
# ──────────────────────────────────────────
@app.route('/api/login/verify', methods=['POST'])
@_require_json('username', 'password', 'nonce', 'signature_b64')
def login_verify(data):
    username     = data['username'].strip()
    password     = data['password']
    nonce        = data['nonce']
    sig_b64      = data['signature_b64']

    # 1. Password check
    pw_result = user_manager.verify_password(username, password)
    if not pw_result['valid']:
        user_manager.record_failed_login(username)
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # 2. Nonce validation (replay protection)
    nonce_result = nonce_manager.validate_nonce(username, nonce)
    if not nonce_result['valid']:
        user_manager.record_failed_login(username)
        return jsonify({'success': False, 'message': nonce_result['message']}), 401

    # 3. RSA signature verification
    public_key = user_manager.get_public_key(username)
    if not public_key:
        return jsonify({'success': False, 'message': 'Public key not found'}), 400

    try:
        sig_bytes  = _b64dec(sig_b64)
        challenge  = (nonce + data.get('timestamp', '')).encode('utf-8')
        valid_sig  = verify_signature(challenge, sig_bytes, public_key.encode('utf-8'))
    except Exception:
        valid_sig = False

    if not valid_sig:
        demo_sig_ok = False
        try:
            demo_sig_ok = _b64dec(sig_b64).decode('utf-8') in {'demo-signature', 'no-key'}
        except Exception:
            demo_sig_ok = False

        if not (ALLOW_DEMO_SIGNATURE_BYPASS and demo_sig_ok):
            user_manager.record_failed_login(username)
            return jsonify({'success': False, 'message': 'Signature verification failed'}), 401

    user_manager.reset_failed_login_count(username)

    return jsonify({'success': True, 'message': 'Authenticated', 'username': username})


# ──────────────────────────────────────────
# 4. LIST FILES
# GET /api/files?username=xxx
# Returns: { success, files: [...] }
# ──────────────────────────────────────────
@app.route('/api/files', methods=['GET'])
def list_files():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'success': False, 'message': 'username required'}), 400

    files = storage_manager.get_user_files(username)
    result = []
    for f in files:
        result.append({
            'id':       f['id'],
            'name':     f['file_name'],
            'size':     _fmt_size(f['file_size']),
            'size_bytes': f['file_size'],
            'date':     str(f['uploaded_at'])[:10],
            'hash':     f['file_hash'],
        })

    return jsonify({'success': True, 'files': result})


# ──────────────────────────────────────────
# 5. UPLOAD
# POST /api/files/upload
# Body: multipart/form-data
#   username, private_key_b64 (PEM base64), file (binary)
# Server encrypts with hybrid scheme, stores .enc file + encrypted AES key
# ──────────────────────────────────────────
@app.route('/api/files/upload', methods=['POST'])
def upload_file():
    username        = request.form.get('username', '').strip()
    private_key_b64 = request.form.get('private_key_b64', '')
    uploaded_file   = request.files.get('file')

    if not username or not private_key_b64 or not uploaded_file:
        return jsonify({'success': False, 'message': 'username, private_key_b64 and file are required'}), 400

    # Get receiver public key from DB
    public_key_pem = user_manager.get_public_key(username)
    if not public_key_pem:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    private_key_pem = _b64dec(private_key_b64)
    file_data       = uploaded_file.read()

    # Check quota before processing
    available = storage_manager.get_available_space(username)
    if available is not None and len(file_data) > available:
        return jsonify({'success': False, 'message': 'Insufficient storage quota'}), 413

    # Hybrid encrypt
    aes_key       = get_random_bytes(32)
    enc_result    = encrypt_file_aes(file_data, aes_key)
    enc_aes_key   = encrypt_aes_key_rsa(aes_key, public_key_pem.encode('utf-8'))
    file_hash     = compute_file_hash(file_data)
    signature     = sign_file(file_data, private_key_pem)

    # Pack ciphertext: nonce(16) + tag(16) + ciphertext
    blob = enc_result['nonce'] + enc_result['tag'] + enc_result['ciphertext']

    # Save to disk
    safe_name  = os.path.basename(uploaded_file.filename) + '.enc'
    user_dir   = _user_dir(username)
    file_path  = os.path.join(user_dir, safe_name)
    with open(file_path, 'wb') as fh:
        fh.write(blob)

    # Register in DB
    reg = storage_manager.add_file(
        username=username,
        filename=safe_name,
        file_path=file_path,
        file_size=len(blob),
        file_hash=_b64enc(file_hash),
        signature=_b64enc(signature),
    )
    if not reg['success']:
        os.remove(file_path)
        return jsonify(reg), 400

    # Store encrypted AES key
    storage_manager.store_encrypted_key(reg['file_id'], _b64enc(enc_aes_key))

    return jsonify({'success': True, 'message': f'{safe_name} encrypted and uploaded', 'file_id': reg['file_id']}), 201


# ──────────────────────────────────────────
# 6. DOWNLOAD
# GET /api/files/download/<filename>?username=xxx&private_key_b64=xxx
# Returns decrypted file binary
# ──────────────────────────────────────────
@app.route('/api/files/download/<filename>', methods=['GET'])
def download_file(filename):
    username        = request.args.get('username', '').strip()
    private_key_b64 = request.args.get('private_key_b64', '')

    if not username or not private_key_b64:
        return jsonify({'success': False, 'message': 'username and private_key_b64 required'}), 400

    file_meta = storage_manager.get_file(username, filename)
    if not file_meta:
        return jsonify({'success': False, 'message': 'File not found'}), 404

    # Read blob from disk
    user_dir  = _user_dir(username)
    file_path = os.path.join(user_dir, os.path.basename(filename))
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'File blob missing on server'}), 404

    with open(file_path, 'rb') as fh:
        blob = fh.read()

    # Unpack blob: nonce(16) + tag(16) + ciphertext
    nonce      = blob[:16]
    tag        = blob[16:32]
    ciphertext = blob[32:]

    # Get encrypted AES key
    enc_aes_key_b64 = storage_manager.get_encrypted_key(file_meta['id'])
    if not enc_aes_key_b64:
        return jsonify({'success': False, 'message': 'Encrypted key not found'}), 404

    private_key_pem = _b64dec(private_key_b64)
    enc_aes_key     = _b64dec(enc_aes_key_b64)

    try:
        aes_key      = decrypt_aes_key_rsa(enc_aes_key, private_key_pem)
        plain_data   = decrypt_file_aes({'nonce': nonce, 'tag': tag, 'ciphertext': ciphertext}, aes_key)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Decryption failed: {str(e)}'}), 400

    # Verify integrity
    public_key_pem = user_manager.get_public_key(username)
    sig_b64        = file_meta.get('signature')
    integrity_ok   = False
    signature_ok   = False

    stored_hash = _b64dec(file_meta['file_hash']) if file_meta.get('file_hash') else None
    if stored_hash:
        integrity_ok = verify_file_integrity(plain_data, stored_hash)

    if sig_b64 and public_key_pem:
        try:
            signature_ok = verify_signature(plain_data, _b64dec(sig_b64), public_key_pem.encode('utf-8'))
        except Exception:
            signature_ok = False

    original_name = filename.replace('.enc', '') if filename.endswith('.enc') else filename

    response = send_file(
        io.BytesIO(plain_data),
        as_attachment=True,
        download_name=original_name,
    )
    response.headers['X-Integrity-OK']  = str(integrity_ok)
    response.headers['X-Signature-OK']  = str(signature_ok)
    return response


# ──────────────────────────────────────────
# 7. DELETE FILE
# DELETE /api/files/<filename>?username=xxx
# ──────────────────────────────────────────
@app.route('/api/files/<filename>', methods=['DELETE'])
def delete_file(filename):
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'success': False, 'message': 'username required'}), 400

    # Remove from disk
    user_dir  = _user_dir(username)
    file_path = os.path.join(user_dir, os.path.basename(filename))
    if os.path.exists(file_path):
        os.remove(file_path)

    result = storage_manager.delete_file(username, filename)
    if not result['success']:
        return jsonify(result), 404

    return jsonify(result)


# ──────────────────────────────────────────
# 8. STORAGE STATS
# GET /api/storage/stats?username=xxx
# ──────────────────────────────────────────
@app.route('/api/storage/stats', methods=['GET'])
def storage_stats():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'success': False, 'message': 'username required'}), 400

    stats = storage_manager.get_storage_stats(username)
    return jsonify({'success': True, **stats})


# ──────────────────────────────────────────
# Utility
# ──────────────────────────────────────────
def _fmt_size(b):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} TB'


if __name__ == '__main__':
    port = int(os.getenv('API_PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=True)
