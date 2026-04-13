"""
server.py — Flask REST API
Connects the frontend to UserManager, StorageManager, NonceManager, crypto_module.
"""

import os
import base64
import functools
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS

from user_manager import UserManager, StorageManager, NonceManager
from user_manager.crypto_module import (
    generate_rsa_keypair,
    verify_signature,
)

app = Flask(__name__)
CORS(app)  # allow browser requests from file:// or different port

# In-memory auth token store for API authorization
TOKEN_TTL_MINUTES = int(os.getenv('TOKEN_TTL_MINUTES', '120'))
AUTH_TOKENS = {}

user_manager    = UserManager()
storage_manager = StorageManager()
nonce_manager   = NonceManager()

CLOUD_DIR = os.path.join(os.path.dirname(__file__), 'cloud')
os.makedirs(CLOUD_DIR, exist_ok=True)
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), 'frontend')

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

def _create_auth_token(username: str) -> str:
    token = secrets.token_urlsafe(48)
    AUTH_TOKENS[token] = {
        'username': username,
        'expires_at': datetime.utcnow() + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    return token

def _extract_auth_username():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[len('Bearer '):].strip()
    session = AUTH_TOKENS.get(token)
    if not session:
        return None

    if datetime.utcnow() > session['expires_at']:
        AUTH_TOKENS.pop(token, None)
        return None

    return session['username']

def _require_auth(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        username = _extract_auth_username()
        if not username:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        return fn(username, *args, **kwargs)
    return wrapper

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


@app.route('/')
def frontend_index():
    return send_from_directory(FRONTEND_DIR, 'login.html')


@app.route('/<path:filename>')
def frontend_assets(filename):
    if os.path.isfile(os.path.join(FRONTEND_DIR, filename)):
        return send_from_directory(FRONTEND_DIR, filename)
    return jsonify({'success': False, 'message': 'Not found'}), 404

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
        user_manager.record_failed_login(username)
        return jsonify({'success': False, 'message': 'Signature verification failed'}), 401

    user_manager.reset_failed_login_count(username)

    auth_token = _create_auth_token(username)

    return jsonify({'success': True, 'message': 'Authenticated', 'username': username, 'auth_token': auth_token})


# ──────────────────────────────────────────
# 4. LIST FILES
# GET /api/files?username=xxx
# Returns: { success, files: [...] }
# ──────────────────────────────────────────
@app.route('/api/files', methods=['GET'])
@_require_auth
def list_files(username):

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
# 4.b USER PUBLIC KEY (for client-side encryption)
# GET /api/users/me/public-key
# ──────────────────────────────────────────
@app.route('/api/users/me/public-key', methods=['GET'])
@_require_auth
def get_my_public_key(username):
    public_key = user_manager.get_public_key(username)
    if not public_key:
        return jsonify({'success': False, 'message': 'Public key not found'}), 404
    return jsonify({'success': True, 'public_key': public_key})


# ──────────────────────────────────────────
# 5. UPLOAD
# POST /api/files/upload
# Body: multipart/form-data
#   file (encrypted blob), signature_b64, file_hash_b64, enc_aes_key_b64
# Encryption is performed client-side. Server stores encrypted bytes + metadata.
# ──────────────────────────────────────────
@app.route('/api/files/upload', methods=['POST'])
@_require_auth
def upload_file(username):
    signature_b64 = request.form.get('signature_b64', '')
    file_hash_b64 = request.form.get('file_hash_b64', '')
    enc_aes_key_b64 = request.form.get('enc_aes_key_b64', '')
    original_filename = request.form.get('original_filename', '')
    uploaded_file = request.files.get('file')

    if not signature_b64 or not file_hash_b64 or not enc_aes_key_b64 or not uploaded_file:
        return jsonify({'success': False, 'message': 'file, signature_b64, file_hash_b64 and enc_aes_key_b64 are required'}), 400

    incoming_name = original_filename or uploaded_file.filename or 'uploaded_file'
    safe_name = os.path.basename(incoming_name) + '.enc'

    # check if the file exists already
    exists = storage_manager.get_file(username, safe_name)
    if exists:
        return jsonify({'success': False, 'message': 'File name already exists. Use a different name or delete it'}), 409

    blob = uploaded_file.read()
    if len(blob) < 32:
        return jsonify({'success': False, 'message': 'Invalid encrypted payload format'}), 400

    # Check quota before processing
    available = storage_manager.get_available_space(username)
    if available is not None and len(blob) > available:
        return jsonify({'success': False, 'message': 'Insufficient storage quota'}), 413

    # Save to disk
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
        file_hash=file_hash_b64,
        signature=signature_b64,
    )
    if not reg['success']:
        os.remove(file_path)
        return jsonify(reg), 400

    # Store encrypted AES key
    storage_manager.store_encrypted_key(reg['file_id'], enc_aes_key_b64)

    return jsonify({'success': True, 'message': f'{safe_name} uploaded', 'file_id': reg['file_id']}), 201


# ──────────────────────────────────────────
# 6. DOWNLOAD
# GET /api/files/download/<filename>
# Returns encrypted package for client-side decryption
# ──────────────────────────────────────────
@app.route('/api/files/download/<filename>', methods=['GET'])
@_require_auth
def download_file(username, filename):

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

    # Get encrypted AES key
    enc_aes_key_b64 = storage_manager.get_encrypted_key(file_meta['id'])
    if not enc_aes_key_b64:
        return jsonify({'success': False, 'message': 'Encrypted key not found'}), 404

    public_key_pem = user_manager.get_public_key(username)
    original_name = filename.replace('.enc', '') if filename.endswith('.enc') else filename

    return jsonify({
        'success': True,
        'filename': original_name,
        'blob_b64': _b64enc(blob),
        'enc_aes_key_b64': enc_aes_key_b64,
        'file_hash_b64': file_meta.get('file_hash'),
        'signature_b64': file_meta.get('signature'),
        'public_key': public_key_pem,
    })


# ──────────────────────────────────────────
# 7. DELETE FILE
# DELETE /api/files/<filename>
# ──────────────────────────────────────────
@app.route('/api/files/<filename>', methods=['DELETE'])
@_require_auth
def delete_file(username, filename):

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
# GET /api/storage/stats
# ──────────────────────────────────────────
@app.route('/api/storage/stats', methods=['GET'])
@_require_auth
def storage_stats(username):

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
    app.run(host='127.0.0.1', port=port, debug=False)
