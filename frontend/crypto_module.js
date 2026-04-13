/*
  Web Crypto helpers for client-side signing and decryption.
  Compatible with current server payload format.
*/

(function () {
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function base64ToUint8Array(base64) {
    return new Uint8Array(base64ToArrayBuffer(base64));
  }

  function pemToArrayBuffer(pem) {
    const body = pem
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');
    return base64ToArrayBuffer(body);
  }

  function uint8ArrayToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function concatUint8(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  function bytesEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function binaryStringToUint8Array(binary) {
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  async function importPrivateKeyForSign(privateKeyPem) {
    return await crypto.subtle.importKey(
      'pkcs8',
      pemToArrayBuffer(privateKeyPem),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );
  }

  async function importPublicKeyForVerify(publicKeyPem) {
    return await crypto.subtle.importKey(
      'spki',
      pemToArrayBuffer(publicKeyPem),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
  }

  async function importPublicKeyForOaep(publicKeyPem, hashName) {
    return await crypto.subtle.importKey(
      'spki',
      pemToArrayBuffer(publicKeyPem),
      { name: 'RSA-OAEP', hash: hashName },
      false,
      ['encrypt']
    );
  }

  async function importPrivateKeyForOaep(privateKeyPem, hashName) {
    return await crypto.subtle.importKey(
      'pkcs8',
      pemToArrayBuffer(privateKeyPem),
      { name: 'RSA-OAEP', hash: hashName },
      false,
      ['decrypt']
    );
  }

  async function signBytes(dataBytes, privateKeyPem) {
    if (privateKeyPem.includes('BEGIN RSA PRIVATE KEY')) {
      if (typeof KJUR === 'undefined' || typeof KEYUTIL === 'undefined') {
        throw new Error('RSA PKCS#1 signing requires jsrsasign to be loaded.');
      }

      const privateKey = KEYUTIL.getKey(privateKeyPem);
      const sig = new KJUR.crypto.Signature({ alg: 'SHA256withRSA' });
      sig.init(privateKey);
      sig.updateHex(uint8ArrayToHex(dataBytes));
      return base64ToUint8Array(hextob64(sig.sign()));
    }

    const key = await importPrivateKeyForSign(privateKeyPem);
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      dataBytes
    );
    return new Uint8Array(signature);
  }

  async function signFileFromFile(file, privateKeyPem) {
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const signature = await signBytes(fileBytes, privateKeyPem);
    return arrayBufferToBase64(signature.buffer);
  }

  async function verifyBytes(dataBytes, signatureBytes, publicKeyPem) {
    const key = await importPublicKeyForVerify(publicKeyPem);
    return await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      signatureBytes,
      dataBytes
    );
  }

  function _tryForgeOaepDecrypt(privateKeyPem, encAesKeyB64, hashName) {
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const mdFactory = hashName === 'SHA-1' ? forge.md.sha1 : forge.md.sha256;
    const decrypted = privateKey.decrypt(forge.util.decode64(encAesKeyB64), 'RSA-OAEP', {
      md: mdFactory.create(),
      mgf1: {
        md: mdFactory.create(),
      },
    });
    return binaryStringToUint8Array(decrypted);
  }

  async function _tryWebCryptoOaepDecrypt(privateKeyPem, encAesKeyB64, hashName) {
    const privateKey = await importPrivateKeyForOaep(privateKeyPem, hashName);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      base64ToArrayBuffer(encAesKeyB64)
    );
    return new Uint8Array(decrypted);
  }

  async function decryptAesKeyRsa(encAesKeyB64, privateKeyPem) {
    if (privateKeyPem.includes('BEGIN RSA PRIVATE KEY')) {
      if (typeof forge === 'undefined') {
        throw new Error('RSA PKCS#1 decryption requires forge to be loaded.');
      }

      try {
        return _tryForgeOaepDecrypt(privateKeyPem, encAesKeyB64, 'SHA-1');
      } catch (_) {
        return _tryForgeOaepDecrypt(privateKeyPem, encAesKeyB64, 'SHA-256');
      }
    }

    try {
      return await _tryWebCryptoOaepDecrypt(privateKeyPem, encAesKeyB64, 'SHA-1');
    } catch (_) {
      return await _tryWebCryptoOaepDecrypt(privateKeyPem, encAesKeyB64, 'SHA-256');
    }
  }

  async function encryptAesKeyRsa(aesKeyBytes, publicKeyPem) {
    try {
      const publicKey = await importPublicKeyForOaep(publicKeyPem, 'SHA-1');
      const enc = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, aesKeyBytes);
      return new Uint8Array(enc);
    } catch (_) {
      const publicKey = await importPublicKeyForOaep(publicKeyPem, 'SHA-256');
      const enc = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, aesKeyBytes);
      return new Uint8Array(enc);
    }
  }

  async function encryptFileAesGcm(plainBytes, aesKeyBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const combined = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, aesKey, plainBytes)
    );

    const ciphertext = combined.slice(0, combined.length - 16);
    const tag = combined.slice(combined.length - 16);

    return concatUint8(iv, concatUint8(tag, ciphertext));
  }

  async function decryptBlobAesGcm(blobB64, aesKeyBytes) {
    const blob = base64ToUint8Array(blobB64);
    if (blob.length < 32) throw new Error('Invalid encrypted blob format.');

    const nonce = blob.slice(0, 16);
    const tag = blob.slice(16, 32);
    const ciphertext = blob.slice(32);

    const combined = concatUint8(ciphertext, tag);

    const aesKey = await crypto.subtle.importKey(
      'raw',
      aesKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        tagLength: 128,
      },
      aesKey,
      combined
    );

    return new Uint8Array(plain);
  }

  async function sha256(dataBytes) {
    const digest = await crypto.subtle.digest('SHA-256', dataBytes);
    return new Uint8Array(digest);
  }

  async function decryptAndVerifyPackage(pkg, privateKeyPem) {
    const aesKey = await decryptAesKeyRsa(pkg.enc_aes_key_b64, privateKeyPem);
    const plainBytes = await decryptBlobAesGcm(pkg.blob_b64, aesKey);

    const computedHash = await sha256(plainBytes);
    const expectedHash = base64ToUint8Array(pkg.file_hash_b64 || '');
    const hashOk = bytesEqual(computedHash, expectedHash);

    let signatureOk = false;
    if (pkg.signature_b64 && pkg.public_key) {
      const sigBytes = base64ToUint8Array(pkg.signature_b64);
      signatureOk = await verifyBytes(plainBytes, sigBytes, pkg.public_key);
    }

    return {
      plainBytes,
      hashOk,
      signatureOk,
      filename: pkg.filename,
    };
  }

  async function encryptFileForUpload(file, privateKeyPem, publicKeyPem) {
    const plainBytes = new Uint8Array(await file.arrayBuffer());
    const aesKey = crypto.getRandomValues(new Uint8Array(32));

    const encryptedBlob = await encryptFileAesGcm(plainBytes, aesKey);
    const encAesKey = await encryptAesKeyRsa(aesKey, publicKeyPem);
    const fileHash = await sha256(plainBytes);
    const signature = await signBytes(plainBytes, privateKeyPem);

    return {
      encryptedBlob,
      encryptedBlobB64: arrayBufferToBase64(encryptedBlob.buffer),
      encAesKeyB64: arrayBufferToBase64(encAesKey.buffer),
      fileHashB64: arrayBufferToBase64(fileHash.buffer),
      signatureB64: arrayBufferToBase64(signature.buffer),
    };
  }

  window.CryptoModule = {
    signFileFromFile,
    decryptAndVerifyPackage,
    encryptFileForUpload,
  };
})();
