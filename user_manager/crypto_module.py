from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# ===============================
# RSA — génération des clés
# ===============================
def generate_rsa_keypair(key_size=2048):
    key = RSA.generate(key_size)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key

# ===============================
# AES — chiffrement fichier
# mode sécurisé : GCM (authentifié)
# ===============================
def encrypt_file_aes(file_data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(file_data)

    return {
        "nonce": cipher.nonce,
        "tag": tag,
        "ciphertext": ciphertext
    }

# ===============================
# AES — déchiffrement
# ===============================
def decrypt_file_aes(encrypted_data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=encrypted_data["nonce"])

    data = cipher.decrypt_and_verify(
        encrypted_data["ciphertext"],
        encrypted_data["tag"]
    )

    return data

# ===============================
# RSA — chiffrement clé AES
# ===============================
def encrypt_aes_key_rsa(aes_key, rsa_public_key):
    public_key = RSA.import_key(rsa_public_key)

    cipher_rsa = PKCS1_OAEP.new(public_key)

    encrypted_key = cipher_rsa.encrypt(aes_key)

    return encrypted_key

# ===============================
# RSA — déchiffrement clé AES
# ===============================
def decrypt_aes_key_rsa(encrypted_key, rsa_private_key):
    private_key = RSA.import_key(rsa_private_key)

    cipher_rsa = PKCS1_OAEP.new(private_key)

    aes_key = cipher_rsa.decrypt(encrypted_key)

    return aes_key

# ===============================
# HASH (intégrité)
# basé sur SHA-256
# ===============================
def compute_file_hash(file_data):
    h = SHA256.new(file_data)
    return h.digest()

# ===============================
# Vérification intégrité
# ===============================
def verify_file_integrity(file_data, expected_hash):
    current_hash = compute_file_hash(file_data)
    return current_hash == expected_hash

# ===============================
# Signature numérique
# ===============================
def sign_file(file_data, private_key):
    key = RSA.import_key(private_key)

    h = SHA256.new(file_data)

    signature = pkcs1_15.new(key).sign(h)

    return signature

# ===============================
# Vérification signature
# ===============================
def verify_signature(file_data, signature, public_key):
    key = RSA.import_key(public_key)

    h = SHA256.new(file_data)

    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ===============================
# Fonction  
# chiffrement hybride complet en une fonction
# ===============================
def hybrid_encrypt(file_data, sender_private_key, receiver_public_key):
    
    aes_key = get_random_bytes(32)

    encrypted_file = encrypt_file_aes(file_data, aes_key)

    encrypted_key = encrypt_aes_key_rsa(aes_key, receiver_public_key)

    file_hash = compute_file_hash(file_data)

    signature = sign_file(file_data, sender_private_key)

    return {
        "encrypted_file": encrypted_file,
        "encrypted_key": encrypted_key,
        "signature": signature,
        "hash": file_hash
    }


def hybrid_decrypt(package, receiver_private_key, sender_public_key):
    
    aes_key = decrypt_aes_key_rsa(package["encrypted_key"], receiver_private_key)

    decrypted_data = decrypt_file_aes(package["encrypted_file"], aes_key)

    integrity_ok = verify_file_integrity(decrypted_data, package["hash"])

    signature_ok = verify_signature(decrypted_data, package["signature"], sender_public_key)

    return decrypted_data, integrity_ok, signature_ok


if __name__ == "__main__":

    # ===============================
    # 🔑 Génération des clés
    # ===============================
    sender_private, sender_public = generate_rsa_keypair()
    receiver_private, receiver_public = generate_rsa_keypair()

    # ===============================
    #  CAS 1 : données normales
    # ===============================
    print("\n=== CAS 1 : DONNÉES NON MODIFIÉES ===")

    data = b"Hello secure world"

    package = hybrid_encrypt(data, sender_private, receiver_public)

    decrypted, integrity_ok, signature_ok = hybrid_decrypt(
        package,
        receiver_private,
        sender_public
    )

    print("Original:", data)
    print("Decrypted:", decrypted)
    print("Integrity OK:", integrity_ok)
    print("Signature OK:", signature_ok)

    # ===============================
    #  CAS 2 : données modifiées (attaque)
    # ===============================
    print("=== CAS 2 : DONNÉES MODIFIÉES ===")

    data = b"Hello secure world"

    package = hybrid_encrypt(data, sender_private, receiver_public)
    
    
    #  Simulation attaque : modification du ciphertext
    package["encrypted_file"]["ciphertext"] = b"HACKED DATA"

    try:
        decrypted, integrity_ok, signature_ok = hybrid_decrypt(
            package,
            receiver_private,
            sender_public
        )

        print("Decrypted:", decrypted)
        print("Integrity OK:", integrity_ok)
        print("Signature OK:", signature_ok)

    except Exception as e:
        print("Erreur détectée (attaque) :", str(e))
