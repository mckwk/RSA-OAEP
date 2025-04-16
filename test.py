#!/usr/bin/env python3
import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# === MGF1 ===
def mgf1(seed: bytes, mask_len: int, hash_func=hashlib.sha256) -> bytes:
    """
    Mask Generation Function based on a hash function (MGF1).
    """
    counter = 0
    output = b""
    hLen = hash_func().digest_size
    while len(output) < mask_len:
        C = counter.to_bytes(4, byteorder='big')
        output += hash_func(seed + C).digest()
        counter += 1
    return output[:mask_len]

# === OAEP Encode/Decode ===
def oaep_encode(message: bytes, k: int, hash_func=hashlib.sha256, label: bytes = b'', seed: bytes = None) -> bytes:
    """
    Encodes `message` (bytes) into an OAEP-padded block of length k bytes.
    """
    hLen = hash_func().digest_size
    lHash = hash_func(label).digest()
    mLen = len(message)

    # Calculate padding string length
    ps_len = k - mLen - 2*hLen - 2
    if ps_len < 0:
        raise ValueError("Message too long for RSA key size")
    PS = b'\x00' * ps_len

    # Data block DB = lHash || PS || 0x01 || message
    DB = lHash + PS + b'\x01' + message

    # Seed for masking
    if seed is None:
        seed = os.urandom(hLen)
    elif len(seed) != hLen:
        raise ValueError(f"Seed must be {hLen} bytes long")

    # Generate masks
    dbMask = mgf1(seed, len(DB), hash_func)
    maskedDB = bytes(x ^ y for x, y in zip(DB, dbMask))
    seedMask = mgf1(maskedDB, hLen, hash_func)
    maskedSeed = bytes(x ^ y for x, y in zip(seed, seedMask))

    # Encoded message EM = 0x00 || maskedSeed || maskedDB
    EM = b'\x00' + maskedSeed + maskedDB
    if len(EM) != k:
        raise ValueError("Encoded message has incorrect length")
    return EM


def oaep_decode(encoded: bytes, k: int, hash_func=hashlib.sha256, label: bytes = b'') -> bytes:
    """
    Decodes an OAEP-padded block `encoded` of length k bytes, returning the original message.
    """
    hLen = hash_func().digest_size
    lHash = hash_func(label).digest()

    if len(encoded) != k:
        raise ValueError("Invalid encoded message length")

    # Split encoded block: Y || maskedSeed || maskedDB
    Y = encoded[0]
    if Y != 0x00:
        raise ValueError("Decryption error: leading byte is not zero")

    maskedSeed = encoded[1:1+hLen]
    maskedDB = encoded[1+hLen:]

    # Recover seed and DB
    seedMask = mgf1(maskedDB, hLen, hash_func)
    seed = bytes(x ^ y for x, y in zip(maskedSeed, seedMask))
    dbMask = mgf1(seed, len(maskedDB), hash_func)
    DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))

    # Verify lHash
    if DB[:hLen] != lHash:
        raise ValueError("Decryption error: lHash mismatch")

    # Find separator 0x01
    idx = DB.find(b'\x01', hLen)
    if idx < 0:
        raise ValueError("Decryption error: separator not found")

    # Return message after the separator
    return DB[idx+1:]

# === RSA Key Management ===
def save_keys(private_key: RSA.RsaKey, public_key: RSA.RsaKey,
              priv_path: str = "private.pem", pub_path: str = "public.pem") -> None:
    """Save RSA keys to PEM files."""
    with open(priv_path, 'wb') as f:
        f.write(private_key.export_key())
    with open(pub_path, 'wb') as f:
        f.write(public_key.export_key())
    print(f"Keys saved to {priv_path} and {pub_path}")


def load_keys(priv_path: str = "private.pem", pub_path: str = "public.pem") -> tuple:
    """Load RSA keys from PEM files."""
    with open(priv_path, 'rb') as f:
        priv = RSA.import_key(f.read())
    with open(pub_path, 'rb') as f:
        pub = RSA.import_key(f.read())
    return priv, pub


def generate_rsa_keys(bits: int = 2048) -> tuple:
    """Generate a new RSA key pair and save to disk."""
    print(f"Generating RSA key pair ({bits}-bit)...")
    key = RSA.generate(bits)
    save_keys(key, key.publickey())
    return key, key.publickey()

# === Interactive CLI ===
def main() -> None:
    print("RSA-OAEP: Encrypt/Decrypt 128-bit AES key")

    # RSA key selection
    choice = input("1: Generate new RSA keys\n2: Load existing keys\n>>> ")
    if choice == "1":
        priv_key, pub_key = generate_rsa_keys()
    elif choice == "2":
        priv_key, pub_key = load_keys()
        print("RSA keys loaded.")
    else:
        print("Invalid option.")
        return

    k = pub_key.size_in_bytes()

    # Hash function selection
    print("\nSelect hash function for OAEP:")
    print(" 1. SHA-256 (default)\n 2. SHA-1\n 3. SHA-512")
    opt = input(">>> ")
    if opt == "2":
        hfunc = hashlib.sha1
    elif opt == "3":
        hfunc = hashlib.sha512
    else:
        hfunc = hashlib.sha256
    print(f"Using hash: {hfunc().name}")

    # AES key selection
    aes_choice = input("\nGenerate random 128-bit AES key? (y/N): ").strip().lower()
    if aes_choice == "y":
        aes_key = get_random_bytes(16)
    else:
        raw = input("Enter AES key (16 bytes as text):\n>>> ")
        aes_key = raw.encode()
        if len(aes_key) != 16:
            print("AES key must be exactly 16 bytes.")
            return
    print(f"\nAES key (hex): {aes_key.hex()}")

    # OAEP Encoding
    print("\nEncoding with OAEP...")
    EM = oaep_encode(aes_key, k, hash_func=hfunc)
    print(f"[OAEP] Encoded block (hex): {EM.hex()}")

    # RSA Encryption
    print("\nRSA Encryption...")
    m_int = int.from_bytes(EM, byteorder='big')
    c_int = pow(m_int, pub_key.e, pub_key.n)
    C = c_int.to_bytes(k, byteorder='big')
    print(f"[RSA] Ciphertext (hex): {C.hex()}")

    # RSA Decryption
    print("\nRSA Decryption...")
    m2_int = pow(int.from_bytes(C, byteorder='big'), priv_key.d, priv_key.n)
    EM2 = m2_int.to_bytes(k, byteorder='big')

    # OAEP Decoding
    print("\nDecoding OAEP...")
    try:
        rec_key = oaep_decode(EM2, k, hash_func=hfunc)
        print(f"[AES] Recovered key (hex): {rec_key.hex()}")
        if rec_key == aes_key:
            print("\nSUCCESS: AES key correctly recovered!")
        else:
            print("\nERROR: Recovered key does not match.")
    except Exception as e:
        print(f"\nOAEP decoding error: {e}")

if __name__ == "__main__":
    main()
