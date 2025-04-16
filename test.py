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
def oaep_encode(message: bytes, k: int, hash_func=hashlib.sha256,
                label: bytes = b'', seed: bytes = None) -> bytes:
    """
    Encodes `message` into an OAEP-padded block of length k bytes.
    """
    hLen = hash_func().digest_size
    lHash = hash_func(label).digest()
    mLen = len(message)

    ps_len = k - mLen - 2*hLen - 2
    if ps_len < 0:
        raise ValueError("Message too long for RSA key size")
    PS = b'\x00' * ps_len
    DB = lHash + PS + b'\x01' + message

    if seed is None:
        seed_val = os.urandom(hLen)
    else:
        if len(seed) != hLen:
            raise ValueError(f"Seed must be {hLen} bytes long")
        seed_val = seed

    dbMask = mgf1(seed_val, len(DB), hash_func)
    maskedDB = bytes(x ^ y for x, y in zip(DB, dbMask))
    seedMask = mgf1(maskedDB, hLen, hash_func)
    maskedSeed = bytes(x ^ y for x, y in zip(seed_val, seedMask))

    EM = b'\x00' + maskedSeed + maskedDB
    if len(EM) != k:
        raise ValueError("Encoded message has incorrect length")
    return EM


def oaep_decode(encoded: bytes, k: int, hash_func=hashlib.sha256,
                label: bytes = b'') -> bytes:
    """
    Decodes an OAEP-padded block back to the original message.
    """
    hLen = hash_func().digest_size
    lHash = hash_func(label).digest()

    if len(encoded) != k:
        raise ValueError("Invalid encoded message length")

    Y = encoded[0]
    if Y != 0x00:
        raise ValueError("Decryption error: leading byte is not zero")

    maskedSeed = encoded[1:1+hLen]
    maskedDB = encoded[1+hLen:]

    seedMask = mgf1(maskedDB, hLen, hash_func)
    seed_val = bytes(x ^ y for x, y in zip(maskedSeed, seedMask))
    dbMask = mgf1(seed_val, len(maskedDB), hash_func)
    DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))

    if DB[:hLen] != lHash:
        raise ValueError("Decryption error: lHash mismatch")

    idx = DB.find(b'\x01', hLen)
    if idx < 0:
        raise ValueError("Decryption error: separator not found")

    return DB[idx+1:]

# === RSA Key Management ===
def save_keys(private_key: RSA.RsaKey, public_key: RSA.RsaKey,
              priv_path: str = "private.pem", pub_path: str = "public.pem") -> None:
    """Save RSA keys to PEM files, deleting existing ones first."""
    # Remove old files to ensure fresh write
    for path in (priv_path, pub_path):
        if os.path.exists(path):
            os.remove(path)
            print(f"Removed old key file: {path}")
    # Write new keys
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
    """Generate and save a new RSA key pair."""
    print(f"Generating RSA key pair ({bits}-bit)...")
    key = RSA.generate(bits)
    save_keys(key, key.publickey())
    return key, key.publickey()

# === Utility Input Functions ===
def prompt_choice(prompt: str, choices: set) -> str:
    while True:
        val = input(prompt).strip()
        if val in choices:
            return val
        print("Invalid option, please try again.")


def prompt_yes_no(prompt: str) -> bool:
    while True:
        val = input(prompt).strip().lower()
        if val in ('y', 'yes'):
            return True
        if val in ('n', 'no', ''):
            return False
        print("Please enter 'y' or 'n'.")


def prompt_hex(prompt: str, length: int) -> bytes:
    while True:
        val = input(prompt).strip()
        try:
            b = bytes.fromhex(val)
            if len(b) != length:
                print(f"Invalid length: expected {length} bytes.")
                continue
            return b
        except ValueError:
            print("Invalid hex, please try again.")

# === Interactive CLI ===
def main() -> None:
    print("RSA-OAEP: Encrypt/Decrypt 128-bit AES key")

    # RSA key selection
    choice = prompt_choice(
        "1: Generate new RSA keys\n2: Load existing keys\n>>> ",
        {'1', '2'}
    )
    if choice == '1':
        priv_key, pub_key = generate_rsa_keys()
    else:
        priv_key, pub_key = load_keys()
        print("RSA keys loaded.")

    k = pub_key.size_in_bytes()

    # Hash function selection
    print("\nSelect hash function for OAEP:")
    print(" 1. SHA-256 (default)\n 2. SHA-1\n 3. SHA-512")
    hfunc_choice = prompt_choice(
        ">>> ",
        {'1', '2', '3'}
    )
    hfunc = {'1': hashlib.sha256,
             '2': hashlib.sha1,
             '3': hashlib.sha512}[hfunc_choice]
    print(f"Using hash: {hfunc().name}")

    # Custom seed
    seed = None
    if prompt_yes_no("\nProvide custom OAEP seed? (y/N): "):
        seed = prompt_hex(
            f"Enter seed as hex ({hfunc().digest_size*2} hex chars):\n>>> ",
            hfunc().digest_size
        )

    # Custom label
    label = b''
    if prompt_yes_no("Provide custom OAEP label? (y/N): "):
        label = input("Enter label string:\n>>> ").encode()

    # AES key selection
    print()
    if prompt_yes_no("Generate random 128-bit AES key? (y/N): "):
        aes_key = get_random_bytes(16)
    else:
        while True:
            raw = input("Enter AES key (16-byte text):\n>>> ")
            aes_key = raw.encode()
            if len(aes_key) == 16:
                break
            print("AES key must be exactly 16 bytes.")
    print(f"\nAES key (hex): {aes_key.hex()}")

    # OAEP Encoding
    print("\nEncoding with OAEP...")
    EM = oaep_encode(aes_key, k, hash_func=hfunc, label=label, seed=seed)
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
        rec_key = oaep_decode(EM2, k, hash_func=hfunc, label=label)
        print(f"[AES] Recovered key (hex): {rec_key.hex()}")
        if rec_key == aes_key:
            print("\nSUCCESS: AES key correctly recovered!")
        else:
            print("\nERROR: Recovered key does not match.")
    except Exception as e:
        print(f"\nOAEP decoding error: {e}")

if __name__ == "__main__":
    main()
