import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# === MGF1 i OAEP (modularne) ===

def mgf1(seed: bytes, mask_len: int, hash_func=hashlib.sha256) -> bytes:
    counter = 0
    output = b""
    hash_len = hash_func().digest_size
    while len(output) < mask_len:
        counter_bytes = counter.to_bytes(4, byteorder='big')
        output += hash_func(seed + counter_bytes).digest()
        counter += 1
    return output[:mask_len]

def oaep_encode(message: bytes, k: int, hash_func=hashlib.sha256, seed: bytes = None) -> bytes:
    hash_len = hash_func().digest_size
    l_hash = hash_func(b'').digest()

    db_len = k - hash_len
    ps_length = db_len - len(message) - hash_len - 1
    if ps_length < 0:
        raise ValueError("Message too long for RSA key size.")

    ps = b'\x00' * ps_length
    db = l_hash + ps + b'\x01' + message

    if seed is None:
        seed = os.urandom(hash_len)
    elif len(seed) != hash_len:
        raise ValueError(f"Seed must be {hash_len} bytes long.")

    db_mask = mgf1(seed, len(db), hash_func)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    seed_mask = mgf1(masked_db, hash_len, hash_func)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    return masked_seed + masked_db

def oaep_decode(encoded: bytes, k: int, hash_func=hashlib.sha256) -> bytes:
    hash_len = hash_func().digest_size
    l_hash = hash_func(b'').digest()

    if len(encoded) != k:
        raise ValueError("Invalid encoded message length")

    masked_seed = encoded[:hash_len]
    masked_db = encoded[hash_len:]

    seed_mask = mgf1(masked_db, hash_len, hash_func)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, len(masked_db), hash_func)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash_candidate = db[:hash_len]
    if l_hash_candidate != l_hash:
        raise ValueError("lHash mismatch")

    rest = db[hash_len:]
    try:
        sep_index = rest.index(b'\x01')
    except ValueError:
        raise ValueError("Separator byte not found in DB")

    return rest[sep_index + 1:]

# === RSA Key Handling ===

def save_keys_to_files(private_key, public_key):
    with open("private.pem", "wb") as f:
        f.write(private_key.export_key())
    with open("public.pem", "wb") as f:
        f.write(public_key.export_key())
    print("🔐 Klucze zapisane jako: private.pem, public.pem")

def load_keys():
    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    with open("public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key

def generate_rsa_keys():
    print("🔧 Generowanie nowej pary kluczy RSA (2048-bit)...")
    key = RSA.generate(2048)
    save_keys_to_files(key, key.publickey())
    return key, key.publickey()

# === Interaktywny program ===

def main():
    print("🔐 RSA-OAEP: Szyfrowanie 128-bitowego klucza AES")

    # Wybór kluczy RSA
    choice = input("🔽 Wybierz opcję:\n 1. Wygeneruj nowe klucze RSA\n 2. Użyj istniejących kluczy\n>>> ")
    if choice == "1":
        private_key, public_key = generate_rsa_keys()
    elif choice == "2":
        private_key, public_key = load_keys()
        print("✅ Klucze RSA załadowane.")
    else:
        print("❌ Nieprawidłowa opcja.")
        return

    k = public_key.size_in_bytes()

    # Wybór funkcji hashującej
    print("\n🔧 Wybierz funkcję hashującą do OAEP:")
    print("  1. SHA-256 (domyślnie)")
    print("  2. SHA-1")
    print("  3. SHA-512")
    hash_option = input(">>> ")

    if hash_option == "2":
        selected_hash = hashlib.sha1
    elif hash_option == "3":
        selected_hash = hashlib.sha512
    else:
        selected_hash = hashlib.sha256

    print(f"✅ Wybrana funkcja skrótu: {selected_hash().name}")

    # Wybór klucza AES
    aes_choice = input("🔽 Wygenerować losowy klucz AES 128-bit? (T/N): ").strip().lower()
    if aes_choice == "t":
        aes_key = get_random_bytes(16)
    else:
        raw = input("🔑 Podaj klucz AES (16 bajtów jako tekst):\n>>> ")
        aes_key = raw.encode()
        if len(aes_key) != 16:
            print("❌ Klucz AES musi mieć dokładnie 16 bajtów.")
            return

    print(f"\n🔑 Klucz AES: {aes_key.hex()}")

    print("\n📦 Kodowanie OAEP...")
    encoded = oaep_encode(aes_key, k, hash_func=selected_hash)
    print(f"[OAEP] Zakodowana wiadomość: {encoded.hex()}")

    print("\n🔐 Szyfrowanie RSA...")
    plaintext_int = int.from_bytes(encoded, byteorder='big')
    ciphertext_int = pow(plaintext_int, public_key.e, public_key.n)
    ciphertext = ciphertext_int.to_bytes(k, byteorder='big')
    print(f"[RSA] Ciphertext (hex): {ciphertext.hex()}")

    print("\n🔓 Deszyfrowanie RSA...")
    decrypted_int = pow(int.from_bytes(ciphertext, byteorder='big'), private_key.d, private_key.n)
    decrypted_encoded = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
    if len(decrypted_encoded) < k:
        decrypted_encoded = b'\x00' * (k - len(decrypted_encoded)) + decrypted_encoded
        print(f"[RSA] Dodano wiodące zera: długość {len(decrypted_encoded)}")

    print("\n📤 Dekodowanie OAEP...")
    try:
        recovered_key = oaep_decode(decrypted_encoded, k, hash_func=selected_hash)
        print(f"[AES] Odszyfrowany klucz AES: {recovered_key.hex()}")
        if recovered_key == aes_key:
            print("\n✅ SUKCES: Klucz AES został poprawnie odzyskany!")
        else:
            print("\n❌ BŁĄD: Klucz AES nie zgadza się!")
    except Exception as e:
        print(f"\n❌ Błąd podczas dekodowania OAEP: {str(e)}")

if __name__ == "__main__":
    main()
