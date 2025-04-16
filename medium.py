import hashlib
import os

def mgf1(input_seed: bytes, mask_length: int, hash_func=hashlib.sha256) -> bytes:
    # Funkcja generowania maski (MGF1) oparta na funkcji skrótu
    counter = 0
    output = b""
    while len(output) < mask_length:
        # Licznik jest konwertowany na 4 bajty i dodawany do input_seed
        counter_bytes = counter.to_bytes(4, byteorder="big")
        # Hashujemy połączenie input_seed i licznika
        output += hash_func(input_seed + counter_bytes).digest()
        counter += 1
    # Zwracamy maskę o wymaganej długości
    return output[:mask_length]

def oaep_encode(message: bytes, seed: bytes, k: int, hash_func=hashlib.sha256) -> bytes:
    # Funkcja kodowania OAEP

    # Krok 1: Dodanie wypełnienia (padding)
    hash_len = hash_func().digest_size
    # Tworzymy PS (ciąg zer) o odpowiedniej długości
    ps = b"\x00" * (k - len(message) - 2 * hash_len - 2)
    # Łączymy wiadomość, PS i separator \x01
    padded_message = message + ps + b"\x01"

    # Krok 2: Podział na DB i Seed
    db = padded_message

    # Krok 3: Generowanie maski dla DB
    db_mask = mgf1(seed, len(db), hash_func)

    # Krok 4: XOR DB z maską
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # Krok 5: Generowanie maski dla Seed
    seed_mask = mgf1(masked_db, len(seed), hash_func)

    # Krok 6: XOR Seed z maską
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    # Krok 7: Połączenie Masked Seed i Masked DB
    encoded_message = masked_seed + masked_db

    return encoded_message

if __name__ == "__main__":
    k = 256  # Rozmiar modułu RSA w bajtach (klucz 2048-bitowy)
    message = b"Hello, OAEP!"  # Wiadomość wejściowa
    seed = os.urandom(32)  # Losowy seed (32 bajty dla SHA-256)

    encoded_message = oaep_encode(message, seed, k)
    print(f"Zakodowana wiadomość: {encoded_message.hex()}")