import os
import serial
import time

# Curba Curve25519 si Montgomery Ladder
P = 2**255 - 19
A24 = 121665
G = 9

def cswap(swap, x, y):
    dummy = swap * (x - y) % P
    x = (x - dummy) % P
    y = (y + dummy) % P
    return x, y

def montgomery_ladder(k, u):
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    swap = 0
    for i in reversed(range(255)):
        bit = (k >> i) & 1
        swap ^= bit
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = bit

        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P

        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P

        x3 = (DA + CB)**2 % P
        z3 = (u * (DA - CB)**2) % P
        x2 = (AA * BB) % P
        z2 = (E * (AA + A24 * E)) % P
    return (x2 * pow(z2, P-2, P)) % P

def generate_private_key():
    private_key = int.from_bytes(os.urandom(32), 'little')
    private_key &= (1 << 254) - 8
    private_key |= 1 << 254
    return private_key

def generate_public_key(private_key):
    return montgomery_ladder(private_key, G)

# XTEA
def pack_2uint32_be(v0, v1):
    result = bytearray(8)
    for i in range(4):
        result[i] = (v0 >> (24 - i * 8)) & 0xFF
    for i in range(4):
        result[i+4] = (v1 >> (24 - i * 8)) & 0xFF
    return bytes(result)

def unpack_2uint32_be(data):
    v0 = 0
    v1 = 0
    for i in range(4):
        v0 = (v0 << 8) | data[i]
        v1 = (v1 << 8) | data[i+4]
    return v0, v1

def xtea_encrypt_block(block, key_bytes, num_rounds=32):
    v0, v1 = unpack_2uint32_be(block)
    k = [int.from_bytes(key_bytes[i:i+4], 'big') for i in range(0, 16, 4)]
    delta = 0x9E3779B9
    sum = 0
    for _ in range(num_rounds):
        v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & 0xFFFFFFFF
        sum = (sum + delta) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]))) & 0xFFFFFFFF
    return pack_2uint32_be(v0, v1)

def xtea_decrypt_block(block, key_bytes, num_rounds=32):
    v0, v1 = unpack_2uint32_be(block)
    k = [int.from_bytes(key_bytes[i:i+4], 'big') for i in range(0, 16, 4)]
    delta = 0x9E3779B9
    sum = (delta * num_rounds) & 0xFFFFFFFF
    for _ in range(num_rounds):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & 0xFFFFFFFF
    return pack_2uint32_be(v0, v1)

def pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_string(plaintext, key_bytes):
    plaintext_bytes = pad(plaintext.encode('utf-8'))
    ciphertext = b''
    for i in range(0, len(plaintext_bytes), 8):
        block = plaintext_bytes[i:i+8]
        ciphertext += xtea_encrypt_block(block, key_bytes)
    return ciphertext

def decrypt_string(ciphertext, key_bytes):
    decrypted = b''
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        decrypted += xtea_decrypt_block(block, key_bytes)
    return unpad(decrypted).decode('utf-8')

# === Program principal ===
bluetooth_port = "COM5"
baud_rate = 9600

private_key = generate_private_key()
public_key = generate_public_key(private_key)

try:
    bt = serial.Serial(bluetooth_port, baud_rate, timeout=1)
    print("Conectat la HC-05")

    time.sleep(2)

    # Trimitem cheia publica catre Pico
    bt.write((str(public_key) + "\n").encode())

    # Primim cheia publica de la Pico
    pico_public_key = int(bt.readline().decode().strip())

    # Calculam cheia secreta comuna
    shared_secret = montgomery_ladder(private_key, pico_public_key)
    shared_key_bytes = shared_secret.to_bytes(32, 'little')[:16]

    print("Negociere terminata, cheia simetrica este stabilita.")
    print(shared_secret)

    while True:
        message = input("Trimite mesaj (sau 'exit'): ")
        if message.lower() == "exit":
            break

        encrypted = encrypt_string(message, shared_key_bytes)
        bt.write(encrypted.hex().encode() + b"\n")
        time.sleep(0.2)

        while bt.in_waiting:
            response = bt.readline().decode().strip()
            if response:
                try:
                    decrypted = decrypt_string(bytes.fromhex(response), shared_key_bytes)
                    print(f"Decriptat: {decrypted}")
                except:
                    print(f"Mesaj necunoscut sau corupt: {response}")

    bt.close()

except Exception as e:
    print(f"Eroare: {e}")
