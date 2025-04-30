# FUNCȚII DE CONVERSIE (BIG-ENDIAN)
def pack_2uint32_be(v0, v1):
    result = bytearray(8)
    for i in range(4):
        result[i] = (v0 >> (24 - i * 8)) & 0xFF
    for i in range(4):
        result[i + 4] = (v1 >> (24 - i * 8)) & 0xFF
    return bytes(result)

def unpack_2uint32_be(data):
    v0 = 0
    v1 = 0
    for i in range(4):
        v0 = (v0 << 8) | data[i]
    for i in range(4):
        v1 = (v1 << 8) | data[i + 4]
    return v0, v1

# XTEA - ENCRYPT/DECRYPT BLOCK
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

# PADDING
def pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Padding invalid: {}".format(pad_len))
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding bytes invalid.")
    return data[:-pad_len]

# ENCRYPT/DECRYPT STRINGURI
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

# TEST
key = b'0123456789012345'  # 16 bytes
text = "Hello"

print("Original:", text)

encrypted = encrypt_string(text, key)
print("Criptat (hex):", encrypted.hex())

decrypted = decrypt_string(encrypted, key)
print("Decriptat:", decrypted)