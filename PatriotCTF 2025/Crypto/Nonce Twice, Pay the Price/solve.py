import hashlib

from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod

# --- PHẦN 1: KHÔI PHỤC PRIVATE KEY ---

# Thông số Curve SECP256k1
n = SECP256k1.order

# Dữ liệu từ đề bài
r = 0x288B415D6703BA7A2487681B10DA092D991A2EF7D10DE016DAEA4444523DC792
s1 = 0xFC00F6D1C8E93BEB4C983104F1991E6D1951AA729004B7A1E841F29D12797F4
z1 = 0x9F9B697BAA97445B19C6552E13B3A796EC9B76D6D95190A0C7FAB01CCE59B7FD

s2 = 0x693EE365DD7307A44FDDBDD81C0059B5B5F7EF419BEEE7AAADA3C37798E270C5
z2 = 0x465E2CF6B15B701B2D40CAC239AB4D50388CD3E0CA54621CFF58308F7C9A226B

# Tính k (Nonce)
# k = (z1 - z2) * (s1 - s2)^-1 mod n
numerator = (z1 - z2) % n
denominator = inverse_mod(s1 - s2, n)
k = (numerator * denominator) % n

# Tính d (Private Key)
# d = r^-1 * (s1 * k - z1) mod n
r_inv = inverse_mod(r, n)
d = (r_inv * (s1 * k - z1)) % n

print(f"d: {hex(d)}")

# --- PHẦN 2: GIẢI MÃ SECRET BLOB ---

# Chuyển d sang bytes để làm key
pri_key_bytes = d.to_bytes(32, "big")

# Dữ liệu mã hóa (Secret Blob)
blob_hex = "5fda1f0ecd917b01ae4cfad672197a84fcde11807e8a60da472c2c475ec19bbbef1884318298587ebb9a66"
ciphertext = bytes.fromhex(blob_hex)

flag = b""
block_size = 32  # SHA256 output size

# Duyệt qua từng block để decrypt
for i in range(0, len(ciphertext), block_size):
    # Counter: 0, 1, 2... (4 bytes Big Endian)
    ctr = i // block_size
    ctr_bytes = ctr.to_bytes(4, "big")

    # Tạo Keystream: SHA256(Key || Counter)
    seed = pri_key_bytes + ctr_bytes
    keystream = hashlib.sha256(seed).digest()

    # Cắt ciphertext tương ứng và XOR
    chunk = ciphertext[i : i + block_size]
    decrypted_chunk = bytes([c ^ k for c, k in zip(chunk, keystream)])
    flag += decrypted_chunk

print(f"FLAG: {flag.decode()}")
