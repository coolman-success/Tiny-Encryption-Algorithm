import struct
import sys


def encrypt_block(v, k) -> bytes:
    n = 32
    op = 0xFFFFFFFF
    delta = 0x9E3779B9
    k0, k1, k2, k3 = struct.unpack(b">LLLL", k[0:16])
    v0, v1 = struct.unpack(b">LL", v[0:8])
    sum_ = 0
    for i in range(n):
        sum_ += delta
        v0 += ((v1 << 4) + k0) ^ (v1 + sum_) ^ ((v1 >> 5) + k1)
        v0 &= op
        v1 += ((v0 << 4) + k2) ^ (v0 + sum_) ^ ((v0 >> 5) + k3)
        v1 &= op
    r = struct.pack(b">LL", v0, v1)
    return r


def decrypt_block(v: bytes, k: bytes) -> bytes:
    n = 32
    op = 0xFFFFFFFF
    v0, v1 = struct.unpack(">LL", v[0:8])
    k0, k1, k2, k3 = struct.unpack(b">LLLL", k[0:16])
    delta = 0x9E3779B9
    sum_ = (delta << 5) & op
    for i in range(n):
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum_) ^ ((v0 >> 5) + k3)
        v1 &= op
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum_) ^ ((v1 >> 5) + k1)
        v0 &= op
        sum_ -= delta
        sum_ &= op
    r = struct.pack(b">LL", v0, v1)
    return r


# function to calculate xor between two bytes
def xor(a, b):
    op = 0xFFFFFFFF
    a1, a2 = struct.unpack(b">LL", a[0:8])
    b1, b2 = struct.unpack(b">LL", b[0:8])
    return struct.pack(b">LL", (a1 ^ b1) & op, (a2 ^ b2) & op)


# function to encode the block of text
def encrypt(text: bytes, iv):
    key = "0xA56BABCD00000000FFFFFFFFABCDEF01"
    key = bytes.fromhex(key[2:])

    r = b""
    prev_cipher = encrypt_block(xor(text[:8], iv), key)
    r += prev_cipher
    for i in range(8, len(text), 8):
        plain = text[i : i + 8]
        current_cipher = encrypt_block(xor(plain, prev_cipher), key)
        r += current_cipher
        prev_cipher = current_cipher
    return r


# function to decode the block of text
def decrypt(text: bytes, iv):
    key = "0xA56BABCD00000000FFFFFFFFABCDEF01"
    key = bytes.fromhex(key[2:])
    r = b""
    prev_cipher = text[:8]
    r += xor(decrypt_block(prev_cipher, key), iv)
    for i in range(8, len(text), 8):
        # print(text[i : i + 8].decode())
        current_cipher = text[i : i + 8]
        current_plain = xor(decrypt_block(current_cipher, key), prev_cipher)
        r += current_plain
        prev_cipher = current_cipher
    return r


# since we are working with the block of 8 bytes at once, the block of plain text should
# have a length multiple of 8, to achieve this padding is done to the end of the plain text
# which is removed after deciphering
def prepare_block(s):
    l = len(s) % 8
    if l == 0:
        return s
    pad = " " * (8 - l)
    return s + pad


# function to extract text from the filename
def extract_text(filename):
    res = ""
    with open(filename, "r") as f:
        for each_line in f.readlines():
            res += each_line
    return res


def main(argv):
    # initialization vector
    iv = "0x182a7402d94f82ef"
    iv = bytes.fromhex(iv[2:])
    filename = "msg.txt"

    # generate encryption and decryption result file names
    enc_filename = filename + ".cbc.enc"
    dec_filename = filename + ".cbc.dec"

    # encryption
    text = extract_text(filename)
    text = prepare_block(text)
    text = text.encode()
    encoded = encrypt(text, iv).hex()
    with open(enc_filename, "w") as file:
        file.write(encoded)
    
    # decryption
    text = extract_text(enc_filename)
    text = bytes.fromhex(text)
    # decode the text and remove any extra space present at the end of the text
    decoded = decrypt(text, iv).decode().rstrip()
    with open(dec_filename, "w") as file:
        file.write(decoded)

if __name__ == "__main__":
    main(sys.argv[1:])
