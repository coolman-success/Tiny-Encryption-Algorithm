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


# function to encode the block of text
def encrypt(text: bytes):
    key = "0xA56BABCD00000000FFFFFFFFABCDEF01"
    key = bytes.fromhex(key[2:])

    r = b""
    for i in range(0, len(text), 8):
        # print(text[i : i + 8].decode())
        r += encrypt_block(text[i : i + 8], key)

    return r


# function to decode the block of text
def decrypt(text: bytes):
    key = "0xA56BABCD00000000FFFFFFFFABCDEF01"
    key = bytes.fromhex(key[2:])
    r = b""
    for i in range(0, len(text), 8):
        r += decrypt_block(text[i : i + 8], key)
    return r


# since we are working with the block of 8 bytes at once, the block of plain text should
# have a length multiple of 8, to achieve this padding is done to the end of the plain text
# which is removed after deciphering
def prepare_block(s):
    l = len(s) % 8
    if l == 0:
        return s
    pad = "\0" * (8 - l)
    return s + pad


# function to extract text from the filename
def extract_text(filename):
    res = ""
    with open(filename, "r") as f:
        for each_line in f.readlines():
            res += each_line
    return res


def main(argv):
    # extrac the filename from command line
    filename = "msg.txt"

    # generate encryption and decryption result file names
    enc_filename = filename + ".ecb.enc"
    dec_filename = filename + ".ecb.dec"

    # encryption
    text = extract_text(filename)
    text = prepare_block(text)
    text = text.encode()
    encoded = encrypt(text).hex()
    with open(enc_filename, "w") as file:
        file.write(encoded)
    
    # decryption
    text = extract_text(enc_filename)
    text = bytes.fromhex(text)
    # decode the text and remove any extra space present at the end of the text
    decoded = decrypt(text).decode().rstrip().rstrip('\x00')
    with open(dec_filename, "w") as file:
        file.write(decoded)


if __name__ == "__main__":
    main(sys.argv[1:])
