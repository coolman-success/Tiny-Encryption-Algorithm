import struct


def tea_code(v, k) -> bytes:
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


def tea_decipher(v: bytes, k: bytes) -> bytes:
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


def main():
    key = "0xA56BABCD00000000FFFFFFFFABCDEF01"
    plain = "0x0123456789ABCDEF"
    key = bytes.fromhex(key[2:])
    plain = bytes.fromhex(plain[2:])
    cipher = tea_code(plain, key)
    print(f"The encrypted message is {cipher.hex()}")
    decipher = tea_decipher(cipher, key)
    print(f"The decrypted message is {decipher.hex().upper()}")


if __name__ == "__main__":
    main()
