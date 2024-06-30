import struct

s = [
    [3, 7, 11, 19],
    [3, 5, 9, 13],
    [3, 9, 11, 15]
]

def F(x, y, z): return (x & y) | (~x & z)
def G(x, y, z): return (x & y) | (x & z) | (y & z)
def H(x, y, z): return x ^ y ^ z

def left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def md4(message):
    # Pre-processing
    message = bytearray(message, 'ascii')
    orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += orig_len_in_bits.to_bytes(8, 'little')

    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    for chunk_start in range(0, len(message), 64):
        chunk = message[chunk_start:chunk_start + 64]
        X = list(struct.unpack('<16I', chunk))

        AA, BB, CC, DD = A, B, C, D

        for i in range(16):
            k = i
            s_index = i % 4
            if i < 4:
                A = left_rotate((A + F(B, C, D) + X[k]) & 0xffffffff, s[0][s_index])
            elif i < 8:
                D = left_rotate((D + F(A, B, C) + X[k]) & 0xffffffff, s[0][s_index])
            elif i < 12:
                C = left_rotate((C + F(D, A, B) + X[k]) & 0xffffffff, s[0][s_index])
            else:
                B = left_rotate((B + F(C, D, A) + X[k]) & 0xffffffff, s[0][s_index])

        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            s_index = i % 4
            if i < 4:
                A = left_rotate((A + G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, s[1][s_index])
            elif i < 8:
                D = left_rotate((D + G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, s[1][s_index])
            elif i < 12:
                C = left_rotate((C + G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, s[1][s_index])
            else:
                B = left_rotate((B + G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, s[1][s_index])

        for i in range(16):
            k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][i]
            s_index = i % 4
            if i < 4:
                A = left_rotate((A + H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, s[2][s_index])
            elif i < 8:
                D = left_rotate((D + H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, s[2][s_index])
            elif i < 12:
                C = left_rotate((C + H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, s[2][s_index])
            else:
                B = left_rotate((B + H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, s[2][s_index])

        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff

    return ''.join(f'{x:08x}' for x in [A, B, C, D])

data = input("Enter the plain text:\n")

hash_result = md4(data)
print(f"MD4 hash of '{data}': {hash_result}")