PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

SHIFT_SCHEDULE = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]


def permute(key, table):
    return ''.join([key[i - 1] for i in table])


def shift_left(key_half, num_shifts):
    return key_half[num_shifts:] + key_half[:num_shifts]


def generate_subkeys(initial_key):
    permuted_key = permute(initial_key, PC1)

    left_half = permuted_key[:28]
    right_half = permuted_key[28:]

    subkeys = []

    for shift in SHIFT_SCHEDULE:
        left_half = shift_left(left_half, shift)
        right_half = shift_left(right_half, shift)

        combined_key = left_half + right_half
        subkey = permute(combined_key, PC2)
        subkeys.append(subkey)

    return subkeys


if __name__ == "__main__":
    initial_key = '0001001100110100010101110111100110011011101111001101111111110001'
    print("Initial Key: ", initial_key)

    subkeys = generate_subkeys(initial_key)

    for i, subkey in enumerate(subkeys):
        print(f"Subkey {i + 1}: {subkey}")