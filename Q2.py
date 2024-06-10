# Define the Expansion P-box table
EXPANSION_P_BOX_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

def expand(block, table):
    return ''.join([block[table[i] - 1] for i in range(len(table))])

def expansion_p_box(block):
    return expand(block, EXPANSION_P_BOX_TABLE)

if __name__ == "__main__":
    input_block = '11110000101010101111000010101010'
    print("Input 32-bit Block:     ", input_block)

    expanded_block = expansion_p_box(input_block)
    print("After Expansion P-box:  ", expanded_block)