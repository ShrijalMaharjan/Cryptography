S_BOX_1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

def s_box_lookup(s_box, input_bits):
    row = int(input_bits[0] + input_bits[5], 2)
    col = int(input_bits[1:5], 2)
    return s_box[row][col]

def s_box_substitution(s_box, input_bits):
    return format(s_box_lookup(s_box, input_bits), '04b')

if __name__ == "__main__":

    input_bits = '110011'
    print("Input 6-bit Block: ", input_bits)

    output_bits = s_box_substitution(S_BOX_1, input_bits)
    print("After S-box 1 Substitution: ", output_bits)