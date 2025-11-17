import random
import string

IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

Exp = [
        32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1   
    ]

S_box = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    ]
]

P_box = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
]

inverse = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
]

pc1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
]

pc2 = [
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
]

SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(data_bit_str, permute_table):
    result = ""
    for p in permute_table:
        result += data_bit_str[p-1]
    return result

def shift_left(data_bit_str, total_shift):
    return data_bit_str[total_shift:] + data_bit_str[:total_shift]

def XOR(str1, str2):
    return ''.join('0' if a==b else '1' for a,b in zip(str1,str2))

def decToBinary(n):
    return bin(n)[2::].zfill(4)

def hexToInt(hex_str):
    return int(hex_str, 16)

def hexToBin(hex_str):
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    bin_str = bin(int(hex_str, 16))[2:]
    bin_str = bin_str.zfill(len(hex_str) * 4)
    return bin_str

def splitBlocks(bin_str):
    blocks = []
    for i in range(0, len(bin_str), 64):
        blocks.append(bin_str[i:i+64])
    return blocks


def binToASCII(bin_str):
    out = []
    for i in range(0, len(bin_str), 8):
        chunk = bin_str[i:i+8]
        if len(chunk) < 8:
            break
        out.append(chr(int(chunk, 2)))
    return ''.join(out)

def ASCIItoBin(str):
    return ''.join(format(ord(char), '08b') for char in str)

def addPadding(bin_str):
    if len(bin_str) % 8 != 0:
        bin_str = bin_str.ljust(((len(bin_str)//8)+1)*8, '0')

    block_bytes = 8 
    curr_bytes = len(bin_str) // 8
    pad_len = block_bytes - (curr_bytes % block_bytes)
    if pad_len == 0:
        pad_len = block_bytes

    pad_byte = format(pad_len, '08b')
    padded = bin_str + pad_byte * pad_len
    return padded

def removePadding(padded_bin_str):
    if len(padded_bin_str) < 8:
        return padded_bin_str 

    last_byte = padded_bin_str[-8:]
    pad_len = int(last_byte, 2)

    if pad_len < 1 or pad_len > 8:
        return padded_bin_str

    expected_padding = last_byte * pad_len
    if padded_bin_str[-8*pad_len:] != expected_padding:
        return padded_bin_str

    return padded_bin_str[:-8*pad_len]

def generateRandomKey():
    hex_characters = '0123456789ABCDEF'
    return ''.join(random.choice(hex_characters) for _ in range(16))

class des():
    @staticmethod
    def keySchedule(binary_64bit_master_key):
        key_56bit = permute(binary_64bit_master_key, pc1)
        
        left_c = key_56bit[0:28]
        right_d = key_56bit[28:56]
        
        round_keys = []
        
        for i in range (16):
            total_shift = SHIFT_TABLE[i]
            left_c = shift_left(left_c, total_shift)
            right_d = shift_left(right_d, total_shift)
            
            key_comb = left_c + right_d
            key_round = permute(key_comb, pc2)
            
            round_keys.append(key_round)
            
        return round_keys

    @staticmethod
    def feistel(right_block, key_round):
        expanded_block = permute(right_block, Exp)
        xor_result = XOR(expanded_block, key_round)
        
        result_sbox = ""
        for i in range (8):
            block_6bit = xor_result[i*6 : i*6 + 6]
            
            row_bit = block_6bit[0] + block_6bit[5]
            row = int(row_bit, 2)
            
            column_bit = block_6bit[1:5]
            column = int(column_bit, 2)
            
            index = row * 16 + column
            sbox = S_box[i][index]
            
            result_sbox += decToBinary(sbox)
            
        final_res = permute(result_sbox, P_box)
        return final_res
        
    @staticmethod
    def encrypt(pt, round_keys):
        permuted_block = permute(pt, IP)
        
        left_c = permuted_block[0:32]
        right_d = permuted_block[32:64]
        
        for i in range (16):
            L_prev = left_c
            left_c = right_d
            f_res = des.feistel(right_d, round_keys[i])
            
            right_d = XOR(L_prev, f_res)
        
        final = right_d + left_c 
        cipher = permute(final, inverse)
        return cipher
    
    @staticmethod
    def decrypt(ct, round_keys):
        reversed_key = round_keys[:]
        reversed_key.reverse()
        
        pt = des.encrypt(ct, reversed_key)
        return pt