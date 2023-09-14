""" 
    implements the AES encryption algorithm for 128 bit keys
"""

from BitVector import *
import datetime

sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


inv_sbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


mixer = [["02", "03", "01", "01"], 
         ["01", "02", "03", "01"], 
         ["01", "01", "02", "03"], 
         ["03", "01", "01", "02"]]

inv_mixer = [["0E", "0B", "0D", "09"], 
             ["09", "0E", "0B", "0D"], 
             ["0D", "09", "0E", "0B"], 
             ["0B", "0D", "09", "0E"]]


def transpose_matrix2(matrix):
    """
    Transposes the matrix
    """
    matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0]))]
    return matrix

def transpose_matrix(matrix):
    if not matrix:
        return []
    
    num_rows = len(matrix)
    num_cols = len(matrix[0])
    
    # Create a new matrix with swapped dimensions
    transposed_matrix = [[0 for i in range(num_rows)] for i in range(num_cols)]
    
    # Populate the transposed matrix
    for i in range(num_rows):
        for j in range(num_cols):
            transposed_matrix[j][i] = matrix[i][j]
    
    return transposed_matrix


    
def adjust_key(key):
    """
    Adjusts the key to be 128 bits long
    """
    if len(key) > 16:
        key = key[:16]
    elif len(key) < 16:
        key = key + (16 - len(key)) * ' ' # padding with spaces
        # key = key + (16 - len(key)) * '0' # padding with zeros
    return key

def adjust_key2(key):
    """
    Adjusts the key to be 128/192/256 bits long
    """
    if len(key) > 32:
        key = key[:32]  # making it 256 bits by cutting off the rest
    elif len(key) > 24:
        key = key + (32 - len(key)) * ' ' # making it 256 bits by padding with spaces
    elif len(key) > 16:
        key = key + (24 - len(key)) * ' ' # making it 192 bits by padding with spaces
    elif len(key) < 16:
        key = key + (16 - len(key)) * ' ' # making it 128 bits by padding with spaces

    return key



def convert_to_hex(text):
    """
    Converts the text to hex
    """
    hex_text = ''
    for i in text:
        hex_text += hex(ord(i))[2:]
    return hex_text

def convert_from_hex(hex):
    """
    Converts from hex to text
    """
    text = ''
    for i in range(0, len(hex), 2):
        text += chr(int(hex[i:i+2], 16))
    return text



def get_words(key):
    """
    Converts the key to a list of 32 bit words
    """
    words = []
    for i in range(0, len(key), 8):
        words.append(key[i:i+8])
    return words

#print(get_words(convert_to_hex(adjust_key("Thats my Kung Fu")))) -> ['54686174', '73206d79', '204b756e', '67204675']


def circular_left_shift(word, shift):
    """
    Performs a shift-bit circular left shift on the word
    """
    return word[shift:] + word[:shift]


def circular_right_shift(word, shift):
    """
    Performs a shift-bit circular right shift on the word
    """
    return word[-shift:] + word[:-shift]



def byte_substitution(word, encrypt):
    """
    Performs a byte substitution on the word
    """
    byte_substituted_values = []
    for i in range(len(word)):
        b = BitVector(hexstring=word[i])   
        int_val = b.intValue()
        if encrypt:
            s = sbox[int_val]   # for encryption
        else:
            s = inv_sbox[int_val]   # for decryption
        s = BitVector(intVal=s, size=8)
        byte_substituted_values.append(s.getHexStringFromBitVector())
    return byte_substituted_values



#print(byte_substitution(['54', '68', '61', '74']))

# for x-or

def xor_hex(hex1, hex2):
    """
    performs x-or between two hexadecimals
    """
    # convert the hexadecimals to binary
    bin1 = bin(int(hex1, 16))[2:]
    bin2 = bin(int(hex2, 16))[2:]

    if len(bin1) > len(bin2):
        bin2 = bin2.zfill(len(bin1))
    else:
        bin1 = bin1.zfill(len(bin2))
    # perform x-or between the binary strings
    bin_result = bin(int(bin1, 2) ^ int(bin2, 2))[2:]

    hex_result = hex(int(bin_result, 2))[2:]
    return hex_result.zfill(len(hex1))


def xor_two_str(a,b):
    """
    performs x-or between two strings
    """
    xored = []
    for i in range(max(len(a), len(b))):
        xored_value = xor_hex(a[i%len(a)], b[i%len(b)])
        xored.append(xored_value)
    return ''.join(xored)


def  xor_words(word1, word2):
    """
    performs x-or between two words, eg ["54", "68", "61", "74"] x-or ["B6", "5A", "9D", "85"]
    """
    xored = []
    for i in range(len(word1)):
        xored_value = xor_two_str(word1[i], word2[i])
        xored.append(xored_value)
    return xored


# adding round constant

round_element_0 = ["01", "01", "02", "04", "08", "10", "20", "40", "80",  "1B", "36"]


def get_round_constant(round):
    """
    returns the round constant
    """
    const = []
    const.append(round_element_0[round])
    const.append("00")
    const.append("00")
    const.append("00")
    return const

 
def add_round_constant(word, round):
    """
    Adds the round constant
    """
    return xor_words(word, get_round_constant(round))


def get_g(word, round, encrypt):
    """
    returns the g value of the word
    """
    word = circular_left_shift(word, 1)
    word = byte_substitution(word, encrypt)
    word = add_round_constant(word, round)
    return word


#print(get_g(["67", "20", "46", "75"]))

# getting round keys
def get_round_keys(prev_key, round, encrypt):
    """
    returns the next round key based on previous round key
    """
    round_keys = []
    if(round == 0):
        return prev_key
    for i in range(4):
        if i == 0:
            round_keys.append(xor_words(prev_key[i], get_g(prev_key[3], round, encrypt)))
        else:
            round_keys.append(xor_words(round_keys[i-1], prev_key[i]))
    return round_keys


def get_round_key_matrix(prev_key, round, encrypt):
    """
    returns the round key matrix
    """
    
    return transpose_matrix(get_round_keys(prev_key, round, encrypt))

#print(get_round_key_matrix([["54", "68", "61", "74"], ["73", "20", "6D", "79"], ["20", "4B", "75", "6E"], ["67", "20", "46", "75"]], 1))


# text

def handle_text(text):
    """
    Handles the text
    """
    #text = text.replace(' ', '')
    text = text.replace('\n', "*-_") #h
    return text

def adjust_text(text):
    """
    splits the text into chunks of 128 bits and adjusts the last chunk if necessary
    """
    chunks = []
    for i in range(0, len(text), 16):
        chunks.append(text[i:i+16])
    if len(chunks[-1]) < 16:
        chunks[-1] = chunks[-1] + (16 - len(chunks[-1])) * '0'
    return chunks


def split_word(word):
    """
    Splits a word into a list of 8 bit words
    """
    words = []
    for i in range(0, len(word), 2):
        words.append(word[i:i+2])
    return words


def get_text_state_matrix(text):
    """
    Gets the 2D state matrix of the text in column major order
    """
    text_state_matrix = [ [ 0 for i in range(4) ] for j in range(4) ]
    arr = get_words(convert_to_hex(text))
    #for i in range(len(arr)):  text_state_matrix.append([[]])
    for i in range(len(arr)):
        splitted_word = split_word(arr[i])
        for j in range(len(splitted_word)):
            # print(i, j)
            #text_state_matrix[i].append(splitted_word[j])
            text_state_matrix[i][j] = (splitted_word[j])

    return transpose_matrix(text_state_matrix)



#print(get_text_state_matrix(text))

# encryption steps

# step 1: substitute bytes
def substitute_bytes(state_matrix, encrypt):
    """
    substitutes the bytes in the state matrix
    """
    for i in range(len(state_matrix)):
        state_matrix[i] = byte_substitution(state_matrix[i], encrypt)
    return state_matrix


# step 2: shift rows
def shift_rows(state_matrix):
    """
    shifts the rows in the state matrix
    """
    for i in range(len(state_matrix)):
        state_matrix[i] = circular_left_shift(state_matrix[i], i)
    return state_matrix

# step 3: mix columns

def multiply(string1, string2):
    AES_modulus = BitVector(bitstring='100011011')
    bv1 = BitVector(hexstring=string1)
    bv2 = BitVector(hexstring=string2)
    bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)

    return bv3.getHexStringFromBitVector()


def mix_columns(state_matrix):
    """
    mixes the columns in the state matrix
    """
    result = []
    for i in range(len(mixer)):
        result.append([])
        for j in range(len(state_matrix[0])):
            result[i].append("00")
            for k in range(len(state_matrix)):
                result[i][j] = xor_hex(result[i][j], multiply(mixer[i][k], state_matrix[k][j]))
    return result

# step 4: add round key
def add_round_key(state_matrix, round_key_matrix):
    """
    Adds the round key
    """
    for i in range(len(state_matrix)):
        state_matrix[i] = xor_words(state_matrix[i], round_key_matrix[i])
    return state_matrix


# encryption
def encrypt(key, text, round_keys):
    """
    Encrypts the text
    """
    #text = adjust_text(handle_text(text))
    state_matrix = get_text_state_matrix(text)
    #key = adjust_key(key)

    # round 0
    state_matrix = add_round_key(state_matrix, round_keys[0])
    #print(0, state_matrix)

    # round 1-10
    for i in range(1, len(round_keys)):
        state_matrix = substitute_bytes(state_matrix, True)
        #print(i, "sub", state_matrix)
        state_matrix = shift_rows(state_matrix)
        #print(i, "shift", state_matrix)
        #if i != 10:
        if i != len(round_keys) - 1:
            state_matrix = mix_columns(state_matrix)
            #print(i, "mix", state_matrix)
        state_matrix = add_round_key(state_matrix, round_keys[i])
        #print(i, state_matrix)

    return transpose_matrix(state_matrix)

# key scheduling

def key_scheduling(key):
    key = adjust_key(key)
    if len(key) == 32:  rounds = 15
    elif len(key) == 24:  rounds = 13
    else : rounds = 11
    round_keys = []
    round_key_matrix = get_text_state_matrix(key)
    round_keys.append([[]])
    round_keys[0] = round_key_matrix

    for i in range(1, rounds):
        round_key_matrix = get_round_key_matrix(transpose_matrix(round_key_matrix), i, True)
        round_keys.append([[]])
        round_keys[i] = round_key_matrix

    return round_keys


# main encryption function
def encrypt_text(key, text, round_keys):

    text = handle_text(text)
    chunks = adjust_text(text)
    #print(chunks)

    key = adjust_key(key)

    encrypted_chunks = []

    for i in range(len(chunks)):
        encrypted_chunks.append(encrypt(key, chunks[i], round_keys))
    
    return encrypted_chunks

# a function to convert the encrypted chunks to a string
def convert_chunks_to_string(chunks):
    """
    Converts the chunks to a string
    """
    result = ""
    for i in range(len(chunks)):
        for j in range(len(chunks[i])):
            for k in range(len(chunks[i][j])):
                result += chunks[i][j][k]
    return result



# decryption steps

# step 1: inverse shift rows
def inverse_shift_rows(state_matrix):
    """
    inverse shifts the rows in the state matrix
    """
    for i in range(len(state_matrix)):
        state_matrix[i] = circular_right_shift(state_matrix[i], i)
    return state_matrix

# step 2: inverse substitute bytes
def inverse_substitute_bytes(state_matrix):
    """
    inverse substitutes the bytes in the state matrix
    """
    for i in range(len(state_matrix)):
        state_matrix[i] = byte_substitution(state_matrix[i], False)
    return state_matrix

# step 3: add round key
def add_round_key(state_matrix, round_key_matrix):
    """
    Adds the round key
    """
    for i in range(len(state_matrix)):
        state_matrix[i] = xor_words(state_matrix[i], round_key_matrix[i])
    return state_matrix

# step 4: inverse mix columns
def inverse_mix_columns(state_matrix):
    """
    inverse mixes the columns in the state matrix
    """
    result = []
    for i in range(len(inv_mixer)):
        result.append([])
        for j in range(len(state_matrix[0])):
            result[i].append("00")
            for k in range(len(state_matrix)):
                result[i][j] = xor_hex(result[i][j], multiply(inv_mixer[i][k], state_matrix[k][j]))
    return result

# a function that takes the 2D state matrix and returns the text
def get_text_from_state_matrix(state_matrix):
    """
    returns the text from the state matrix
    """
    text = ""
    for i in range(len(state_matrix)):
        for j in range(len(state_matrix[i])):
            text += state_matrix[i][j]
    return convert_from_hex(text)


def decrypt(key, state_matrix, round_keys):
    """
    Decrypts the text
    """
    #text = adjust_text(handle_text(text))
    #state_matrix = get_text_state_matrix(cypher_text)
    key = adjust_key(key)
    state_matrix = transpose_matrix(state_matrix)

    # round 0
    round_key_matrix = round_keys[len(round_keys)-1]
    #print(0, "round", round_key_matrix)
    #print(0, state_matrix)
    state_matrix = add_round_key(state_matrix, round_key_matrix)
    #print(0, state_matrix)

    # round 1-10
    for i in range(1, len(round_keys)):
        state_matrix = inverse_shift_rows(state_matrix)
        #print(i, "shift", state_matrix)
        state_matrix = inverse_substitute_bytes(state_matrix)
        #print(i, "sub", state_matrix)
        round_key_matrix = round_keys[len(round_keys)-1-i]
        #print(i, "round", round_key_matrix)
        state_matrix = add_round_key(state_matrix, round_key_matrix)
        #print(i, state_matrix)
        #if i != 10:
        if i != len(round_keys) - 1:
            state_matrix = inverse_mix_columns(state_matrix)
            #print(i, "mix", state_matrix)
        

    return get_text_from_state_matrix(transpose_matrix(state_matrix))


def decrypt_total(key, encrypted_chunks, round_keys):
    """
    Decrypts the total text
    """
    decrypted_chunks = []
    for i in range(len(encrypted_chunks)):
        decrypted_chunks.append(decrypt(key, encrypted_chunks[i], round_keys))
    # return decrypted_chunks joined but without the trailing 0s
    
    padded_text = "".join(decrypted_chunks)
    padded_text = padded_text.replace("*-_","\n") #h
    return padded_text.rstrip("0")



# main function
if __name__ == "__main__":
    
    f = open("text.txt", "r")
    text = f.read()
    f.close()

    key = input("Enter key: ")

    key = adjust_key(key)

    print("Plain text:")
    print("In ASCII:", text)
    print("In hex:", convert_to_hex(text)) 

    print("Key:")
    print("In ASCII:", key)
    print("In hex:", convert_to_hex(key))

    # key scheduling and timing
    time_before = datetime.datetime.now()
    round_keys = key_scheduling(key)
    time_after = datetime.datetime.now()
    scheduling_time = time_after - time_before


    # encryption and timing
    time_before = datetime.datetime.now()
    encrypted_chunks = encrypt_text(key, text, round_keys)
    time_after = datetime.datetime.now()
    encryption_time = time_after - time_before

    encrypted_text = convert_chunks_to_string(encrypted_chunks)
    
    print("Cipher text:")
    print("In hex:", encrypted_text)
    print("In ASCII:", convert_from_hex(encrypted_text))

    # decryption and timing
    time_before = datetime.datetime.now()
    decrypted_text = decrypt_total(key, encrypted_chunks, round_keys)
    time_after = datetime.datetime.now()
    decryption_time = time_after - time_before

    print("Decrypted text:")
    print("In hex:", convert_to_hex(decrypted_text))
    print("In ASCII:", decrypted_text)

    print("Execution time:")
    print("Key scheduling:", scheduling_time.total_seconds() * 100000, " microseconds, ", scheduling_time.total_seconds() * 1000.0, " milliseconds")
    print("Encryption:", encryption_time.total_seconds() * 100000, " microseconds, ", encryption_time.total_seconds() * 1000.0, " milliseconds")
    print("Decryption:", decryption_time.total_seconds() * 100000, " microseconds, ", decryption_time.total_seconds() * 1000.0, " milliseconds")
