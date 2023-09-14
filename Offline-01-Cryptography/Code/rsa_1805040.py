# RSA (Rivest-Shamir-Adleman) algorithm implementation

import random
import datetime
import diffie_hellman_1805040 as dh
import math

# util methods

def extended_gcd(a, b):
    """returns gcd, x, y such that gcd(a, b) = ax + by"""
    if b == 0:
        return a, 1, 0
    else:
        gcd, x, y = extended_gcd(b, a % b)
        t = x - (a // b) * y
        return gcd, y, t
    
def gcd_check():
    """checks if extened_gcd is working"""
    for i in range(1000):
        p = random.randint(0, 100000)
        q = random.randint(0, 100000)
        t, t1, t2 = extended_gcd(p, q)
        if(t != math.gcd(p, q)):
            print("Error", p, q)
            break
    else:
        print("Done")

#gcd_check()

def generate_relative_prime(phi_n):
    """generates a random number e such that gcd(e, phi_n) = 1 ie. e and phi_n are coprime"""
    while True:
        e = random.randrange(2, phi_n)
        gcd, t1, t2 = extended_gcd(e, phi_n)
        if gcd == 1:
            return e

def generate_multiplicative_inverse(e, phi_n):
    """generates d such that d is the multiplicative inverse of e modulo phi_n"""
    gcd, t1, t2 = extended_gcd(e, phi_n)
    if gcd == 1:
        return t1 % phi_n
    

def generate_keys(k):
    """generates n, e, d"""
    p = dh.generate_prime(k // 2)
    q = dh.generate_prime(k // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = generate_relative_prime(phi)
    d = generate_multiplicative_inverse(e, phi)

    return n, e, d


def encrypt_char(char, e, n):
    """encrypts a single character"""
    char = ord(char)
    return dh.fast_exponentiation(char, e, n)


def decrypt_char(encrypted_char, d, n):
    """decrypts a single character"""
    decrypted_val = dh.fast_exponentiation(encrypted_char, d, n)
    return chr(decrypted_val)


def encrypt(text, e, n):
    """encrypts a string"""
    cypher_text = [ encrypt_char(char, e, n) for char in text ]
    return cypher_text


def decrypt(cypher_text, d, n):
    """decrypts a string"""
    plain_text = [ decrypt_char(char, d, n) for char in cypher_text ]
    plain_text = "".join(plain_text)
    return plain_text


# main function
if __name__ == "__main__":

    # read file
    f = open("text.txt", "r")
    text = f.read()
    f.close()

    print("Plain text : ", text)

    # generate keys
    k = 128
    time_before = datetime.datetime.now()
    n, e, d = generate_keys(k)
    time_after = datetime.datetime.now()
    key_time = time_after - time_before
    key_time = key_time.total_seconds() * 100000.0
    

    # encrypt
    time_before = datetime.datetime.now()
    cypher_text = encrypt(text, e, n)
    time_after = datetime.datetime.now()
    encrypt_time = time_after - time_before
    encrypt_time = encrypt_time.total_seconds() * 100000.0
    print("Cypher text : ", cypher_text)


    # decrypt
    time_before = datetime.datetime.now()
    plain_text = decrypt(cypher_text, d, n)
    time_after = datetime.datetime.now()
    deccrypt_time = time_after - time_before
    deccrypt_time = deccrypt_time.total_seconds() * 100000.0
    print("Plain text : ", plain_text)

    # timing
    print("Key generation time : ", key_time, "microseconds,", key_time / 1000.0, "milliseconds")
    print("Encryption time : ", encrypt_time, "microseconds,", encrypt_time / 1000.0, "milliseconds")
    print("Decryption time : ", deccrypt_time, "microseconds,", deccrypt_time / 1000.0, "milliseconds")


