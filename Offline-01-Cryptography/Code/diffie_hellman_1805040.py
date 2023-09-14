# Diffie-Hellman : A key exchange algorithm

import random
import datetime

# utility methods

def fast_exponentiation(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp = exp >> 1
    return result 




def is_prime(n, k):
    """Checks if n is prime using Miller-Rabin primality test."""
    if n <= 1 or n % 2 == 0:    return False
    
    if n == 2 or n == 3:    return True

    # Write (n-1) as 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        r = r + 1
        d = d // 2

    # Miller-Rabin primality test
    for i in range(k):
        a = random.randint(2, n - 2)
        x = fast_exponentiation(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for i in range(r - 1):
            x = fast_exponentiation(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(k):
    """Generates a prime number of k bits"""
    min = 2**(k-1)
    max = 2**k - 1
    iter = 10
    while True:
        n = random.randint(min, max)    # a random integer in the range [min, max]
        if is_prime(n, iter):
            return n
        


# if p is a safe prime, thne both p and (p-1)/2 are primes
# then there are only two possible values for g (ie prime factors of p - 1), 2 and (p - 1)/2
# p is a safe prime if p = 2q + 1, where q is also a prime
# following is a function that returns a safe prime of length k bits
def generate_safe_prime(k):
    """Generate a safe prime number of k bits"""
    iter = 10
    while True:
        q = generate_prime(k-1)
        p = 2 * q + 1
        if is_prime(p, iter):
            return p



def find_primitive_root(p):
    """Finds a primitive root of a prime number p where p is a safe prime"""
    phi = p - 1
    factors = [2, phi // 2]
    while True:
        g = random.randint(2, p - 2)
        for factor in factors:
            if fast_exponentiation(g, factor, p) == 1:
            #if pow(g, factor, p) == 1:
                break # try another g
        else:
            return g
        
#print(find_primitive_root(23))

# Diffie-Hellman key exchange algorithm
def diffie_hellman(k):
    """Diffie-Hellman key exchange algorithm"""

    p = generate_safe_prime(k)
    #print("p = ", p)
    g = find_primitive_root(p)
    #print("g = ", g)
    a = generate_prime(k // 2)
    #print("a = ", a)
    b = generate_prime(k // 2)
    #print("b = ", b)
    A = fast_exponentiation(g, a, p)
    B = fast_exponentiation(g, b, p)
    s1 = fast_exponentiation(B, a, p)
    s2 = fast_exponentiation(A, b, p)
    #print(s1, s2)
    assert s1 == s2
    return s1

# with timing
def diffie_hellman_w_timing(k):
    """Diffie-Hellman key exchange algorithm"""

    time_before = datetime.datetime.now()
    p = generate_safe_prime(k)
    time_after = datetime.datetime.now()
    p_time = time_after - time_before
    p_time = p_time.total_seconds() * 100000.0
    
    time_before = datetime.datetime.now()
    g = find_primitive_root(p)
    time_after = datetime.datetime.now()
    g_time = time_after - time_before
    g_time = g_time.total_seconds() * 100000.0
    
    time_before = datetime.datetime.now()
    a = generate_prime(k // 2)
    time_after = datetime.datetime.now()
    a_time = time_after - time_before
    a_time = a_time.total_seconds() * 100000.0


    time_before = datetime.datetime.now()
    b = generate_prime(k // 2)
    time_after = datetime.datetime.now()
    b_time = time_after - time_before
    b_time = b_time.total_seconds() * 100000.0

    time_before = datetime.datetime.now()
    A = fast_exponentiation(g, a, p)
    time_after = datetime.datetime.now()
    A_time = time_after - time_before
    A_time = A_time.total_seconds() * 100000.0

    time_before = datetime.datetime.now()
    B = fast_exponentiation(g, b, p)
    time_after = datetime.datetime.now()
    B_time = time_after - time_before
    B_time = B_time.total_seconds() * 100000.0

    time_before = datetime.datetime.now()
    s1 = fast_exponentiation(B, a, p)
    time_after = datetime.datetime.now()
    s1_time = time_after - time_before
    s1_time = s1_time.total_seconds() * 100000.0

    time_before = datetime.datetime.now()
    s2 = fast_exponentiation(A, b, p)
    time_after = datetime.datetime.now()
    s2_time = time_after - time_before
    s2_time = s2_time.total_seconds() * 100000.0

    #print(s1, s2)
    assert s1 == s2
    
    # print("report:")
    # print("p = ", p, "time = ", p_time, "microseconds")
    # print("g = ", g, "time = ", g_time, "microseconds")
    # print("a = ", a, "time = ", a_time, "microseconds")
    # print("b = ", b, "time = ", b_time, "microseconds")
    # print("A = ", A, "time = ", A_time, "microseconds")
    # print("B = ", B, "time = ", B_time, "microseconds")
    # print("s1 = ", s1, "time = ", s1_time, "microseconds")
    # print("s2 = ", s2, "time = ", s2_time, "microseconds")
    # print("total time = ", (p_time + g_time + a_time + b_time + A_time + B_time + s1_time + s2_time), "microseconds")

    total_time = p_time + g_time + a_time + b_time + A_time + B_time + s1_time + s2_time

    return p_time, g_time, a_time, b_time, A_time, B_time, s1_time, s2_time, total_time


# main function
if __name__ == "__main__":
    
    keys = [128, 192, 256]

    print("timing report in microseconds:")
    
    for k in keys:
        # run diffie_hellman_w_timing(k) 5 times
        # and take the average of the each timing
        p_time = 0
        g_time = 0
        a_time = 0
        b_time = 0
        A_time = 0
        B_time = 0
        s1_time = 0
        s2_time = 0
        total_time = 0
        for i in range(5):
            p_time_i, g_time_i, a_time_i, b_time_i, A_time_i, B_time_i, s1_time_i, s2_time_i, total_time_i = diffie_hellman_w_timing(k)
            p_time += p_time_i
            g_time += g_time_i
            a_time += a_time_i
            b_time += b_time_i
            A_time += A_time_i
            B_time += B_time_i
            s1_time += s1_time_i
            s2_time += s2_time_i
            total_time += total_time_i

    
        # print report in a tabular format
        print("k =", k, "p =", p_time/5, "g =", g_time/5, "a =", a_time/5, "b =", b_time/5, "A =", A_time/5, "B =", B_time/5, "s1 =", s1_time/5, "s2 =", s2_time/5, "total =", total_time/5)

