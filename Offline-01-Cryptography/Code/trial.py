import datetime
#print(now.time())

import random
import aes_1805040 as aes

N = 1000000007


print(aes.get_words(aes.convert_to_hex(aes.adjust_key("Thats my Kung Fu"))))

print(aes.get_text_state_matrix("Thats my Kung Fu"))

# declare a mXn matrix
def declare_matrix(m, n):
    return [ [ 0 for i in range(n) ] for j in range(m) ]