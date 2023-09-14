import socket
import aes_1805040 as aes_1805040
import diffie_hellman_1805040 as dh
import pickle

# BOB
# create a socket object
s = socket.socket()
print("socket created")

# get local machine name
host = socket.gethostname()
port = 1111

# connect to the server on local computer
s.connect((host, port))
print("socket connected to server")

# receive p, g, A from ALICE
p = s.recv(1024).decode()
#print("p received from ALICE")
s.send("received p".encode()) 
g = s.recv(1024).decode()
#print("g received from ALICE")
s.send("received g".encode()) 
A = s.recv(1024).decode()
s.send("received A".encode()) 
print("p, g, A received from ALICE")

# convert p, g, A to int
p = int(p)
g = int(g)
A = int(A)

# generate B 
k = 128
b = dh.generate_prime(k // 2)
B = dh.fast_exponentiation(g, b, p)

# send B to ALICE
s.send(str(B).encode())
print("B sent to ALICE")

# compute s
s_key = str(dh.fast_exponentiation(A, b, p))

# receive ready to transmit from ALICE
s.recv(1024).decode()


# receive the message from ALICE
#cypher_text = s.recv(1024).decode()
#rcvd_data = s.recv(4096)
data = []
while True:
    packet = s.recv(4096)
    if not packet: break
    data.append(packet)

encrypted_chunks = pickle.loads(b"".join(data))

print("cyphertext received from ALICE")

# break the message into chunks
#encrypted_chunks = aes.convert_string_to_chunks(cypher_text)


# decrypt the message using AES
key = aes_1805040.adjust_key(s_key)
round_keys = aes_1805040.key_scheduling(key)
#chunks = aes.adjust_text(cypher_text)
#print(chunks)
text = aes_1805040.decrypt_total(key, encrypted_chunks, round_keys)

# print the decrypted message
print("The message received from ALICE is:")
print(text)

# close the connection
s.close()
