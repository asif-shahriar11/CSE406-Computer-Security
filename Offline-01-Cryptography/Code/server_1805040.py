import socket
import aes_1805040 as aes_1805040
import diffie_hellman_1805040 as dh
import pickle

# ALICE
# create a socket object
serversocket = socket.socket()
print("socket created")

# get local machine name
host = socket.gethostname()
port = 1111

# bind to the port
serversocket.bind((host, port))
print("socket bound to port")

# queue up to 5 requests
serversocket.listen(5)
print("socket is listening")

# establish a connection
while True:

    # establish connection
    clientsocket, addr = serversocket.accept()

    print("got a connection from %s" % str(addr))

    # generate p, g, A by diffie-hellman
    k = 128
    print("generating p, g, A")
    p = dh.generate_safe_prime(k)
    #print(p)
    g = dh.find_primitive_root(p)
    #print(g)
    a = dh.generate_prime(k // 2)
    A = dh.fast_exponentiation(g, a, p)
    #print(A)

    # send p, g, A to BOB
    clientsocket.send(str(p).encode())
    temp = clientsocket.recv(1024).decode()
    if temp == "received p":    clientsocket.send(str(g).encode())
    temp = clientsocket.recv(1024).decode()
    if temp == "received g":    clientsocket.send(str(A).encode())
    temp = clientsocket.recv(1024).decode()
    if temp == "received A":    print("p, g, A sent to BOB")

    # receive B from BOB
    B = clientsocket.recv(1024).decode()
    print("B received from BOB")
    B = int(B)

    # compute s
    s = str(dh.fast_exponentiation(B, a, p))

    # read the text from text.txt
    f = open("text.txt", "r")
    text = f.read()
    f.close()

    # inform BOB that ready to transmit
    clientsocket.send("ready to transmit".encode())

    # encrypt the message using AES
    key = aes_1805040.adjust_key(s)
    round_keys = aes_1805040.key_scheduling(key)
    encrypted_chunks = aes_1805040.encrypt_text(key, text, round_keys)
    cypher_text = aes_1805040.convert_chunks_to_string(encrypted_chunks)

    print("encrypted text: ", cypher_text)

    data=pickle.dumps(encrypted_chunks)

    # send the encrypted message to BOB
    #clientsocket.send(cypher_text.encode())
    clientsocket.send(data)
    print("encrypted text sent to BOB")

    # close the connection
    clientsocket.close()





