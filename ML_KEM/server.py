import socket
import pickle
from pqcrypto.kem.ml_kem_512 import generate_keypair, decrypt
from Cryptodome.Cipher import AES

HOST = '0.0.0.0'
PORT = 5000

# ===== Hàm nhận 1 packet =====

import struct

def recv_packet(sock):
    # nhận 4 byte độ dài
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    length = struct.unpack("!I", raw_len)[0]

    # nhận đúng số byte
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            break
        data += packet

    return pickle.loads(data)
# ===== ML-KEM key =====
pk, sk = generate_keypair()

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("Server listening...")

conn, addr = server.accept()
print("Connected:", addr)

# ===== gửi pk =====
conn.sendall(pickle.dumps(pk))

# ===== nhận ciphertext =====
ciphertext = recv_packet(conn)

# ===== decaps =====
shared_key = decrypt(sk, ciphertext)
print("Shared key (server):", shared_key.hex())

# ===== nhận AES =====
nonce, cipher_aes, tag = recv_packet(conn)

# ===== decrypt AES =====
key = shared_key[:16]
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(cipher_aes)

print("Decrypted message:", plaintext)

conn.close()
server.close()
