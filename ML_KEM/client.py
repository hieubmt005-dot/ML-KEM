import socket
import pickle
import struct
from pqcrypto.kem.ml_kem_512 import encrypt
from Cryptodome.Cipher import AES

SERVER_IP = '192.168.1.6'
PORT = 5000

# ===== gửi packet chuẩn =====
def send_packet(sock, data):
    raw = pickle.dumps(data)
    sock.sendall(struct.pack("!I", len(raw)))  # gửi length
    sock.sendall(raw)

client = socket.socket()
client.connect((SERVER_IP, PORT))

# nhận public key
data = client.recv(4096)
pk = pickle.loads(data)

# ===== ML-KEM =====
ciphertext, shared_key = encrypt(pk)

# ===== AES =====
key = shared_key[:16]
cipher = AES.new(key, AES.MODE_EAX)

plaintext = b"Hello FPGA"
cipher_aes, tag = cipher.encrypt_and_digest(plaintext)
nonce = cipher.nonce

# ===== GỬI ĐÚNG FORMAT =====
send_packet(client, ciphertext)
send_packet(client, (nonce, cipher_aes, tag))

print("Shared key (client):", shared_key.hex())

client.close()
# Xem Public Key nhận từ server
print(f"Public Key (hex): {pk.hex()[:50]}...")

# Xem Ciphertext (kết quả của ML-KEM)
print(f"ML-KEM Ciphertext: {ciphertext.hex()[:50]}...")
