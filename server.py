import socket

def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(plaintext)])

def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(ciphertext)])

key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08"

HOST = '0.0.0.0'
PORT = 1337

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind((HOST, PORT))

server_sock.listen()

client_sock, client_address = server_sock.accept()
print(f'Connected to {client_address[0]}:{client_address[1]}')

while True:
    # Receive a message from the client
    message = client_sock.recv(8192)
    if not message:
        break

    # Decrypt the message
    decrypted = xor_decrypt(message, key)
    decrypted = decrypted.decode()
    print(f'Received: {decrypted}')

    # Encrypt the response
    response = input('Enter a response: ')
    encrypted = xor_encrypt(response.encode(), key)
    print(f'Sent: {response}')
    client_sock.send(encrypted)

client_sock.close()
server_sock.close()
