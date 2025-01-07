import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



# Common session key 

# KS_new_str = str(KS_new.hex())
# with open("Session_Key.txt", "w") as f:
#     f.write(KS_new_str)

with open("Session_Key.txt", "r") as f:
    session_key = f.read()

print("DEVICE - SECRET KEY RETRIEVE: ", session_key)

# session_key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
session_key = session_key.encode()
# Encryption function
def encrypt(message):
    cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + b'\x00' * (16 - len(message) % 16)  # Padding if necessary
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return ciphertext

# Decryption function
def decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.rstrip(b'\x00')  # Remove padding

def main():
    HOST = 'localhost'
    PORT = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)

            # Receiving message
            ciphertext = conn.recv(1024)  # Adjust buffer size as needed
            decrypted_message = decrypt(ciphertext)
            print("Received from user:", decrypted_message.decode())

            # Sending message
            message_to_send = b'Hello, user!'
            encrypted_message = encrypt(message_to_send)
            conn.sendall(encrypted_message)

if __name__ == "__main__":
    main()
