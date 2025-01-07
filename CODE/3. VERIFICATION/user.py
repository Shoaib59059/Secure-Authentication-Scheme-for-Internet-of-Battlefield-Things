import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Common session key (replace this with your actual session key)

with open("Session_Key.txt", "r") as f:
    session_key = f.read()
print("USER - SECRET KEY RETRIEVE: ", session_key)

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
        s.connect((HOST, PORT))

        # Sending message
        message_to_send = b'Hello, device!'
        encrypted_message = encrypt(message_to_send)
        s.sendall(encrypted_message)

        # Receiving message
        ciphertext = s.recv(1024)  # Adjust buffer size as needed
        decrypted_message = decrypt(ciphertext)
        print("Received from device:", decrypted_message.decode())

if __name__ == "__main__":
    main()












