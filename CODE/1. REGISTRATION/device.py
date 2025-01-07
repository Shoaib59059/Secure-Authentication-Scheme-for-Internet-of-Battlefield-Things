
import socket
import ecdsa
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


gateway_address = ('localhost', 12346)
device_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
device_socket.connect(gateway_address)


# var2 = "message_to_device_1"
# device_socket.send(var2.encode())
# print("data sent from device to gateway")

message_from_gateway_1 = device_socket.recv(1024).decode()
print("message from gateway 1 : ",message_from_gateway_1)
# M_hex, PD_hex, NGj_hex, Cj_hex = message_from_gateway_1.strip('<>').split(',')

device_socket.close()