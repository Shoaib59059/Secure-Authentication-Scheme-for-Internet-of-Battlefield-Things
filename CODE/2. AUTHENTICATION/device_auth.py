
import socket
import ecdsa
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time

gateway_address = ('localhost', 12346)
device_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
device_socket.connect(gateway_address)

curve = ecdsa.NIST256p

IDj = "ghi"
Sj = "secret of device"

# var2 = "message_to_device_1"
# device_socket.send(var2.encode())
# print("data sent from device to gateway")

# message_from_gateway_1 = device_socket.recv(1024).decode()
# print("message from gateway 1 : ",message_from_gateway_1)
# M_hex, PD_hex, NGj_hex, Cj_hex = message_from_gateway_1.strip('<>').split(',')

M = device_socket.recv(32)
PD = device_socket.recv(3)
NGj = device_socket.recv(32)
Cj = device_socket.recv(32)
R = device_socket.recv(32)

print("M : ", M.hex())
print("PD : ", PD.hex())
print("NGj : ", NGj.hex())
print("Cj : ", Cj.hex())

hash_device = hashlib.md5(M + PD + NGj + IDj.encode()).hexdigest()
SGj = bytes(a ^ b for a, b in zip(Cj, hash_device.encode()))#, SGi.to_bytes((SGi.bit_length() + 7) // 8, byteorder='big')))
Cj_XOR_SGj = bytes(a ^ b for a, b in zip(Cj, SGj))

print("SGj : ", SGj)

# print("Cj_XOR_SGj : ", Cj_XOR_SGj)
# print("hash_device: ", hash_device)

# if(Cj_XOR_SGj == hash_device):
#     print("\nINTEGRITY OF THE MESSAGE VERIFIED")
# else:
#     print("\nIntegrity verification FAILED")

# SECRET GENERATION
sj = (int.from_bytes(Sj.encode(), 'big') + int.from_bytes(R, 'big')) % curve.order
Secret_generated = ((2 * sj) - int.from_bytes(SGj, 'big')) % curve.order
print("Secret Generated: ", Secret_generated)
print("Si : ", int.from_bytes(Sj.encode(), 'big'))

if(int.from_bytes(Sj.encode(), 'big') == Secret_generated):
    print("SECRET SUCCESSFULLY VERIFIED")
else:
    print("WRONG SECRET")


Vj = hashlib.md5(Sj.encode() + IDj.encode()).hexdigest()
NG = bytes(a ^ b ^ c for a, b, c in zip(PD, SGj, IDj.encode()))

Vi = bytes(a ^ b ^ c for a, b, c in zip(M, Vj.encode(), NG))
KS = hashlib.md5(Vi + NG + Vj.encode()).digest()
print("Vi = ", Vi)
print("NG = ", NG)
print("Vj = ", Vj)
specific_bytes = Vj[0:3]
print("specific_byte - Vj",specific_bytes)
KS_new = hashlib.md5(Vi + NG + specific_bytes.encode()).digest()
# print("Vj hex: ", Vj)
# print("Session key (KS) on the DEVICE side:", KS.hex())




# print("\n\nVi.encode : ", Vi)
# print("NG : ", NG)
# print("specific_bytes.encode - vj: ", specific_bytes.encode())

print("Session key (KS) on the DEVICE side:", KS_new.hex())


device_socket.close()