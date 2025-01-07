from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import hashlib
import secrets


IDi = "abc"
IDg = "def"
IDi_bytes = IDi.encode()
Ni = secrets.token_bytes(16)

print("type of Ni : ", type(Ni))
Ki = "xyz"
# KUiG = "ghi"
# Ni = "jkl"


gateway_address = ('localhost', 12345)
user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
user_socket.connect(gateway_address)
# user_socket.send(Ci.encode())

KG = user_socket.recv(64)
# print("KG : ", KG)
# print("KG - type: ", type(KG))

KUi = user_socket.recv(64).strip() 
print("KUi - received : ", KUi.hex())
# print("KUi - type: ", type(KUi))


# Receive symmetric key from the gateway
KUiG = user_socket.recv(16).strip()  # Symmetric key is 16 bytes
print("KUiG type: ", type(KUiG))
print("KUiG - Symmetric Key (received): ", KUiG.hex())


Ci= hashlib.md5(IDi.encode() + Ki.encode() + Ni + KUiG).hexdigest()





# WE are NOT sending {IDi, Ki} encoded with KUiG because of ENCODING PADDING ISSUE
user_socket.send(Ni)
user_socket.send(Ci.encode())



print("IDi : ", IDi)
print("Ki : ", Ki)
print("Ni : ", Ni)
print("Ci : ", Ci)


M_received = user_socket.recv(32)
PU1 = user_socket.recv(32)
PU2 = user_socket.recv(32)
NG_2 = user_socket.recv(16)
Cg = user_socket.recv(32)

print("\n\nM : ", M_received)
print("PU1 : ", PU1)
print("PU2: ", PU2)
print("NG_2: ", NG_2)
print("Cg : ", Cg)
print("KUiG : ", KUiG)


            # Compute TDi = hash(IDi + KUi + Ni)
concat_IDi_KUi_Ni = IDi_bytes + KUi + Ni
TDi = hashlib.md5(concat_IDi_KUi_Ni).hexdigest() #STRING TYPE
print("\nTDi user side : ", TDi )
print("TDi type: ", type(TDi))

# Since PU2 = NGi
# print("Ni type : ", type(Ni))
# print("PU2 type : ", type(PU2))



concat_IDg_KG_NG_2 = IDg.encode() + KG + NG_2
TDg = hashlib.md5(concat_IDg_KG_NG_2).hexdigest()
print("TDg : ", TDg)
print("TDg type : ", type(TDg))

import ecdsa
curve = ecdsa.NIST256p

R_computed = bytes(a ^ b ^ c for a, b, c in zip(PU1, TDi.encode(), KUiG))
# R_int = int.from_bytes(R_computed, 'big')
NGi_computed = bytes(a ^ b ^ c for a, b, c in zip(PU2, TDi.encode(), KUiG))

Si = bytes(a ^ b for a, b in zip(NGi_computed, Ni)) 

si = (int.from_bytes(Si, 'big') + int.from_bytes(R_computed, 'big')) % curve.order

print("\nPU2 : ", PU2)
print("TDi : ", TDi)
print("KUiG : ", KUiG)
print("\nR computed : ", R_computed)
print("NGi_computed: ",NGi_computed)

print("Ni user: ", Ni)

first_hash_input = Si + IDi_bytes
first_hash_result = hashlib.md5(first_hash_input).digest()
second_hash_input = first_hash_result + Ni
M_generated = hashlib.md5(second_hash_input).hexdigest()
print("M generated  : ", M_generated)


if M_received == M_generated.encode():
    print("\nM received matches M generated.")
else:
    print("\nM received doesn't match M generated.")

# Store data in UserStorage.txt
with open('UserStorage.txt', 'a') as f:
    f.write(f'<{IDi},{IDg},{hashlib.md5(Si + IDg.encode()).hexdigest()},{si}>\n')



#-------------------AUTHENTICATION----------------------------



# SGi = (int.from_bytes(Si, 'big') + 2 * int.from_bytes(R_computed, 'big')) % curve.order
# SGi_bytes = SGi.to_bytes((SGi.bit_length() + 7) // 8, byteorder='big')

# print("\nSi --> Secret : ", Si)
# secret_computed_from_shares = (SGi_bytes - int.from_bytes(R_computed, 'big')) % curve.order
# print("secret computed from share : ", secret_computed_from_shares)
user_socket.close()