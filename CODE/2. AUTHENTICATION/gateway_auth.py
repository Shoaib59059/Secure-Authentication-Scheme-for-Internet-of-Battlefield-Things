
import socket
import threading
import ecdsa
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

curve = ecdsa.NIST256p
print("p-- ", curve.order)
message_to_device_1 = "mmmm" 
IDi = "abc"
IDg = "def"
IDj = "ghi"

Si = "secret of user"
# Si = 6200159426
Sj = "secret of device"

Ki = "xyz"



M = "mmm"
PD = "pd"
NGj = "ngj"
Cj = 'cj'
R = "r"


def generate_ecc_keys_bytes():
    # Generate private key
    private_key = ecdsa.SigningKey.generate(curve=curve)

    # Generate public key from private key
    public_key = private_key.verifying_key

    # Convert keys to bytes
    private_key_bytes = private_key.to_string()
    public_key_bytes = public_key.to_string()

    return private_key_bytes, public_key_bytes

# Function to generate symmetric key
def generate_symmetric_key():
    return secrets.token_bytes(16) 

def handle_user_connection(user_socket):
    
    try:

        TDi = user_socket.recv(32)
        TDg = user_socket.recv(32)
        TDj = user_socket.recv(32)
        Ni = user_socket.recv(16)
        Ci = user_socket.recv(32)
        Ki = user_socket.recv(32)
        KUiG = user_socket.recv(16)

        print("TDi recv: ", TDi)
        print("TDg recv: ", TDg)
        print("TDj recv: ", TDj)
        print("Ni recv: ", Ni.hex())
        print("Ci recv: ", Ci)
        print("Ki recv: ", Ki)
        print("KUiG recv: ", KUiG.hex())



        # Si = bytes(a ^ b for a, b in zip(NGi, Ni))
        from random import randint
        p = curve.order
        # R = randint(6200159427, 9999999999)
        global R
        R = secrets.token_bytes(16)
        # Si = 6200159426


        # SGi = (int.from_bytes(Si.encode(), 'big') + 2 * int.from_bytes(R, 'big')) % curve.order


        SGi = (int.from_bytes(Si.encode(), 'big') + 2 * int.from_bytes(R, 'big')) % curve.order

        si = (int.from_bytes(Si.encode(), 'big') + int.from_bytes(R, 'big')) % curve.order

        # p = 80020823

        SGj = (int.from_bytes(Sj.encode(), 'big') + 2 * int.from_bytes(R, 'big')) % curve.order
        sj = (int.from_bytes(Sj.encode(), 'big') + int.from_bytes(R, 'big')) % curve.order
        
        



        
        
        # SGi = (Si + (2 * R)) % p
        # si = (Si + R) % p

        
        testing_Secret_generate_Si = ((2 * si) - SGi) % p

        # chatGPT_secret = (SGi - R) % p
        # chatGPT_secret = (2*SGi - si)
        print("R : ", R)
        print("p : ", p)
        print("SGi : ", SGi)
        print("share(si) : ", si)
        print("Secret(Si) : ", int.from_bytes(Si.encode(), 'big'))
        print("testing secret generation: ", testing_Secret_generate_Si)




        NG = secrets.token_bytes(16)
        global NGj 
        NGj = secrets.token_bytes(16)
        NGi = secrets.token_bytes(16)


        MU = hashlib.md5(Si.encode() + IDi.encode()).hexdigest()
        MD = hashlib.md5(Sj.encode() + IDj.encode()).hexdigest()

        global M
        M = bytes(a ^ b ^ c for a, b, c in zip(MU.encode(), MD.encode(), NG))
        # PU = bytes(a ^ b ^ c for a, b, c in zip(NG, SGi.encode(), IDi.encode()))
        PU = bytes(a ^ b ^ c for a, b, c in zip(NG, SGi.to_bytes((SGi.bit_length() + 7) // 8, byteorder='big'), IDi.encode()))


        
        # # PD = bytes(a ^ b ^ c for a, b, c in zip(NG, SGj, IDj.encode()))
        global PD
        PD = bytes(a ^ b ^ c for a, b, c in zip(NG, SGj.to_bytes((SGj.bit_length() + 7) // 8, byteorder='big'), IDj.encode()))

        hash_device = hashlib.md5(M + PD + NGj + IDj.encode()).hexdigest()

        global Cj
        # # Cj = bytes(a ^ b for a, b in zip(hash_device, SGj))
        Cj = bytes(a ^ b for a, b in zip(hash_device.encode(), SGj.to_bytes((SGj.bit_length() + 7) // 8, byteorder='big')))


        hash_user = hashlib.md5(M + PU + NGi + IDi.encode()).hexdigest()
        # # Ci = bytes(a ^ b for a, b in zip(hash_user, SGi))
        Ci = bytes(a ^ b for a, b in zip(hash_user.encode(), SGi.to_bytes((SGi.bit_length() + 7) // 8, byteorder='big')))

        SGi_computed = bytes(a ^ b for a, b in zip(Ci, hash_user.encode()))
        Ci_XOR_SGi = bytes(a ^ b for a, b in zip(Ci, SGi_computed))

        print("\n------------GATEWAY----------")
        print("M : ", M.hex())
        print("PU : ", PU.hex())
        print("NGi : ", NGi.hex())
        print("Ci : ", Ci.hex())
        print("Hash user: ", hash_user)
        print("SGi: ", SGi)
        print("SGi_computed (Ci XOR hash_user): ", SGi_computed.hex())
        print("Ci_XOR_SGi : ", Ci_XOR_SGi)



        
        print("PD : ", PD)
       
        print("Cj : ", Cj)
        
        print("NGj ", NGj)
        
        # message_to_user_1 = f'<{M.hex()},{PU.hex()},{NGi.hex()},{Ci.hex()},{R.hex()}>'
        # user_socket.send(message_to_user_1.encode())

        user_socket.send(M)
        user_socket.send(PU)
        user_socket.send(NGi)
        user_socket.send(Ci)
        user_socket.send(R)

        user_socket.close()

        













    except ConnectionResetError:
        print("Connection closed by the remote host.")
    finally:
        # Close the connection
        user_socket.close()





def handle_device_connection(device_socket):

    # global message_to_device_1    
    # print("Sending message to device: ", message_to_device_1)
    # device_socket.send(message_to_device_1.encode())

    global M
    device_socket.send(M)
    global PD
    device_socket.send(PD)
    global NGj 
    device_socket.send(NGj)
    global Cj
    device_socket.send(Cj)
    global R
    device_socket.send(R)
    
    print("----- DEVICE HANDLER -----")
    print("M : ", M)

    print("PD : ", PD)
    print("NGj ", NGj)
    
    print("Cj : ", Cj)
    print("R: ", R)
    
    

    # global R
    # print("R : ", R.hex())
    # message_to_device_2 = f'{Nj.hex()},{R.hex()}'
    # device_socket.send(message_to_device_2.encode())


    device_socket.close()



user_gateway_address = ('localhost', 12345)
device_gateway_address = ('localhost', 12346)

# Create sockets for user and device connections
user_gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
device_gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind sockets to their respective addresses and ports
user_gateway_socket.bind(user_gateway_address)
device_gateway_socket.bind(device_gateway_address)

# Listen for connections
user_gateway_socket.listen(5)
device_gateway_socket.listen(5)

print("Gateway is listening for connections...")

# Function to accept user connections
def accept_user_connections():
    while True:
        user_socket, user_address = user_gateway_socket.accept()
        user_thread = threading.Thread(target=handle_user_connection, args=(user_socket,))
        user_thread.start()

# Function to accept device connections
def accept_device_connections():
    while True:
        device_socket, device_address = device_gateway_socket.accept()
        device_thread = threading.Thread(target=handle_device_connection, args=(device_socket,))
        device_thread.start()

# Start threads for accepting user and device connections
user_accept_thread = threading.Thread(target=accept_user_connections)
device_accept_thread = threading.Thread(target=accept_device_connections)

# Start the threads
user_accept_thread.start()
device_accept_thread.start()

