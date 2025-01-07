import socket
import threading
import ecdsa
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

curve = ecdsa.NIST256p
message_to_device_1 = "mmmm" 
IDi = "abc"
IDg = "def"
Ki = "xyz"




# # Function to generate ECC keys
# def generate_ecc_keys():
#     # Generate private key
#     private_key = ecdsa.SigningKey.generate(curve=curve)

#     # Generate public key from private key
#     public_key = private_key.verifying_key

#     return private_key, public_key


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
    return secrets.token_bytes(16)  # Generate a 16-byte (128-bit) random symmetric key





def handle_user_connection(user_socket):
    
    try:

    # Generate ECC keys for the user (KUi = PUBLIC KEY)

        # IDi = "abc"
        # Ki = "def"
        # KUiG = "ghi"
        # Ni = "jkl"

  

        user_private_key, KUi = generate_ecc_keys_bytes()

        # print("KUi : ", KUi.hex())
        # print("KUi type: ", type(KUi))

        gateway_private_key, KG = generate_ecc_keys_bytes()   #  KG = GATEWAY PUBLIC KEY

        # print("KG : ", KG)

        # Generate symmetric key for user-gateway communication
        KUiG = generate_symmetric_key()
        # print("KUiG Type : ", type(KUiG))
        # print("KUiG- Symmetric Key: ", KUiG.hex())

        # Send public key and symmetric key to the user
        user_socket.send(KG)
        user_socket.send(KUi)
        user_socket.send(KUiG)


        # message_from_user_1 = user_socket.recv(1024).decode()
        # Ni, Ci = message_from_user_1.strip('<>').split(',')
        Ni = user_socket.recv(16)
        Ci = user_socket.recv(32).decode()


        
        IDi_bytes = IDi.encode()
        Ki_bytes = Ki.encode()
        IDg_bytes = IDg.encode()
        # print("Ki encode : ", Ki_bytes)
        # print("IDi types: ", type(IDi))
        # print("IDi_bytes types:", type(IDi_bytes))
        # print("Ni types : ", type(Ni))

        Ci_generated = hashlib.md5(IDi_bytes + Ki_bytes + Ni + KUiG).hexdigest()

        # print("IDi : ", IDi)
        # print("Ki : ", Ki)
        # print("Ni : ", Ni)        
        print("Ci received : ", Ci)
        print("Ci generated: ", Ci_generated)


        R = secrets.token_bytes(16)
        NGi = secrets.token_bytes(16)

                # Computing Secret
        Si = bytes(a ^ b for a, b in zip(NGi, Ni))
                # Computing Share
        # print("curve.order type : ", type(curve.order))
        # print("Si type : ", type(Si))
        # print("Ni type : ", type(Ni))
        # print("IDi_bytes type: ", type(IDi_bytes))

        SGi = (int.from_bytes(Si, 'big') + 2 * int.from_bytes(R, 'big')) % curve.order
        
                # for computing M
        first_hash_input = Si + IDi_bytes
        first_hash_result = hashlib.md5(first_hash_input).digest()

        second_hash_input = first_hash_result + Ni
        M = hashlib.md5(second_hash_input).hexdigest()
        # print("M : ", M )
        # print("M type : ", type(M))

            # Compute TDi = hash(IDi + KUi + Ni)
        concat_IDi_KUi_Ni = IDi_bytes + KUi + Ni
        TDi = hashlib.md5(concat_IDi_KUi_Ni).hexdigest() #STRING TYPE

        

        PU1 = bytes(a ^ b ^ c for a, b, c in zip(R, TDi.encode(), KUiG)) # PU1 encrypting R
        PU2 = bytes(a ^ b ^ c for a, b, c in zip(NGi, TDi.encode(), KUiG))

        NG_2 = secrets.token_bytes(16) 

        # print("IDg.encode : ", IDg_bytes)
        # print("KG : ", KG)
        # print("NG_2 : ", NG_2)
        concat_IDg_KG_NG_2 = IDg_bytes + KG + NG_2
        TDg = hashlib.md5(concat_IDg_KG_NG_2).hexdigest()




        Cg =hashlib.md5(TDg.encode() + M.encode() + PU1 + PU2 + NG_2).hexdigest()
        # print("Cg: ", Cg)
        # print("Cg types : ", type(Cg))


                # Store data in GatewayStorage.txt
        with open('GatewayStorage.txt', 'a') as f:
            f.write(f'<{IDi},{hashlib.md5(Si + IDi_bytes).hexdigest()},{SGi}>\n')

        # message_to_user_1 = f'<{M.encode()},{PU1},{PU2},{NG_2},{Cg.encode()}>'
        
        print("\n\nM : ", M)
        print("PU1 : ", PU1)
        print("PU2: ", PU2)
        print("NG_2: ", NG_2)
        print("Cg : ", Cg)
        print("KUiG : ", KUiG)
        print("\nR generated gateway side: ", R)

        print("\nTDi gateway side : ", TDi)
        print("TDi type : ", type(TDi))
        print("TDg : ", TDg)
        print("TDg type : ", type(TDg))

        NGi_computed = bytes(a ^ b ^ c for a, b, c in zip(PU2, TDi.encode(), KUiG))
        print("NGi computed - gateway side: ", NGi_computed)

        print("Si gateway: ", Si) 
        print("Ni gateway: ", Ni)

        print("\nPU2 : ", PU2)
        print("TDi : ", TDi)
        print("KUiG : ", KUiG)
        print("NGi : ", NGi)
        print("M gateway : ", M)
        # user_socket.send(message_to_user_1.encode())
        user_socket.send(M.encode())
        user_socket.send(PU1)
        user_socket.send(PU2)
        user_socket.send(NG_2)
        user_socket.send(Cg.encode())



        # print("sent PU1 = ", PU1.hex())
        # print("sent PU2 = ", PU2.hex())
        # print("sent NGi = ", NGi.hex())
        # print("sent Cg = ", Cg.hex())
        # print("value of R generated: ", R.hex())





        global message_to_device_1
        message_to_device_1 = "zzz"


    except ConnectionResetError:
        print("Connection closed by the remote host.")
    finally:
        # Close the connection
        user_socket.close()


# Function to handle device connections
def handle_device_connection(device_socket):

    global message_to_device_1    
    print("Sending message to device: ", message_to_device_1)
    device_socket.send(message_to_device_1.encode())

    # global Nj
    # print("Nj : ", Nj.hex())
    # global R
    # print("R : ", R.hex())
    # message_to_device_2 = f'{Nj.hex()},{R.hex()}'
    # device_socket.send(message_to_device_2.encode())


    device_socket.close()


# print("globally --> M, PD, NGj, Cj : ", message_to_device_1)
# print("global message to device --> M, PD, NGj, Cj : ", message_to_device_1)

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