import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import paho.mqtt.client as Client

MQTT_IP="18.100.158.114"
MQTT_USERNAME="sinf"
MQTT_PASSWD="HkxNtvLB3GC5GQRUWfsA"
topic = "tuID"


def read_public_key (file):
    PB_PATH = os.path("pubkeys.py")

    with open(file, "rb") as key_file:    
        pb_key = key_file.read()
        pba_key = serialization.load_ssh_public_key(
            pb_key,
            backend=default_backend()
        )

    

def read_private_key():
    pr_path = os.path("") # Aquí va el archivo de clave privada

    with open(pr_path, "rb") as key_file:    
        pr_key = key_file.read()
        pra_key = serialization.load_ssh_private_key(
            pr_key,
            password=None,
            backend=default_backend()
        )
    
    return pra_key


def input ():

    usuarios = [item for item in input(f"Introduce los IDs de los usuarios (separados por comas): ").split(',')]
    message = input(f"Introduce el mensaje a enviar: ")

    n = len (usuarios)
    for i in range (n-1,1):
        nested_encrypt(message)

# Encriptación en RSA (clave pública -> criptografía asimétrica)
def rsa_encrypt(pk, k) -> bytes:
    return pk.encrypt(
    k,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Encriptación en AES
def aes_encrypt(k,data,as_data):
    iv = k 

    encryptor = Cipher(
        algorithms.AES(k),
        modes.GCM(iv),
    ).encryptor()

    encryptor.authenticate_additional_data(as_data)
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)


    
  #  c = rsa_encrypt(pk, k) + aes_encrypt(k, data)


# Desencriptación en RSA (se utiliza clave privada por criptografía asimétrica)
def rsa_decrypt(k,c):
    return k.decrypt(
    c,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ) 
    )

def aes_decrypt(k, data):
    return AESGCM(k).decrypt(k, data, None)

# Procedimiento
def nested_encrypt(pb, message):
    # Coger mensaje recibido
    m = bytes(message, 'utf-8')

    # Encriptar mensaje con cifrado simétrico y concatenar ID de usuario con mensaje
    k = AESGCM.generate_key(bit_length=128)
    mJoin = message[0] + b"|" + message[1]
    c = aes_encrypt (k,mJoin,None)

    # Encripto clave simétrica con clave pública (cifrado asimétrico)
    mRSAEncrypt = rsa_encrypt (pb, k)
    
    # Retornar mensaje completo
    return mRSAEncrypt + bytes(b"|","utf-8") + c


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker!")
        client.subscribe(topic)
    else:
        print("Failed to connect, return code %d\n", rc)
# Set Connecting Client ID
    client.username_pw_set(MQTT_USERNAME,MQTT_PASSWD)
    client.on_connect = on_connect
    client.connect(MQTT_IP)


def subscribe(client: Client):
    def on_message(client, msg):
        compMessage = msg.payload
        private_key = read_private_key()
        decryptM = message.rsa_decrypt(private_key,message)
        msgSplit = decryptM.decode('utf-8').split("|")
        cabecera = msgSplit[0]
        message = msgSplit[1]
        if (cabecera == "end"):
            finalDecr = decryptM.aes_decrypt() 

        else:   
            client.publish(cabecera, message)
    client.subscribe(topic) # El topic es el ID propio
    client.on_message = on_message
        
#if __name__ == '__main__':        