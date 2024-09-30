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
from pubkeys import PublicKeys

MQTT_IP="18.100.158.114"
MQTT_USERNAME="sinf"
MQTT_PASSWD="HkxNtvLB3GC5GQRUWfsA"
topic = "nuci"


def read_public_key (file):
    PB_PATH = os.path("")  
     
    with open(file, "rb") as key_file:    
        pb_key = key_file.read()
        pba_key = serialization.load_ssh_public_key(
            pb_key,
            backend=default_backend()
        )

def read_private_key():
    pr_path = os.path.join(os.getcwd(), "clave") 

    with open(pr_path, "rb") as key_file:    
        pr_key = key_file.read()
        password="nuria" 
        pra_key = serialization.load_ssh_private_key(
            pr_key,
            password=password.encode(), 
            backend=default_backend()
        )
    
    return pra_key


def rsa_encrypt(pk, k) -> bytes:
    return pk.encrypt(
    k,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)


def aes_encrypt(k,data,as_data):
    aesgcm = AESGCM(k)
    nonce = k
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return ciphertext

def encrypt (pk, message: bytes):
    k = AESGCM.generate_key(bit_length=128)
    c = rsa_encrypt (pk,k) + aes_encrypt (k,message,None)

    return c


def nested_encrypt(users: list, pks: list, message: bytes):
    m = embed_id(users[0].encode('utf-8'),message)
    m = embed_id(b'end',m)

    c = encrypt (pks[-1], m)
    
    for i in range (len(users[1:])-1, 0, -1):
        c = encrypt(pks[i-1], embed_id(users[i+1].encode('utf-8'),c))
        
    return c


def embed_id(id: bytes, message: bytes) -> bytes:
    return b'\x00'*(5-len(id)) + id + message

def extract_id(message: bytes) -> bytes:
    return message[:5].strip(b'\x00')

def extract_message(message: bytes) -> bytes:
    return message[5:].strip(b'\x00')


def rsa_decrypt(pk,k):
    return pk.decrypt(
    k,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ) 
    )

def aes_decrypt(k, data):
    aesgcm = AESGCM(k)
    nonce = k
    m = aesgcm.decrypt(nonce, data, None)

    return m


def decode_Rely(message, private_key):
    c1h = message[:private_key.key_size//8]
    c2h = message[private_key.key_size//8:]
    
    k = rsa_decrypt(private_key, c1h)

    aux = aes_decrypt(k, c2h)

    next_hop = extract_id(aux)
    c1h_next = aux[5:]
    if next_hop == b"end": 
        sender = extract_id(c1h_next)
        message = extract_message(c1h_next)
        print("Sender: ", sender.decode('utf-8'), ", Message: ",message.decode('utf-8')) 
    
    else: 
        c1h_id = next_hop.decode('utf-8')
        client.publish(c1h_id, c1h_next)
   

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker!")
        client.publish(topic)
    else:
        print("Failed to connect, return code %d\n", rc)

def on_message(client: Client, userdata, message):
    msg = message.payload
    private_key = read_private_key()
    m = decode_Rely(msg,private_key) 

    return m

if __name__ == '__main__':    
    
    opcion = input(f"¿Qué acción quieres realizar? Encriptar o desencriptar.")
    
    if opcion == "Encriptar":

        usuarios = [item for item in input(f"Introduce los IDs de los usuarios (separados por comas). Si quieres que el mensaje sea anónimo, escribe None como primer identificador: ").split(',')]
        
        message = input(f"Introduce el mensaje a enviar: ")

        pks = [PublicKeys.get_key(id) for id in usuarios[1:]]
        m = message.encode('utf-8')

        c = nested_encrypt(usuarios,pks,m)

        print(f"El mensaje ha sido encriptado.\n")

        client = Client.Client() 
        client.username_pw_set(MQTT_USERNAME,MQTT_PASSWD)
        client.on_connect = on_connect
        client.connect(MQTT_IP)
        print(f"Enviando mensaje al nodo ", c)
        client.publish(usuarios[1],c)
  
    elif opcion == "Desencriptar":        
        client = Client.Client() 
        client.username_pw_set(MQTT_USERNAME,MQTT_PASSWD)
        client.connect(MQTT_IP)
        client.subscribe(topic)
        client.on_message = on_message
        client.loop_forever() 
 
       



