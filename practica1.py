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
topic = "abh"

### Lectura de claves públicas y privadas
def read_public_key (file):
    PB_PATH = os.path("") # Clave pública propia

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
    aesgcm = AESGCM(k)
    nonce = k
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return ciphertext

# Procedimiento de encriptación
def encrypt (pk, message: bytes):
    k = AESGCM.generate_key(bit_length=128)
    c = rsa_encrypt (pk,k) + aes_encrypt (k,message,None)

    return c

# Procedimiento 
def nested_encrypt(users: list, pks: list, message: bytes):
    # Primer paso: encriptación de mensaje + usuario final con marcador "END"
    m = b'\x00'*(5-len(users[0].encode('ascii'))) + users[0].encode('ascii') + message
    m = b'\x00'*(5-len(b'end')) + b'end' + message

    # Segundo paso: encriptación del primer nodo
    c = encrypt (pks[-1], m)
    
    # Tercer paso: encriptación con el resto de nodos
    for i in range (len(users[1:])-1,1):
        print(pks[i-1])
        print(users[i+1])
        c = encrypt(pks[i-1], b'\x00'*(5-len(users[i+1].encode('ascii'))) + users[i+1].encode('ascii') + message)
    
    # Retornar mensaje completo
    return c

##### ALGORITMO 2 #####

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
    aesgcm = AESGCM(k)
    nonce = k
    m = aesgcm.decrypt(nonce, data, None)
    return m.decode('utf-8')

#Relay or decode algorithm
def decode_Rely(message, private_key):
    #c1h: clave simétrica
    #c2h: mensaje
    c1h = msg[:private_key.key_size]
    c2h = msg[private_key.key_size:]

    #Get the symmetric key: desencriptamos con la clave privada
    k = rsa_decrypt(private_key, c1h)
    
    #Decrypt message
    aux = aes_decrypt(k, c2h)
        
    next_hop = aux[:5]
    c1h_next = aux[5:]
    
    if (next_hop == b'end') : #Si el siguiente nodo es el destinatario final
        print("Message:", c2h.decode('ascii')) #Mensaje real
        
    else: # Por el contrario, si es un nodo intermedio reenviamos el mensaje al siguiente nodo
        #se publica el mensaje (c1h, c2h)
        return next_hop, (c1h_next, c2h)
        
   

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker!")
        client.publish(topic)
    else:
        print("Failed to connect, return code %d\n", rc)
# Set Connecting Client ID

def on_message(client: Client, userdata, message):
    msg = message.payload
    private_key = read_private_key()
    m = decode_Rely(private_key,msg)

    return m
"""
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
"""

if __name__ == '__main__':    
    
    opcion = input(f"¿Qué acción quieres realizar? Encriptar, enviar mensaje o desencriptar.")
    if opcion == "Activar nodo":
        client = Client.Client() 
        client.connect(MQTT_IP)
        client.loop_forever()
    elif opcion == "Encriptar":

        usuarios = [item for item in input(f"Introduce los IDs de los usuarios (separados por comas): ").split(',')]
        message = input(f"Introduce el mensaje a enviar: ")

        pks = [PublicKeys.get_key(id) for id in usuarios[1:]]
        m = bytes (message,'utf-8')

        c = nested_encrypt(usuarios,pks,m)

        print(f"El mensaje ha sido encriptado.\n")

        client = Client.Client() 
        client.username_pw_set(MQTT_USERNAME,MQTT_PASSWD)
        client.on_connect = on_connect
        client.connect(MQTT_IP)
        print(f"Enviando mensaje al nodo ")
        client.publish(topic,c)

    elif opcion == "Desencriptar":        
        #Conexion con MQTT
        client = Client.Client() 
        client.connect(MQTT_IP)
        client.on_message = on_message 
        client.subscribe(topic)#Recibir mensajes con x topic
        client.loop_forever() #Conexión abierta para escuchar mensajes continuamente
 
       



