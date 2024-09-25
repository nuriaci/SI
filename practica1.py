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
    PB_PATH = os.path("")  # Clave pública propia
     
    with open(file, "rb") as key_file:    
        pb_key = key_file.read()
        pba_key = serialization.load_ssh_public_key(
            pb_key,
            backend=default_backend()
        )

def read_private_key():
    #pr_path = os.path("clave")  # cambio
    pr_path = os.path.join(os.getcwd(), "ABH") # Aquí va el archivo de clave privada

    with open(pr_path, "rb") as key_file:    
        pr_key = key_file.read()
        password="2109201a" #cambio
        pra_key = serialization.load_ssh_private_key(
            pr_key,
            password=password.encode(), #None
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
    m = embed_id(users[0].encode('ascii'),message)
    m = embed_id(b'end',m)
    # Segundo paso: encriptación del primer nodo
    c = encrypt (pks[-1], m)
    
    # Tercer paso: encriptación con el resto de nodos
    for i in range (len(users[1:])-1, 0, -1):
        c = encrypt(pks[i-1], embed_id(users[i+1].encode('ascii'),c))
        
    # Retornar mensaje completo
    return c

##### ALGORITMO 2 #####
def embed_id(id: bytes, message: bytes) -> bytes:
    """Prepends the 5 bytes of the ID before the message.

    Args:
        id (bytes): ID.
        message (bytes): Message.

    Returns:
        bytes: ID and message in bytes.
    """

    return b'\x00'*(5-len(id)) + id + message

def extract_id(message: bytes) -> bytes:
    """Extracts the 5 bytes of the ID from the message.

    Args:
        message (bytes): Message.

    Returns:
        bytes: ID without padding.
    """

    return message[:5].strip(b'\x00')

def extract_message(message: bytes) -> bytes:
    """Extracts the 5 bytes of the ID from the message.

    Args:
        message (bytes): Message.

    Returns:
        bytes: ID without padding.
    """

    return message[5:].strip(b'\x00')

# Desencriptación en RSA (se utiliza clave privada por criptografía asimétrica)
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
    print ("MENSAJE;",m)
    print (repr(m.decode('utf-8')))
    return m

#Relay or decode algorithm
def decode_Rely(message, private_key):
    #c1h: clave simétrica
    #c2h: mensaje
    c1h = message[:private_key.key_size//8]
    c2h = message[private_key.key_size//8:]
    
    #Get the symmetric key: desencriptamos con la clave privada
    k = rsa_decrypt(private_key, c1h)
    print(k)
    print(c2h)
    #Decrypt message
    aux = aes_decrypt(k, c2h)
    print(aux)
    print ("PASO")
    next_hop = extract_id(aux)
    print (next_hop)
    c1h_next = extract_message(aux)
    print(c1h_next)
    print(next_hop == b"end")
    if next_hop == b"end": #Si el siguiente nodo es el destinatario final
        print("Message:", c1h_next.decode('utf-8')) #Mensaje real
    
    else: # Por el contrario, si es un nodo intermedio reenviamos el mensaje al siguiente nodo
        #se publica el mensaje (c1h, c2h)
        #return next_hop, (c1h_next, c2h)
        client.publish(c1h_next, c2h)
        print ("VOY AQUI")

   

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
    m = decode_Rely(msg,private_key) #cambio

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
    
    opcion = input(f"¿Qué acción quieres realizar? Encriptar o desencriptar.")
    """ if opcion == "Activar nodo":
        client = Client.Client() 
        client.connect(MQTT_IP)
        client.loop_forever()"""
    if opcion == "Encriptar":

        usuarios = [item for item in input(f"Introduce los IDs de los usuarios (separados por comas): ").split(',')]
        message = input(f"Introduce el mensaje a enviar: ")

        pks = [PublicKeys.get_key(id) for id in usuarios[1:]]
        m = message.encode('utf-8')

        c = nested_encrypt(usuarios,pks,m)
        print (len(c))

        print(f"El mensaje ha sido encriptado.\n")

        client = Client.Client() 
        client.username_pw_set(MQTT_USERNAME,MQTT_PASSWD)
        client.on_connect = on_connect
        client.connect(MQTT_IP)
        print(f"Enviando mensaje al nodo ", c)
        client.publish(topic,c)
  
    elif opcion == "Desencriptar":        
        #Conexion con MQTT
        #client_id="nuci"
        client = Client.Client() 
        client.username_pw_set(MQTT_USERNAME,MQTT_PASSWD)
        client.connect(MQTT_IP)
        client.subscribe(topic)#Recibir mensajes con x topic
        client.on_message = on_message
        client.loop_forever() #Conexión abierta para escuchar mensajes continuamente
 
       



