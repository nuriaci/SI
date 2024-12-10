import time
import cryptography
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os


#### Clase User
class User:
    # Inicializa un usuario 
    def __init__(self, name, sendChannel, recvChannel, rootKey):
        self.name = name
        self.client = mqtt.Client()
        self.DHRatchet = DiffieHellman(rootKey)
        self.sendChannel = sendChannel
        self.recvChannel = recvChannel

    # Configura el cliente MQTT para recibir mensajes
    def inicioMQTT(self, mqtt_server, on_message):
        self.client.on_message = on_message # Establece la función de manejo de mensajes

        self.client.connect(mqtt_server) # Conecta al servidor MQTT

        self.client.subscribe(self.sendChannel, qos=2) # Suscribe a los canales
        self.client.subscribe(self.recvChannel, qos=2)

        self.client.loop_start() # Inicia el bucle de escucha

        while not self.client.is_connected():
            time.sleep(1) # Espera a que se conecte

    def publish(self, data):
        if data:
            # Deriva la clave secreta y el IV utilizando el ratchet
            send_result = self.DHRatchet.send()
            secretKey = send_result[0]
            iv = send_result[1]
            
            # Encriptas los datos utilizando la Clave secreta compartida y el iv
            data = encryptMessage(secretKey, iv, data)

        # Obtienes la clave pública del ratchet de DH
        public_key = self.DHRatchet.getPublicKey()

        
        header = public_key.hex() + "\n\n"  # Convertimos a hexadecimal
        print(type(data))
        # En función de si tienes datos o no
        if data:
            # Envías cabecera y datos
            payload = header + data  
        else:
            # Envías solamente la cabecera
            payload = header

        # Se hace el envío
        self.client.publish(self.sendChannel, payload).wait_for_publish()


    def finalizarMQTT(self):
        self.client.loop_stop()   


class DiffieHellman:
    def __init__(self, rootKey, update_interval=5):
        self.privateKey = X25519PrivateKey.generate() # Genera clave privada X25519
        self.publicKey = self.privateKey.public_key()  # Obtén clave pública
        self.rootKey = rootKey # Clave raíz inicial
        self.sharedKey = None 
        self.rootRatchet = HKDFRatchet(rootKey) # Inicializa el ratchet raíz
        self.sendRatchet = None # Ratchet para enviar
        self.recvRatchet = None
        self.dhUpdateCount = 0  # Contador de mensajes enviados o recibidos
        self.update_interval = update_interval  # Cuántos mensajes antes de actualizar

    def getPublicKey(self):
        return self.publicKey.public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    # Actualiza la clave compartida con la clave pública recibida
    def actualizarDH(self, publicKey):
        self.sharedKey = X25519PublicKey.from_public_bytes(publicKey)
        newRoot = self.rootRatchet.actualizarCKMK(self.privateKey.exchange(self.sharedKey))[1]
        self.sendRatchet = HKDFRatchet(newRoot)
        self.recvRatchet = HKDFRatchet(newRoot)

    def send(self):

        self.dhUpdateCount += 1  # Incrementa contador
        if self.dhUpdateCount >= self.update_interval:
            print(f"Actualizando claves DH después de {self.update_interval} mensajes.")
            # Genera nuevas claves si se alcanza el límite de mensajes
            self.privateKey = X25519PrivateKey.generate()
            self.publicKey = self.privateKey.public_key()
            self.dhUpdateCount = 0  # Reiniciamos el contador

         # Deriva clave e IV para el mensaje
        newRatchet = self.sendRatchet.actualizarCKMK(self.privateKey.exchange(self.sharedKey))
        claveSimetrica = newRatchet[0]
        iv = newRatchet[2]

        self.actualizarDH(self.sharedKey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

        return claveSimetrica, iv


    def receive(self, publicKey):

        self.sharedKey = X25519PublicKey.from_public_bytes(publicKey)
        # Actualizamos el ratchet de recepción y obtenemos la clave simétrica (symmetric key) y el iv
        newRatchet = self.recvRatchet.actualizarCKMK(self.privateKey.exchange(self.sharedKey))
        claveSimetrica = newRatchet[0]
        iv = newRatchet[2]

        self.actualizarDH(publicKey)

        return claveSimetrica, iv



class HKDFRatchet:

    def __init__(self, rootKey):
        self.rootKey = rootKey
        self.HKDFRatchet = None

    # Derivación desde RootKey    
    def KDF_RK(self, sharedKey):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=48,
            salt=self.rootKey,
            info=b'hkdf_ratchet',
        ).derive(sharedKey)
        
        self.rootKey = derived_key[:16]
        chainKey = derived_key[16:32]
        iv = derived_key[32:]

        return chainKey, iv
    
    def actualizarCKMK(self, sharedKey):
        output = self.KDF_RK(sharedKey)
        chainKey = output[0]
        iv = output[1]
        self.hmacRatchet = HMACRatchet(chainKey)
        messageKey = self.hmacRatchet.KDF_CK()

        return messageKey, self.rootKey, iv
    
class HMACRatchet:
    
    def __init__(self, chainKey):
        self.chainKey = chainKey

    def KDF_CK(self):
        hmac = HMAC(self.chainKey, hashes.SHA256()).finalize()
        self.chainKey = hmac[:16]
        messageKey = hmac[16:]
        
        return messageKey



## AES-GCM (AEAD)
# Cifrado
def encryptMessage(messageKey, iv, plaintext):
    if messageKey is None or iv is None:
        print("Error: La clave secreta o el IV son None.")
        return None
    
    aesgcm = AESGCM(messageKey) # Inicializa AES-GCM
    ciphertext = aesgcm.encrypt(iv, bytes(plaintext,"utf-8"), None).hex() # Cifra y devuelve como hex
    return ciphertext


# Descifrado 
def decryptMessage(messageKey, iv, ciphertext):
    try:
        aesgcm = AESGCM(messageKey)
        plaintext = aesgcm.decrypt(iv, bytes.fromhex(ciphertext), None) # Descifra el mensaje
        return plaintext
    except cryptography.exceptions.InvalidTag as e:
        print("Error: InvalidTag - Decryption failed. This might be due to mismatched key or iv.")
        return None


if __name__ == "__main__":

    # Generamos el rootKey para el intercambio
    rootKey = os.urandom(16)

    # Solicitamos los nombres de los usuarios
    nombreUser1 = str(input("Escribe un nombre para el usuario 1: "))
    nombreUser2 = str(input("Escribe un nombre para el usuario 2: "))

    nombreCanal = str(input("Escribe un nombre de canal: "))
    # Creamos los usuarios
    user1 = User(nombreUser1, nombreCanal + ".in", nombreCanal + ".out", rootKey)
    user2 = User(nombreUser2, nombreCanal + ".out", nombreCanal + ".in",  rootKey)

    # Función para manejar los mensajes recibidos por el usuario 1 (Alice)
    def on_message_user1(client, userdata, message):
    
        if message.topic == str(user1.recvChannel):
            payload = message.payload.decode("utf-8").split("\n\n")  
            publicKey = bytes.fromhex(payload[0])  # Clave pública del remitente
            ciphertext = payload[1]  # Cuerpo del mensaje cifrado

            # Si el mensaje no tiene cifrado (vacío), solo imprimimos la cabecera
            if not ciphertext:
                user1.DHRatchet.actualizarDH(publicKey)
            else:
                
                messageKey, iv = user1.DHRatchet.receive(publicKey)

                if messageKey and iv:
                    decryptedMessage = decryptMessage(messageKey, iv, ciphertext)
                    print(f"[{user2.name}]: {decryptedMessage}")
                else:
                    print("Error al obtener la clave de mensaje o IV para descifrar.")


    # Función para manejar los mensajes recibidos por el usuario 2 (Bob)
    def on_message_user2(client, userdata, message):

        if message.topic == str(user2.recvChannel):
            payload = message.payload.decode("utf-8").split("\n\n")  
            publicKey = bytes.fromhex(payload[0])  # Clave pública del remitente
            ciphertext = payload[1]  # Cuerpo del mensaje cifrado
            # Si el mensaje no tiene cifrado (vacío), solo imprimimos la cabecera
            if not ciphertext:
                user2.DHRatchet.actualizarDH(publicKey)
            else:
                messageKey, iv = user2.DHRatchet.receive(publicKey)
                decryptedMessage = decryptMessage(messageKey, iv, ciphertext)
                
                print(f"[{user1.name}]: {decryptedMessage}")


    # Creamos conexión a MQTT
    mqtt_server = "localhost"# Aquí debes poner la dirección de tu servidor MQTT
    user1.inicioMQTT(mqtt_server, on_message_user1)  # Inicia la conexión para el usuario 1
    user2.inicioMQTT(mqtt_server, on_message_user2)  # Inicia la conexión para el usuario 2

    user1.publish("")
    time.sleep(0.5)
    user2.publish("")

    time.sleep(2)
    
    #Bucle: enviar mensajes
    while True:
        print()
        print("*** 1 para enviar el mensaje como " + nombreUser1)
        print("*** 2 para enviar el mensaje como " + nombreUser2)
        print("*** SALIR para enviar el mensaje como ")
        select = input("Selección: ")
        if select == "1":
            user_1_message = input("Envía un mensaje como " + nombreUser1 + ": ")
            user1.publish(user_1_message)
            time.sleep(2)
        elif select == "2":
            user_2_message = input("Envía un mensaje como " + nombreUser2 + ": ")            
            user2.publish(user_2_message)
            time.sleep(2)
        elif select == "SALIR":
            print("Cerrando conexión")
            user1.finalizarMQTT()
            user2.finalizarMQTT()
            break
        else:
            print("Selección inválida. Escoge entre las opciones admitidas.")
