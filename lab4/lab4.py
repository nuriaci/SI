import time
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

# Crear parámetros globales para Diffie-Hellman (compartidos por Alice y Bob)#
# parameters = dh.generate_parameters(generator=2, key_size=2048)

#### Clase User
class User:
    def __init__(self, name, sendChannel, recvChannel, rootKey):
        self.name = name
        self.sessionInit = None
        self.messageCount = 0
        self.client = mqtt.Client()
        self.DHRatchet = DiffieHellman(rootKey)
        self.sendChannel = sendChannel
        self.recvChannel = recvChannel

    def inicioMQTT(self, mqtt_server, on_message):
        self.client.on_message = on_message
        print(mqtt_server)

        self.client.connect(mqtt_server)

        self.client.subscribe(self.sendChannel)
        self.client.subscribe(self.recvChannel)

        self.client.loop_start()

    def publish(self, data):
        if data:
            # Obtienen la Secret Shared Key y el iv del ratchet de envio
            send_result = self.DHRatchet.send(self.DHRatchet.getPublicKey(), self.messageCount)
            secretKey = send_result[0]
            iv = send_result[1]
            print("Enviando el mensaje: " + str(data) + " por el topic " + str(self.sendChannel))
            
            # Encriptas los datos utilizando la Clave secreta compartida y el iv
            data = encryptMessage(secretKey, iv, data)

        # Obtienes la clave pública del ratchet de DH
        public_key = self.DHRatchet.getPublicKey()

        # Ya no necesitamos public_bytes() ya que estamos trabajando con un objeto 'bytes'
        header = public_key.hex() + "\n\n"  # Convertimos a hexadecimal

        # En función de si tienes datos o no
        if data:
            # Envías cabecera y datos
            payload = header + data  # Usamos encrypted_data en vez de 'data' directamente
        else:
            # Envías solamente la cabecera
            payload = header

        # Se hace el envío
        self.client.publish(self.sendChannel, payload).wait_for_publish()




    def finalizarMQTT(self):
        self.client.loop_stop()   

    def update_message_count(self):
        self.messageCount += 1

    # def rotateDHKeys(self):
    #     # Genera nuevas claves DH después de cierto número de mensajes
    #     if self.messageCount > 5:  # Ejemplo: después de 5 mensajes
    #         print(f"{self.name}: Rotando claves Diffie-Hellman.")
    #         self.privateKey, self.publicKey = self.generateKeysPair()
    #         self.messageCount = 0  # Reiniciamos el contador
    #     else:
    #         self.messageCount += 1

class DiffieHellman:

    def __init__(self, rootKey):
        self.privateKey = X25519PrivateKey.generate()
        self.publicKey = self.privateKey.public_key()
        self.rootKey = rootKey
        self.sharedKey = None
        self.rootRatchet = HKDFRatchet(rootKey)
        self.sendRatchet = None  # Inicializamos en None, pero se debe inicializar más tarde
        self.recvRatchet = None  # Igual que sendRatchet

    def getPublicKey(self):
        return self.publicKey.public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    
    def actualizarDH(self, publicKey, messageCount):
        if messageCount > 5:
            print(f"Generando nuevas claves DH después de {messageCount} mensajes.")
            self.privateKey = X25519PrivateKey.generate()
            self.publicKey = self.privateKey.public_key()

        # Establecer la clave compartida
        pk = X25519PublicKey.from_public_bytes(publicKey)
        self.sharedKey = self.privateKey.exchange(pk)

        # Derivamos las nuevas claves (rootKey, chainKey, iv)
        rootKey = self.rootRatchet.actualizarCKMK(self.sharedKey)

        # Inicializamos sendRatchet y recvRatchet con el rootKey
        self.sendRatchet = HKDFRatchet(rootKey)  # Inicializamos sendRatchet
        self.recvRatchet = HKDFRatchet(rootKey)  # Inicializamos recvRatchet

    def send(self, publicKey, messageCount):
        if self.sendRatchet is None:
            print("sendRatchet no ha sido inicializado.")
            return None, None  # O alguna otra lógica de error

        # Actualizamos el ratchet y obtenemos la clave simétrica (symmetric key) y el iv
        newRatchet = self.sendRatchet.actualizarCKMK(self.sharedKey)
        claveSimetrica = newRatchet[0]
        iv = newRatchet[2]

        # Actualizamos las claves DH cada vez que se envía un mensaje
        self.actualizarDH(publicKey, messageCount)

        return claveSimetrica, iv

    def receive(self, publicKey, messageCount):
        if self.recvRatchet is None:
            print("recvRatchet no ha sido inicializado.")
            return None, None  # O alguna otra lógica de error

        # Actualizamos el ratchet y obtenemos la clave simétrica (symmetric key) y el iv
        newRatchet = self.recvRatchet.actualizarCKMK(self.sharedKey)
        claveSimetrica = newRatchet[0]
        iv = newRatchet[2]

        # Actualizamos las claves DH después de recibir un mensaje
        self.actualizarDH(publicKey, messageCount)

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
    aesgcm = AESGCM(messageKey)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
    print("Mensaje cifrado.")
    return ciphertext

# Descifrado 
def decryptMessage(messageKey, iv, ciphertext):
    aesgcm = AESGCM(messageKey)
    plaintext = aesgcm.decrypt(iv, ciphertext, None).decode()
    print("Mensaje descifrado.")
    return plaintext
    # self.sharedKey = derived_key
    # print(f"{self.name}: Clave compartida derivada.")
    # self.ratchetSymmetricKey()
    
##################################################################

# Symmetric key ratchet
# HMAC
# Ratchet de clave simétrica con HMAC
# def ratchetSymmetricKey(self):
#     h = hmac.HMAC(self.symmetricKey, hashes.SHA256())
#     h.update(b'symmetric_ratchet')        
#     self.symmetricKey = h.finalize()
#     print(f"{self.name}: Clave simétrica actualizada.")



# Descifrar mensaje con AES-GCM



if __name__ == "__main__":

    # Generamos el rootKey para el intercambio
    rootKey = os.urandom(16)

    # Solicitamos los nombres de los usuarios
    nombreUser1 = str(input("Escribe un nombre para el usuario 1: "))
    nombreUser2 = str(input("Escribe un nombre para el usuario 2: "))

    nombreCanal = str(input("Escribe un nombre de canal: "))
    # Creamos los usuarios
    user1 = User(nombreUser1, nombreCanal + ".in", nombreCanal + ".out", rootKey)
    user2 = User(nombreUser2, nombreCanal + ".in", nombreCanal + ".out", rootKey)

        # Función para manejar los mensajes recibidos por el usuario 1 (Alice)
    def on_message_user1(client, userdata, message):
        # Decodificamos el mensaje recibido
        if message.topic == str(user1.recvChannel):
            payload = message.payload.decode('utf-8').split("\n\n")
            publicKey = payload[0]  # La clave pública del remitente
            ciphertext = payload[1]  # El mensaje cifrado
            print(f"{user1.name} ha recibido un mensaje en {message.topic}.")
            if len(ciphertext) == 0:
                user1.DHRatchet.update_dh(bytes.fromhex(publicKey))
            else:
                messageKey, iv = user2.DHRatchet.receive(publicKey, user1.messageCount)
                decryptedMessage = decryptMessage(user1, messageKey, iv, ciphertext)
                print(f"Mensaje descifrado recibido por {user1.name}: {decryptedMessage}")
            


    # Función para manejar los mensajes recibidos por el usuario 2 (Bob)
    def on_message_user2(client, userdata, message):
        # Decodificamos el mensaje recibido
        if message.topic == str(user2.recvChannel):
            payload = message.payload.decode('utf-8').split("\n\n")
            print(payload)
            publicKey = payload[0]  # La clave pública del remitente
            ciphertext = payload[1]  # El mensaje cifrado
            print(f"{user2.name} ha recibido un mensaje en {message.topic}.")
            if len(ciphertext) == 0:
                user2.DHRatchet.update_dh(bytes.fromhex(publicKey))
            else:
                messageKey, iv = user2.DHRatchet.receive(publicKey, user2.messageCount)
                decryptedMessage = decryptMessage(user2, messageKey, iv, ciphertext)
                print(f"Mensaje descifrado recibido por {user2.name}: {decryptedMessage}")
            

           

    # Creamos conexión a MQTT
    mqtt_server = "localhost"#"mastropiero.det.uvigo.es"  # Aquí debes poner la dirección de tu servidor MQTT
    user1.inicioMQTT(mqtt_server, on_message_user1)  # Inicia la conexión para el usuario 1
    user2.inicioMQTT(mqtt_server, on_message_user2)  # Inicia la conexión para el usuario 2

    user1.publish("")
    user2.publish("")
    time.sleep(2)

    while True:
        print()
        print("-Pulse 0 para enviar un mensaje como " + nombreUser1)
        print("-Pulse 1 para enviar un mensaje como " + nombreUser2)
        print("-Pulse 2 para salir")
        select = input("Selección: ")
        if select == "0":
            user_1_message = input("Mensaje como " + nombreUser1 + ": ")
            user1.publish(user_1_message)
            time.sleep(2)
        elif select == "1":
            user_2_message = input("Mensaje como " + nombreUser2 + ": ")
            user2.publish(user_2_message)
            time.sleep(2)
        elif select == "2":
            print("Cerrando conexión")
            user1.finalizarMQTT()
            user2.finalizarMQTT()
            break
        else:
            print("Escoja 0, 1, o 2")
