import time
from mqtt import MQTT
from mqtt import ID_ALICE,ID_BOB
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os

# Crear parámetros globales para Diffie-Hellman (compartidos por Alice y Bob)
parameters = dh.generate_parameters(generator=2, key_size=2048)

#### Clase User
class User():
    def __init__(self, name):
        self.name = name
        self.privateKey = None
        self.publicKey = None
        self.rootKey = rootKey
        self.sessionInit = None
    
    def getPublicKey(self):
        return (self.publicKey)

    def getPrivateKey(self):
        return (self.privateKey)

    # Crear una nueva sesión
    def startNewSession(self):
        self.privateKey, self.publicKey = self.generateKeysPair()
        self.sessionInit = time.time()
        print(f"Nueva sesión comenzada para el usuario {self.name}.")

    # Tiempo de sesión
    def getSessionDuration(self):
        if self.session_start_time is None:
            return 0
        return time.time() - self.sessionInit
    
    # Generación de par de claves para cada usuario
    def generateKeysPair():
        #Genera par de claves publica-privada 
        privateKey = parameters.generate_private_key()
        publicKey = privateKey.public_key()
        return privateKey, publicKey
    
  
## HKDF
def deriveKey():
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=rootKey,
        info=b'hkdf_ratchet',
    )

    return derived_key
    


# Symmetric key ratchet


## HMAC



## AES-GCM (AEAD)


if __name__ == "__main__":
    # Generar RootKey
    rootKey = os.urandom(16)

    # Creamos el usuario solicitado y generamos su par de claves mediante Diffie-Hellman
    nombreUser = str(input("¿Qué usuario quieres crear: Alice o Bob? "))
    user = User(nombreUser)

    # Creamos conexión a mqtt
    ## Aquí va la conexión MQTT
    mqtt: MQTT = MQTT(nombreUser)
    print("¡Bienvenido!")
    mqtt.connect()
    time.sleep(2)
    
    # Iniciamos la sesión
    user.startNewSession()