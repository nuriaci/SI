import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Inicialización de clase Encrypt
class Encrypt:

    def _init_(self, passwd: bytes):

        with open("", "rb") as key_file:    
            pb_key = key_file.read()
            self.pb_key = serialization.load_ssh_public_key(
                pb_key,
                backend=default_backend()
            )

        with open("", "rb") as key_file:    
            pr_key = key_file.read()
            self.pr_key = serialization.load_ssh_private_key(
                pr_key,
                password=passwd,
                backend=default_backend()
            )

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

def encrypt(pk, data):
    k = AESGCM.generate_key(bit_length=128)
    c = rsa_encrypt(pk, k) + aes_encrypt(k, data)

    return c

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