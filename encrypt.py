import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class Encrypt:

    def __init__(self, passwd: bytes):

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

def encrypt():
    k = AESGCM.generate_key(bit_length=128)
    c = rsa_encrypt(pk, k) + aes_encrypt(k, data)



