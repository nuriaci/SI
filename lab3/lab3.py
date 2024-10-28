import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from Nodo import *


def crearArbol(t):
    if (t == 0):
        return None
    
    k = os.urandom(16) 
    i = 0
    root = Nodo(f"k{i}", k)
    rellenarArbol(root, 0, t, i)

    return root

def rellenarArbol(nodo, nivelActual, niveles,i):
    if nivelActual < niveles:
        indiceNodoIzq = 2*i + 1;
        indiceNodoDer = 2*i + 2;
        
        k1 = os.urandom(16) 
        k2 = os.urandom(16) 

        nodo.hijoIzq = Nodo(f"k{indiceNodoIzq}",k1)
        nodo.hijoDer = Nodo(f"k{indiceNodoDer}",k2)

        rellenarArbol(nodo.hijoIzq, nivelActual + 1, niveles, indiceNodoIzq)
        rellenarArbol(nodo.hijoDer, nivelActual + 1, niveles, indiceNodoDer)


def imprimirArbol(nodo):
    if nodo is not None:
        print(f"{nodo.nombre} ({nodo.clave})")
        imprimirArbol(nodo.hijoIzq)
        imprimirArbol(nodo.hijoDer)

def encrypt(key, plaintext):
    # Generate a random 128-bit IV.
    iv = os.urandom(16)
    # Construct an AES-128-CBC Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext)

def decrypt(key, iv, ciphertext):
    # Construct a Cipher object, with the key, iv
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()
    # Decryption gets us the plaintext.
    return decryptor.update(ciphertext) + decryptor.finalize()


def get_parent_index(index):
    return index // 2 if index > 0 else None

def get_sibling_index(index):
    return index - 1 if index % 2 == 0 else index + 1


def getConjuntoCobertura(niveles,conjuntoRev):
    conjuntoCob = set()
    #Recorrido hojas
    for nodo in range(2 ** niveles, 2 ** (niveles + 1)):
        disp = nodo - (2 ** niveles) + 1
        if disp not in conjuntoRev:
            path = nodo
            while path > 1:
                hermano = get_sibling_index(path)
                if hermano in conjuntoCob:
                    conjuntoCob.discard(hermano)
                else:
                    conjuntoCob.add(hermano)
                # Subimos al padre en la siguiente iteración
                path = get_parent_index(path)

    return conjuntoCob

def pad_block(block):
    """Applies PKCS#7 padding to a single block."""
    block_size = 16
    padding_len = block_size - len(block)
    padding = bytes([padding_len] * padding_len)
    return block + padding

def split_into_blocks(data):
    """Splits data into 16-byte blocks with padding for the last block if necessary."""
    block_size = 16
    blocks = []
    
    # Split data into blocks
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            block = pad_block(block)  # Add padding if block is smaller than 16 bytes
        blocks.append(block)
    
    return blocks

def encryptionProcedure(niveles, arbol, conjuntoRev, contenido):
    # Paso 1: generación de una clave aleatoria k
    k = os.urandom(16)
    # Paso 2: para cada nodo de S, computar c = (kroot, k)
    conjuntoCob = getConjuntoCobertura(niveles,conjuntoRev)
    print("Conjunto de cobertura:", conjuntoCob)
    
    # Cifrar la clave con cada nodo en el conjunto de cobertura
    c_keys = {}
    for nodo in conjuntoCob:
        c_keys[f"k{nodo}"] = encrypt(arbol.clave, k)
    # Paso 3: encriptar contenido como c = Eprima (k,m)
    with open(contenido, "rb") as file:
        archivo_contenido = file.read()
        
    archivo_cifrado = b''
    bloques = split_into_blocks(archivo_contenido)
    for bloque in bloques:
        iv, cifrado = encrypt(k, bloque)
        archivo_cifrado += iv + cifrado
    return {"claves_cifradas": c_keys, "contenido_cifrado": (iv, archivo_cifrado)}

if __name__ == "__main__":
    niveles = int(input("Introduce el número de niveles: "))
    arbol = crearArbol(niveles)
 
    file = input("Ingresa un archivo para cifrar (ingresa para omitir): ")
    if file:
        file = f"C:/Users/nuria/Desktop/master/SI/practicas/practica1/SI/lab3/{file}"
    
    conjuntoRev_input = input("Introduce un nodo o conjunto de nodos a revocar: ")
    conjuntoRev = set(map(int, conjuntoRev_input.split(',')))

    res = encryptionProcedure(niveles,arbol,conjuntoRev,file)
    imprimirArbol(arbol)

    print("Claves cifradas:", res["claves_cifradas"])
    print("Contenido cifrado:", res["contenido_cifrado"])