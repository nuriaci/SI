import os
import math
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from Nodo import *


def crearArbol(dispositivos):
    nodos = []
    
    # Paso 1: Crear los nodos hoja (de 1 a dispositivos)
    for i in range(1, dispositivos + 1):
        clave = os.urandom(16)  # Generar una clave aleatoria
        nodos.append(Nodo(f"Nodo {i}", clave))  # Agregar un nodo hoja
    
    # Paso 2: Crear nodos padres
    index = dispositivos + 1  # Empezamos a contar los nodos padres desde dispositivos + 1
    while len(nodos) > 1:
        nuevos_nodos = []
        
        for i in range(0, len(nodos), 2):
            # Crear un nuevo nodo padre que tiene como hijos los nodos i y i+1
            if i + 1 < len(nodos):  # Asegurarse de que hay un par
                clave_padre = os.urandom(16)  # Clave aleatoria para el nodo padre
                padre = Nodo(f"Nodo {index}", clave_padre)
                padre.hijoIzq = nodos[i]      # Asignar hijo izquierdo
                padre.hijoDer = nodos[i + 1]  # Asignar hijo derecho
                nuevos_nodos.append(padre)    # Agregar nodo padre a la lista de nuevos nodos
                index += 1  # Incrementar el índice para el siguiente padre
        
        nodos = nuevos_nodos  # Reemplazar la lista de nodos con los nuevos nodos creados
    
    # La raíz del árbol es el único nodo que queda
    return nodos[0]  # Devolver la raíz del árbol

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

def getConjuntoCobertura(conjuntoRev):
    conjuntoCob = set()

    # Revisamos cada nodo en el conjunto de revocación
    for nodo in conjuntoRev:
        if nodo > 0:  # Asegurarse de que no sea el nodo raíz
            padre = get_parent_index(nodo)
            if padre is not None:
                conjuntoCob.add(padre)  # Agregar al padre

            # Agregar al hermano si existe
            hermano = get_sibling_index(nodo)
            if hermano != nodo:  # Si no es el mismo nodo
                conjuntoCob.add(hermano)

    return conjuntoCob


def getConjuntoCoberturaNoSeUsa(dispositivos,conjuntoRev):
    conjuntoCob = set()
    #Recorrido hojas
    for nodo in range(2 ** dispositivos, 2 ** (dispositivos + 1)):
        disp = nodo - (2 ** dispositivos) + 1
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

def encryptionProcedure(dispositivos, arbol, conjuntoRev, contenido):
    # Paso 1: generación de una clave aleatoria k
    k = os.urandom(16)
    # Paso 2: para cada nodo de S, computar c = (kroot, k)
    conjuntoCob = getConjuntoCobertura(dispositivos,conjuntoRev)
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
        #print(f"IV: {iv}")
        #print(f"Cifrado: {cifrado}")
        archivo_cifrado += iv + cifrado
    return {"claves_cifradas": c_keys, "contenido_cifrado": (iv, archivo_cifrado)}


def decryptionProcedure(contenido_cifrado, c_keys, k):
    bloques_descifrados = []
    offset = 0

    while offset < len(contenido_cifrado):
        iv = contenido_cifrado[offset:offset + 16]  # Obtener IV del bloque
        offset += 16
        ciphertext_block = contenido_cifrado[offset:offset + 16]  # Obtener bloque de cifrado
        offset += 16

        decrypted_block = decrypt(k, iv, ciphertext_block)
        bloques_descifrados.append(decrypted_block)

    plaintext = b''.join(bloques_descifrados)

    # Remover el padding PKCS#7
    padding_len = plaintext[-1]  # El último byte indica la longitud del padding
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Padding inválido o corrupto.")
    
    return plaintext[:-padding_len]  # Retornar el contenido sin padding

def comparar_imagenes(ruta_imagen1, ruta_imagen2):
    with open(ruta_imagen1, "rb") as img1, open(ruta_imagen2, "rb") as img2:
        contenido_img1 = img1.read()
        contenido_img2 = img2.read()

        if contenido_img1 == contenido_img2:
            print("Las imágenes son idénticas.")
            return True
        else:
            print("Las imágenes son diferentes.")
            return False

# Usar la función

if __name__ == "__main__":
    dispositivos = int(input("Introduce el número de dispositivos (potencia de 2): "))
    
    # Verificar si el número de dispositivos es potencia de 2
    if dispositivos & (dispositivos - 1) != 0:
        print("El número de dispositivos debe ser una potencia de 2.")
            
    arbol = crearArbol(dispositivos)
 
    """ file = input("Ingresa un archivo para cifrar (ingresa para omitir): ")
    if file:
        file = f"C:/Users/nuria/Desktop/master/SI/practicas/practica1/SI/lab3/{file}"
    
    conjuntoRev_input = input("Introduce un nodo o conjunto de nodos a revocar: ")
    conjuntoRev = set(map(int, conjuntoRev_input.split(',')))

    res = encryptionProcedure(dispositivos,arbol,conjuntoRev,file)"""
    imprimirArbol(arbol)

    """clave_cifrada = next(iter(res["claves_cifradas"].values()))  # Obtener el primer par (IV, ciphertext)
    iv_clave_cifrada, ciphertext_clave_cifrada = clave_cifrada
    k = decrypt(arbol.clave, iv_clave_cifrada, ciphertext_clave_cifrada)  # Desencriptar la clave `k`

    # Desencriptar el contenido usando `k`
    contenido_descifrado = decryptionProcedure(res["contenido_cifrado"][1], res["claves_cifradas"], k)
    # Guardar contenido descifrado en un nuevo archivo
    with open("contenido_descifrado.jpg", "wb") as file:
        print("Writing file...")
        file.write(contenido_descifrado)

    comparar_imagenes("image.jpg", "contenido_descifrado.jpg")"""

   