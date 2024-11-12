import os
import math
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from Nodo import *

##########################################################################
#                             CLASE NODO                                 #
##########################################################################

class Nodo:
    def __init__(self, numero, clave):
        self.numero = numero
        self.clave = clave
        self.padre = None
        self.hijoIzq = None
        self.hijoDer = None


##########################################################################
#                  ENCRIPTACIÓN Y DESENCRIPTACIÓN                        #
##########################################################################

def encrypt(key, plaintext):
    # Generamos una clave de 128 bits
    iv = os.urandom(16)

    # Construimos un cifrado AES-128-CBC
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()

    # Encriptamos el texto 
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, ciphertext)

def decrypt(key, iv, ciphertext):
    # Construimos un Cipher con la clave y el IV
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()

    # Desencriptamos para obtener el texto planoq
    return decryptor.update(ciphertext) + decryptor.finalize()

##########################################################################
#                           CREACIÓN DE ÁRBOL                            #
##########################################################################

def crearArbol(niveles):
    # Creamos el array del árbol
    arbol = []
    
    # Paso 1: Calcular el número total de nodos
    nodosTotales = 2**niveles - 1  # Formula para el total de nodos en un árbol binario completo
    
    # Paso 2: Crear los nodos
    for i in range(1, nodosTotales + 1):
        nodo = Nodo(i, os.urandom(16))  # Creamos el nodo con su número y clave aleatoria
        arbol.append(nodo)  # Añadimos el nodo al árbol
    
    # Paso 3: Asignar padres e hijos usando la estructura de un árbol binario completo
    for i in range(nodosTotales):
        nodo_actual = arbol[i]  # Nodo actual
        
        # Determinar índices de hijos en un árbol binario completo
        indice_hijo_izq = 2 * i + 1
        indice_hijo_der = 2 * i + 2
        
        # Asignamos hijos si existen dentro de los límites del árbol
        if indice_hijo_izq < nodosTotales:
            nodo_actual.hijoIzq = arbol[indice_hijo_izq]
            arbol[indice_hijo_izq].padre = nodo_actual  # Asignamos al hijo su padre
            
        if indice_hijo_der < nodosTotales:
            nodo_actual.hijoDer = arbol[indice_hijo_der]
            arbol[indice_hijo_der].padre = nodo_actual  # Asignamos al hijo su padre
    
    return arbol
def revocar_nodos(conjunto_revocados, arbol):
    """
    Marca los nodos en el árbol como revocados y calcula el conjunto de cobertura.
    
    Args:
        conjunto_revocados (set): Conjunto de índices de nodos a revocar.
        arbol (list): Lista que representa el árbol de nodos.

    Returns:
        conjunto_cobertura (set): Conjunto de nodos que cubren todos los nodos no revocados.
    """
    conjunto_revocacion = set()
    
    # Paso 1: Agregar todos los nodos a revocar y sus ancestros
    for indice_nodo in conjunto_revocados:
        nodo_actual = arbol[indice_nodo - 1]  # Índices del árbol están basados en 0
        while nodo_actual is not None:
            conjunto_revocacion.add(nodo_actual)
            nodo_actual = nodo_actual.padre  # Subimos hasta la raíz
    
    # Paso 2: Calcular el conjunto de cobertura
    conjunto_cobertura = calcular_conjunto_cobertura(conjunto_revocacion, arbol)
    
    return conjunto_cobertura


def calcular_conjunto_cobertura(conjunto_revocacion, arbol):
    conjunto_cobertura = set()
    
    # Recorremos todos los nodos del árbol
    for nodo in arbol:
        # Ignoramos los nodos revocados
        if nodo in conjunto_revocacion:
            continue

        nodo_actual = nodo
        nodo_a_agregar = nodo_actual  # Inicialmente asumimos que el nodo puede ser el candidato a agregar

        # Subimos en el árbol para ver si un ancestro cubre completamente el subárbol
        while nodo_actual.padre is not None:
            hermano = None
            # Identificamos el hermano del nodo actual
            if nodo_actual.padre.hijoIzq == nodo_actual:
                hermano = nodo_actual.padre.hijoDer
            else:
                hermano = nodo_actual.padre.hijoIzq
            
            # Si el hermano no está revocado, el padre cubre completamente el subárbol
            if hermano is not None and hermano not in conjunto_revocacion:
                nodo_a_agregar = nodo_actual.padre
                nodo_actual = nodo_actual.padre  # Subimos un nivel y seguimos verificando hacia la raíz
            else:
                # Si el hermano está revocado, no seguimos subiendo; el nodo actual es suficiente
                break
        
        # Añadimos el nodo elegido para la cobertura si aún no está en el conjunto
        conjunto_cobertura.add(nodo_a_agregar)

    return conjunto_cobertura




def obtener_nodos_revocados(input_usuario):
    """
    Convierte la entrada del usuario en un conjunto de nodos a revocar.
    
    Args:
        input_usuario (str): Entrada del usuario, que puede ser una lista de números separados por comas,
                             un solo número o una cadena vacía.
                             
    Returns:
        set: Un conjunto de enteros representando los nodos a revocar.
    """
    # Si la entrada está vacía, devolver un conjunto vacío
    if not input_usuario.strip():
        return set()
    
    # Convertir la entrada en un conjunto de enteros
    try:
        conjunto_revocados = {int(num) for num in input_usuario.split(",") if num.strip().isdigit()}
        return conjunto_revocados
    except ValueError:
        print("Entrada inválida. Asegúrate de introducir solo números separados por comas.")
        return set()


"""def rellenarArbol(nodo, nivelActual, niveles,i):
    if nivelActual < niveles:
        indiceNodoIzq = 2*i + 1;
        indiceNodoDer = 2*i + 2;
        
        k1 = os.urandom(16) 
        k2 = os.urandom(16) 

        nodo.hijoIzq = Nodo(f"k{indiceNodoIzq}",k1)
        nodo.hijoDer = Nodo(f"k{indiceNodoDer}",k2)

        rellenarArbol(nodo.hijoIzq, nivelActual + 1, niveles, indiceNodoIzq)
        rellenarArbol(nodo.hijoDer, nivelActual + 1, niveles, indiceNodoDer)"""


def imprimirArbol(nodo):
    if nodo is not None:
        print(f"{nodo.nombre} ({nodo.clave})")
        imprimirArbol(nodo.hijoIzq)
        imprimirArbol(nodo.hijoDer)




"""def get_parent_index(index):
    return index // 2 if index > 0 else None

def get_sibling_index(index):
    return index - 1 if index % 2 == 0 else index + 1

def calcular_conjunto_cobertura(dispositivos, S):

    Calcula el conjunto de cobertura para el conjunto S en un árbol binario.
    dispositivos: número total de dispositivos (nodos en el árbol).
    S: conjunto de nodos a considerar (debe ser un conjunto o lista de nodos, con nombres como cadenas).

    conjunto_cobertura = set()

    # Verificamos que S sea un iterable y convertimos a conjunto si es un solo string
    if isinstance(S, str):
        S = {S}  # Si S es un solo string, lo convertimos en un conjunto

    # Para cada nodo en S, encontrar su camino hacia la raíz
    for nombre in S:
        path = find_path_to_root_by_name(nombre)
        
        # Para cada nodo en el camino (excepto la raíz), ver si su hermano está en S
        for i in range(len(path) - 1, 0, -1):
            nodo_actual = path[i]
            nodo_padre = path[i - 1]
            if nodo_actual not in S:  # Si el nodo actual no está en S
                hermano = sibling_by_name(nodo_actual.nombre)  # Encontramos el hermano
                if hermano not in S:  # Si el hermano no está en S, lo agregamos a la cobertura
                    conjunto_cobertura.add(hermano.nombre)
    
    return conjunto_cobertura



# Función para encontrar el camino hacia la raíz por nombre de nodo
def find_path_to_root_by_name(nodo):
    path = [nodo]
    while nodo != "Nodo 1":  # Suponemos que "Nodo 1" es la raíz
        nodo = get_parent_name(nodo)  # Esta función debe devolver el nombre del nodo padre
        path.insert(0, nodo)
    return path

# Función para encontrar el hermano de un nodo dado su nombre
def sibling_by_name(nodo):
    # Suponemos que los hermanos se numeran de forma consecutiva
    # Ejemplo: Nodo 2 es hermano de Nodo 3, Nodo 4 es hermano de Nodo 5, etc.
    nodo_num = int(nodo.nombre.split()[-1])  # Extraemos el número del nodo (por ejemplo, "Nodo 2" -> 2)
    hermano_num = nodo_num + 1 if nodo_num % 2 == 0 else nodo_num - 1  # Los hermanos están a +1 o -1
    return f"Nodo {hermano_num}"

# Función para obtener el nombre del nodo padre, dado su nombre
def get_parent_name(nodo):
    nodo_num = int(nodo.nombre.split()[-1])  # Extraemos el número del nodo
    parent_num = nodo_num // 2  # El nodo padre está en la posición nodo_num // 2
    return f"Nodo {parent_num}"

def getConjuntoCobertura(dispositivos, conjuntoRev):
    conjuntoCob = set()
    hojas = range(2 ** (dispositivos.bit_length() - 1), 2 ** dispositivos.bit_length())  # Rango de nodos hoja
    
    for hoja in hojas:
        dispositivo = hoja - (2 ** (dispositivos.bit_length() - 1)) + 1
        if dispositivo not in conjuntoRev:  # Solo consideramos dispositivos no revocados
            path = hoja
            
            while path > 1:
                padre = get_parent_index(path)
                hermano = get_sibling_index(path)
                
                # Agregamos el hermano al conjunto de cobertura solo si:
                # - No está en el conjunto de dispositivos revocados.
                # - No está ya cubierto por un nodo ancestro
                if hermano not in conjuntoRev and hermano not in conjuntoCob:
                    conjuntoCob.add(hermano)
                
                # Verificamos si el padre ya cubre los dispositivos activos en este subárbol
                if padre in conjuntoCob:
                    break
                
                # Continuamos hacia el padre
                path = padre
    
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
    # Applies PKCS#7 padding to a single block.
    block_size = 16
    padding_len = block_size - len(block)
    padding = bytes([padding_len] * padding_len)
    return block + padding

def split_into_blocks(data):
    # Splits data into 16-byte blocks with padding for the last block if necessary.
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
    k = os.urandom(16)
    conjuntoCob = calcular_conjunto_cobertura(dispositivos, conjuntoRev)
    
    print("Conjunto de cobertura:", conjuntoCob)
    
    c_keys = {}
    for nodo in conjuntoCob:
        c_keys[f"k{nodo}"] = encrypt(arbol.clave, k)
    
    with open(contenido, "rb") as file:
        archivo_contenido = file.read()
    
    archivo_cifrado = b''
    bloques = split_into_blocks(archivo_contenido)
    for bloque in bloques:
        iv, cifrado = encrypt(k, bloque)
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
            return False"""

# Usar la función

if __name__ == "__main__":
    dispositivos = int(input("Introduce el número de dispositivos (potencia de 2): "))
    
    # Verificamos si el número de dispositivos es potencia de 2
    if dispositivos % 2 != 0:
        print("El número de dispositivos debe ser una potencia de 2.")

    # Calculamos el número de niveles del árbol
    lvls = math.ceil(math.log2(dispositivos))
    arbol = crearArbol(lvls)
    # Para imprimir los nodos y verificar que todos están en el árbol
    # Mostrar la estructura del árbol
    for nodo in arbol:
        print(f"Nodo {nodo.numero}:")
        print(f"  Clave: {nodo.clave.hex()}")
        print(f"  Padre: {nodo.padre.numero if nodo.padre else None}")
        print(f"  Hijo Izq: {nodo.hijoIzq.numero if nodo.hijoIzq else None}")
        print(f"  Hijo Der: {nodo.hijoDer.numero if nodo.hijoDer else None}")
        print("-" * 30)

    conjuntoRev_input = input("Introduce un dispositivo o dispositivos a revocar: ")
    conjunto_revocados = obtener_nodos_revocados(conjuntoRev_input)
    conjunto_cobertura = revocar_nodos(conjunto_revocados, arbol)
    conjunto_cobertura.sort(reverse=True)
     # Imprimir el conjunto de cobertura
    print("Conjunto de cobertura para proteger los dispositivos no revocados:")
    for nodo in conjunto_cobertura:
        print(f"Nodo {nodo.numero}, Clave: {nodo.clave.hex()}")
    # # Creamos el árbol con n-1 nodos        
    # # arbol = crearArbol(dispositivos)
 
    # file = input("Ingresa un archivo para cifrar (ingresa para omitir): ")
    # if file:
    #     file = os.path.join(os.getcwd(), "image.jpg")#f"C:/Users/nuria/Desktop/master/SI/practicas/practica1/SI/lab3/{file}"
    
    # 
    # conjuntoRev = revocacionNodos(conjuntoRev_input, arbol)
    # for nodo in conjuntoRev:
    #  print(nodo.nombre)  # Accede al atributo 'nombre' de cada nodo

    # res = encryptionProcedure(dispositivos,arbol,conjuntoRev,file)
    # imprimirArbol(arbol)

    # clave_cifrada = next(iter(res["claves_cifradas"].values()))  # Obtener el primer par (IV, ciphertext)
    # iv_clave_cifrada, ciphertext_clave_cifrada = clave_cifrada
    # k = decrypt(arbol.clave, iv_clave_cifrada, ciphertext_clave_cifrada)  # Desencriptar la clave `k`

    # # Desencriptar el contenido usando `k`
    # contenido_descifrado = decryptionProcedure(res["contenido_cifrado"][1], res["claves_cifradas"], k)
    # # Guardar contenido descifrado en un nuevo archivo
    # with open("contenido_descifrado.jpg", "wb") as file:
    #     print("Writing file...")
    #     file.write(contenido_descifrado)

    # comparar_imagenes("image.jpg", "contenido_descifrado.jpg")

   