import os
import math
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding
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

##########################################################################
#                         REVOCACIÓN DE NODOS                            #
##########################################################################

def revocar_nodos(conjunto_revocados, arbol):
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

##########################################################################
#                  CÁLCULO DEL CONJUNTO DE COBERTURA                     #
##########################################################################

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

##########################################################################
#                      OBTENCIÓN DE NODOS REVOCADOS                      #
##########################################################################

def obtener_nodos_revocados(input_usuario):
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

##########################################################################
#                      IMPRESIÓN DE ÁRBOL Y HOJAS                        #
##########################################################################

def imprimirArbol(nodo):
    if nodo is not None:
        print(f"{nodo.nombre} ({nodo.clave})")
        imprimirArbol(nodo.hijoIzq)
        imprimirArbol(nodo.hijoDer)

def imprimir_nodos_hoja(arbol, conjunto_revocados):
    print("Nodos hoja disponibles (sin revocar):")
    
    for nodo in arbol:
        # Verificamos que el nodo sea hoja (sin hijos) y que no esté revocado
        if nodo.hijoIzq is None and nodo.hijoDer is None and nodo.numero not in conjunto_revocados:
            # Imprimimos el nodo solo si es hoja y no está revocado
            print(f"- Nodo {nodo.numero}")

##########################################################################
#                     DIVISIÓN EN BLOQUES Y PADDING                      #
##########################################################################

def pad_block(data, blockSize):
    # Applies PKCS#7 padding to a single block.
    padding_len = blockSize - (len(data) % blockSize)
    if padding_len == 0:  # Si el tamaño ya es múltiplo del bloque, agregamos el relleno completo
        padding_len = blockSize
    padding = bytes([padding_len] * padding_len)  # Genera padding con el byte de padding_len
    return data + padding

def split_into_blocks(data, block_size=16):
    blocks = []
    
    # Divide los datos en bloques del tamaño especificado
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            block = pad_block(block, block_size)  # Agregar relleno si el bloque es más pequeño
        blocks.append(block)
    
    return blocks

##########################################################################
#                      PROCEDIMIENTO DE ENCRIPTACIÓN                     #
##########################################################################

def encryptionProcedure(conjuntoCobertura, contenido):

    # Paso 1: generar una clave aleatoria para cifrar el archivo
    k = os.urandom(16)

    # Paso 2: crear diccionario de claves
    clavesCifradas = {}

    # Paso 3: cifrar la clave del contenido con la clave de cada uno de los nodos en el conjunto de cobertura
    for nodo in conjuntoCobertura:
        iv, cifrado = encrypt(nodo.clave, k) 
        clavesCifradas[f"nodo_{nodo.numero}"] = (iv, cifrado) 

    # Paso 4: leer el archivo y dividir el contenido en bloques
    with open(contenido, "rb") as file:
        contenidoArchivo = file.read()
    contenidoBloques = split_into_blocks(contenidoArchivo)
    
    archivoCifrado = b''
    # Paso 5: cifrar cada bloque con la clave k del archivo
    for bloque in contenidoBloques:
        iv, cifrado = encrypt(k, bloque)
        archivoCifrado += iv + cifrado

    # Paso 6: retornar las claves 
    return {"claves_cifradas": clavesCifradas, "contenido_cifrado": (iv, archivoCifrado)}

##########################################################################
#                      PROCESO DE DESENCRIPTACIÓN                        #
##########################################################################

def decryptionProcedure(arbol, contenido_cifrado, c_keys, nodoDest, conjuntoCobertura):
    # Paso 1: Buscar el nodo correspondiente a nodoDest en el árbol
    nodoDest_obj = None
    for nodo in arbol:
        if nodo.numero == nodoDest:
            nodoDest_obj = nodo
            break

    if nodoDest_obj is None:
        raise ValueError(f"Nodo destino {nodoDest} no encontrado en el árbol")
    
    # Paso 2: Si el nodo destino está en el conjunto de cobertura, desencriptamos con su clave
    if nodoDest_obj in conjuntoCobertura:
        print("Desencriptando con el nodo destino...")
        kCifrada = c_keys.get(f"nodo_{nodoDest_obj.numero}")
        if not kCifrada:
            raise ValueError(f"No se encontró la clave cifrada para el nodo {nodoDest_obj.numero}")
        
        iv_clave_cifrada, ciphertext_clave_cifrada = kCifrada
        # Desencriptar con la clave del nodo destino
        k = decrypt(nodoDest_obj.clave, iv_clave_cifrada, ciphertext_clave_cifrada)
        
    else:
        # Paso 3: Si el nodo destino no está en el conjunto de cobertura, buscamos el nodo de cobertura más cercano
        print("Buscando el nodo de cobertura más cercano...")
        nodo_actual = nodoDest_obj
        
        # Subimos en el árbol hasta encontrar un nodo que esté en el conjunto de cobertura
        while nodo_actual is not None:
            # Si encontramos un nodo en el conjunto de cobertura, lo seleccionamos
            if nodo_actual in conjuntoCobertura:
                print(f"Encontramos el nodo de cobertura: {nodo_actual.numero}")
                break

            # Si no está en el conjunto de cobertura, subimos al padre
            nodo_actual = nodo_actual.padre
        
        # Si hemos encontrado un nodo en el conjunto de cobertura
        if nodo_actual in conjuntoCobertura:
            kCifrada = c_keys.get(f"nodo_{nodo_actual.numero}")
            if not kCifrada:
                raise ValueError(f"No se encontró la clave cifrada para el nodo {nodo_actual.numero}")
            
            iv_clave_cifrada, ciphertext_clave_cifrada = kCifrada
            # Desencriptar con la clave del nodo relacionado
            k = decrypt(nodo_actual.clave, iv_clave_cifrada, ciphertext_clave_cifrada)
            
        else:
            raise ValueError("No se encontró un nodo de cobertura al subir por el árbol.")
    
    # Paso 4: Desencriptar el contenido cifrado utilizando la clave 'k' obtenida
    print("Desencriptando el contenido cifrado...")

    # El contenido cifrado está en la forma: iv + datos_cifrados por cada bloque
    contenido_descifrado = b''

    # Recorremos el contenido cifrado en bloques de 32 bytes (16 bytes IV + 16 bytes de datos cifrados)
    for i in range(0, len(contenido_cifrado), 32):  # Cada bloque tiene 16 bytes de IV + 16 bytes de datos cifrados
        iv = contenido_cifrado[i:i+16]  # IV
        ciphertext = contenido_cifrado[i+16:i+32]  # Datos cifrados

        # Desencriptar cada bloque con la clave 'k'
        bloque_descifrado = decrypt(k,iv,ciphertext)

        # Añadimos el bloque descifrado al contenido final
        contenido_descifrado += bloque_descifrado

    # Después de desencriptar, es posible que el contenido esté relleno (padding)
    # Debemos eliminar el relleno, por ejemplo, con PKCS7
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    contenido_descifrado = unpadder.update(contenido_descifrado) + unpadder.finalize()

    return contenido_descifrado

##########################################################################
#                        COMPARACIÓN DE IMÁGENES                         #
##########################################################################
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

##########################################################################
#                                 MAIN                                   #
##########################################################################

if __name__ == "__main__":
    # Entrada: Número de dispositivos (hojas)
    dispositivos = int(input("Introduce el número de dispositivos (hojas): "))

    # Verificamos si el número de dispositivos es una potencia de 2
    if dispositivos % 2 != 0:
        print("El número de dispositivos debe ser una potencia de 2.")
    else:
        # Calculamos el número de niveles del árbol basándonos en el número de hojas
        lvls = int(math.log2(dispositivos)) + 1  # +1 para incluir la raíz del árbol
        arbol = crearArbol(lvls)

    print(f"El árbol tendrá {lvls} niveles y {dispositivos} hojas.")

    # Para imprimir los nodos y verificar que todos están en el árbol
    # Mostrar la estructura del árbol
    for nodo in arbol:
        print(f"Nodo {nodo.numero}:")
        print(f"  Padre: {nodo.padre.numero if nodo.padre else None}")
        print(f"  Hijos: {nodo.hijoIzq.numero if nodo.hijoIzq else None}, {nodo.hijoDer.numero if nodo.hijoDer else None}")
        print("-" * 30)

    conjuntoRev_input = input("Introduce un dispositivo o dispositivos a revocar: ")
    conjunto_revocados = obtener_nodos_revocados(conjuntoRev_input)
    conjunto_cobertura = revocar_nodos(conjunto_revocados, arbol)
    
    # Imprimir el conjunto de cobertura
    print("Conjunto de cobertura para proteger los dispositivos no revocados:")
    for nodo in conjunto_cobertura:
        print(f"- Nodo {nodo.numero}")
 
    file = input("Ingresa un archivo para cifrar (ingresa para omitir): ")
    if file:
        file = os.path.join(os.getcwd(), "image.jpg")
       # file = f"C:/Users/nuria/Desktop/master/SI/practicas/practica1/SI/lab3/image.jpg"
    
    # Encriptación del contenido del fichero con los nodos del conjunto de cobertura
    res = encryptionProcedure(conjunto_cobertura,file)
    # imprimirArbol(arbol)

    # Pregunta al usuario qué dispositivo quiere que sea el destinatario (debe ser un nodo hoja)
    print("Listado de nodos hoja: ")
    imprimir_nodos_hoja(arbol, conjunto_revocados)
    nodoDest = int(input("¿Qué dispositivo quieres que reciba el mensaje?"))

    """clave_cifrada = next(iter(res["claves_cifradas"].values()))  # Obtener el primer par (IV, ciphertext)
    iv_clave_cifrada, ciphertext_clave_cifrada = clave_cifrada
    #??
    nodo_destino = arbol[nodoDest - 1]  # Obtiene el nodo destinatario específico
    k = decrypt(nodo_destino.clave, iv_clave_cifrada, ciphertext_clave_cifrada)  # Desencriptar la clave `k`"""

    # Desencriptar el contenido usando `k`
    contenido_descifrado = decryptionProcedure(arbol, res["contenido_cifrado"][1], res["claves_cifradas"], nodoDest, conjunto_cobertura)
    # Guardar contenido descifrado en un nuevo archivo
    with open("contenido_descifrado.jpg", "wb") as file:
        print("Writing file...")
        file.write(contenido_descifrado)

    #ruta_imagen_original = "C:/Users/nuria/Desktop/master/SI/practicas/practica1/SI/lab3/image.jpg"
    #ruta_imagen_descifrado = "C:/Users/nuria/Desktop/master/SI/practicas/practica1/SI/contenido_descifrado.jpg"
    #comparar_imagenes(ruta_imagen_original, ruta_imagen_descifrado)
    comparar_imagenes("image.jpg", "contenido_descifrado.jpg")

   
