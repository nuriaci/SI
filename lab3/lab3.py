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

#def encryptionProcedure():
    # Paso 1: generación de una clave aleatoria k
    
    # Paso 2: para cada nodo de S, computar c = (kroot, k)

    # Paso 3: encriptar contenido como c = Eprima (k,m)

if __name__ == "__main__":
    niveles = int(input("Introduce el número de niveles: "))
    arbol = crearArbol(niveles)

    imprimirArbol(arbol)