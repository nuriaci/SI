import random
import time
import numpy as np
from mqtt import MQTT
from mqtt import ID_ALICE,ID_BOB

m = 16
n = 3*m
q = 3*m

def generarBitAleatorio(): 
    b0 = random.getrandbits(1)
    print("Bob ha generado un bit {b0}.")
    return b0
"""
# Generación de compromiso
def commitment (Gs,r,b0):
    #Gs = generarS(s)
    if b0 == 0:
        c = Gs
    elif b0 == 1:
        c = Gs ^ r

    return c
"""

def generarVectorC (r):
    return r*3

def generarVectorR(q):
    # Generate a zero vector of length 2q
    r = np.zeros(2 * q, dtype=int)
    
    # Randomly choose q positions to set to 1
    ones_indices = np.random.choice(2 * q, q, replace=False)
    r[ones_indices] = 1

    return r.tobytes()

def obtenerB(b0,b1):
    b = b0 ^ b1;
    return b

def xor_vectors(v1, v2):
    return [v1[i] ^ v2[i] for i in range(len(v1))]

def blum_micali(s):
    n = m ** 3
    p = 2011
    g = 564
    r = []
    if s <= (p-1/2):
        r.append(1)
    elif s > (p-1/2):
        r.append(0)

    s = g**s % p

    return r

# Filtración de subsecuencia de G(s) en donde los bits de r son igual a 1
def Grs(Gs,r):
    return [Gs[i] for i in range(len(r)) if r[i] == 1]

def proveAndVerify(s,r,eRecibida, bitsRecibidos):

    # Paso 1: Cálculo de c'
    cprima = generarVectorC(bitsRecibidos)

    # Paso 2: generación de PRG
    Gs = blum_micali(s)
    Grsub = Grs(Gs,r)

    # Paso 3: verificación de secuencia de bits correcta
    bitsr0BOB = []
    for i in range(len(r)):
      if r[i] == 0:
          bitsr0BOB.append(Gs[i])

    if not np.array_equal(bitsRecibidos,bitsr0BOB):
        return False

    # Paso 4: verificación de e
    e = xor_vectors(cprima,Grsub)

    if not np.array_equal(eRecibida, e):
        return False  

    return True


if __name__ == "__main__":

    mqtt: MQTT = MQTT(ID_BOB)
    print("¡Bienvenido Bob!")
    mqtt.connect()
    time.sleep(2)
    # Paso 1: Generación de bits de vector r
    vecR = generarVectorR(q)
    print(type(vecR))
    # Paso 2: envío de bits a Alice
    
    mqtt.publish_message(ID_ALICE, vecR)
    print("ENVÍO")
    # Paso 3: recepción de mensaje de Alice que incluye (s,b)
    messageE = mqtt.receive_message()
    messageSB = mqtt.receive_message()
    # msg.payload
    seed = messageSB[:n]
    bitSeq = messageSB[n:]
    verifyOk = proveAndVerify(seed, vecR, messageE, bitSeq)

    print("Verificación:", "Correcta" if verifyOk else "Incorrecta")



    