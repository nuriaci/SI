import random
import time
import numpy as np
from mqtt import MQTT
from mqtt import ID_ALICE,ID_BOB
from bitstring import BitArray

m = 16
n = 3*m
q = 3*m

def generarBitAleatorio(): 
    b0 = random.getrandbits(1)
    print("Bob ha generado un bit {b0}.")
    return b0

def generarVectorC (r):
    return r*3

def generarVectorR(q):
    # Generate a zero vector of length 2q
    r = np.zeros(2 * q, dtype=int)
    
    # Randomly choose q positions to set to 1
    ones_indices = np.random.choice(2 * q, q, replace=False)
    r[ones_indices] = 1

    return r

def obtenerB(b0,b1):
    b = b0 ^ b1;
    return b

def xor_vectors(v1, v2):
    return [v1[i] ^ v2[i] for i in range(len(v1))]

def blum_micali(s):
    n = m * 6
    p = 2011
    g = 564
    r = []
    s = int(s)
    for i in range(n): 
        if s <= (p-1)/2:
            r.append(1)
        elif s > (p-1)/2:
            r.append(0)

        s = pow(g, s, p) 
        
    print(f"Semilla: {s}")
    return r

# Filtración de subsecuencia de G(s) en donde los bits de r son igual a 1
def Grs(Gs,r):
    return [Gs[i] for i in range(len(r)) if r[i] == 1]

def proveAndVerify(s,r,eRecibida, bitsOG, bitsR0):

    # Paso 1: Cálculo de c'
    cprima = generarVectorC(bitsOG)

    # Paso 2: generación de PRG
    Gs = blum_micali(s)
    Grsub = Grs(Gs,r)

    # Paso 3: verificación de secuencia de bits correcta
    bitsr0BOB = []
    for i in range(len(r)):
      if r[i] == 0:
          bitsr0BOB.append(Gs[i])

    if not np.array_equal(bitsR0,bitsr0BOB):
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
    
    # Paso 2: envío de bits a Alice
    mqtt.publish_message(ID_ALICE, ''.join(str(bit) for bit in vecR))
    print("Esperando mensaje de Alice...")
    # Paso 3: recepción de mensaje de Alice que incluye (s,b)
    messageEB0 = mqtt.receive_message()
    messageSB = mqtt.receive_message()
    
    messageSB_str = messageSB.decode('utf-8')
    indexMessage = messageSB_str.index('[')
    seed = messageSB_str[:indexMessage]  
    bitSeq = messageSB_str[indexMessage:]  
    bitSeq = [int(x) for x in bitSeq.strip('[]').split(',')]

    messageEB0 = messageEB0.decode('utf-8')         # Usar el carácter "[" para separar los vectores
    separated_vectors = messageEB0.split("[")

    # Separa los vectores y limpia los corchetes "]" de los datos
    vector1_str = separated_vectors[1].replace(']', '')  # Primer vector
    vector2_str = separated_vectors[2].replace(']', '')  # Segundo vector
    vector1 = list(map(int, vector1_str.split(',')))
    vector2 = list(map(int, vector2_str.split(',')))    
    

    verifyOk = proveAndVerify(seed, vecR, vector1, bitSeq, vector2)

    
    if verifyOk==True:
        mqtt.publish(ID_ALICE,"Verificación correcta.")
    elif verifyOk==False:
        mqtt.publish(ID_ALICE,"Verificación incorrecta.")

    print("Verificación:", "Correcta" if verifyOk else "Incorrecta")


    