import random
import time
from mqtt import MQTT
from mqtt import ID_ALICE,ID_BOB

m = 16
n = 3*m
q = 3*m

# Generación de 0 o 1
def generarBitAleatorio():
    b1 = random.getrandbits(1)

    return b1

def blum_micali(s):
    n = m * 6
    p = 2011
    g = 564
    r = []
    print(s)
    for i in range(n): #??
        if s <= (p-1/2):
            r.append(1)
            print("1")
        elif s > (p-1/2):
            r.append(0)
            print("0")

        print("llego")
        #s = g**s % p  
        s = pow(g, s, p) 
        
    print(f"Semilla: {s}")
    return r

def generarVectorC (r):
    return r*3

def commitmentStage(r,b,n):
    # Paso 1: Formación del vector de repetición c
    print("paso1")
    c = generarVectorC(b)

    # Paso 2: Selección de semilla
    print("paso2")
    s = random.getrandbits(n)

    # Paso 3: Generar secuencia pseudoaleatoria
    print("paso3")
    Gs = blum_micali(s)

    # Paso 4: Filtrar subsecuencia de G(s) donde los bits de r son 1
    print("paso4")
    Grsub = Grs(Gs,r)

    # Paso 5: Cálculo de e
    print("paso5")
    e = xor_vectors(c,Grsub)

    # Paso 6: Envío de bits de G(s) donde los bits de r son 0
    print("paso6")
    bits_r0 = [Gs[i] for i in range(len(r)) if r[i] == 0]

    print("return")
    return e, bits_r0, s

# Filtración de subsecuencia de G(s) en donde los bits de r son igual a 1
def Grs(Gs,r):
    return [Gs[i] for i in range(len(r)) if r[i] == 1]

def xor_vectors(v1, v2):
    return [v1[i] ^ v2[i] for i in range(len(v1))]

   

if __name__ == "__main__":
    print("¡Bienvenida Alice!")
    
    mqtt: MQTT = MQTT(ID_ALICE)
    mqtt.connect()
    time.sleep(2)
    # Paso 1: generar secuencia de bits
    b = []
    for i in range(m):
        b.append(generarBitAleatorio())
    print(f"Cadena de bits generada: {b}")
    # Paso 2: recibir vector r de Bob
    r = mqtt.receive_message()
    print (r)
    r = r.decode('utf-8')
    r = [int(bit) for bit in r] 
    print (r)   
    
    # Paso 3: fase de commitment
    vecE, vecB, seed = commitmentStage(r,b,n)
    messageSB = [seed,vecB]
    # Paso 4: envío de vectores generados
    mqtt.connect()
    mqtt.publish(ID_BOB,''.join(map(str, vecE)))
    mqtt.publish(ID_BOB,''.join(map(str, messageSB)))

    