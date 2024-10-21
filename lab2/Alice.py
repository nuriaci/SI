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
    for i in range(n): 
        if s <= (p-1)/2:
            r.append(1)
        elif s > (p-1)/2:
            r.append(0) 
        s = pow(g, s, p) 
        
    print(f"Último valor de la semilla: {s}")
    return r

def generarVectorC (r):
    return r*3

def commitmentStage(r,b,n):
    # Paso 1: Formación del vector de repetición c
    c = generarVectorC(b)

    # Paso 2: Selección de semilla
    s = random.getrandbits(n)

    # Paso 3: Generar secuencia pseudoaleatoria
    Gs = blum_micali(s)

    # Paso 4: Filtrar subsecuencia de G(s) donde los bits de r son 1
    Grsub = Grs(Gs,r)

    # Paso 5: Cálculo de e
    e = xor_vectors(c,Grsub)
    # Paso 6: Envío de bits de G(s) donde los bits de r son 0
    bits_r0 = [Gs[i] for i in range(len(r)) if r[i] == 0]
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
    # Paso 2: recibir vector r de Bob
    r = mqtt.receive_message()
    r = r.decode('utf-8')
    r = [int(bit) for bit in r] 

    # Paso 3: fase de commitment
    vecE, vecB, seed = commitmentStage(r,b,n)
    messageEB0 = [vecE,vecB]
    messageSB = [seed,b]
    # Paso 4: envío de vectores generados
    mqtt.publish(ID_BOB,''.join(map(str, messageEB0)))
    print("Fase de commitment finalizada.")
    time.sleep(5)
    print("Fase de verificación iniciada.")
    mqtt.publish(ID_BOB,''.join(map(str, messageSB)))

    verifyOk = mqtt.receive_message()
    if (verifyOk=="Verificación correcta."):
        print("Verificación correcta, finalizando programa...")
        exit(-1)
    elif (verifyOk=="Verificación incorrecta."):
        print("Verificación incorrecta, finalizando programa...")
        exit(-1)


    