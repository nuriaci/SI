import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from Python_fuctions.bdct import bdct


def DCT(image_path='lena.tif'):
    try:
        # Paso 1: Leer la imagen
        img = Image.open(image_path)

        # Paso 2: Convertir la imagen a escala de grises (ahorro computacional)
        img_grises = img.convert('L')

        # Paso 3: Convertir la imagen a un arreglo de numpy
        img_array = np.array(img_grises).astype(float)

        # Paso 4: Calcular la DCT de la imagen
        img_dct = bdct(img_array)

        # Paso 5: Obtener coeficientes DCT 3x3
        dct_coefficients = img_dct[3::8, 3::8].flatten()

        # Paso 6: Redondear al entero más cercano
        dct_coefficients = np.round(dct_coefficients).astype(int)

        # Paso 7: Obtener el valor mínimo y máximo de cada coeficiente
        min_val = int(dct_coefficients.min())
        max_val = int(dct_coefficients.max())

        return dct_coefficients, min_val, max_val
    except Exception as e:
        print(f"Error: {e}")
        return None, None, None


def JSTEG(img_dct_flat):
    # JSTEG
    # Paso 1: Generar bits aleatorios
    random_bits = np.random.randint(0, 2, size=img_dct_flat.shape)

    # Paso 2: Aplicar el algoritmo JSTEG
    img_dct_flat = img_dct_flat.astype(np.int32)
    for i in range(len(img_dct_flat)):
        if abs(img_dct_flat[i]) > 1:
            img_dct_flat[i] = (img_dct_flat[i] & ~1) | random_bits[i]

    return img_dct_flat


def F3(img_dct_flat):
    # F3
    # Paso 1: Generar bits aleatorios
    random_bits = np.random.randint(0, 2, size=img_dct_flat.shape)

    # Paso 2: Aplicar el algoritmo F3
    img_dct_flat = img_dct_flat.astype(np.int32)
    for i in range(len(img_dct_flat)):
        if img_dct_flat[i] != 0:
            img_dct_flat[i] = img_dct_flat[i] - 1 if random_bits[i] == 0 else img_dct_flat[i] + 1

    return img_dct_flat


if __name__ == '__main__':
    # Ejecutar DCT
    img_dct_flat, min_val, max_val = DCT()

    if img_dct_flat is not None:
        # Ejecutar JSTEG
        img_dct_flatModified = JSTEG(img_dct_flat.copy())
        # Ejecutar F3
        img_dct_flatModified_F3 = F3(img_dct_flat.copy())

        plt.figure(figsize=(15, 5))

        plt.subplot(1, 3, 1)
        plt.hist(img_dct_flat, bins=max_val - min_val + 1, range=(min_val - 0.5, max_val + 0.5), alpha=0.5, label='Original')
        plt.title('Histograma Original')
        plt.xlabel('Valor')
        plt.ylabel('Frecuencia')
        plt.legend()

        plt.subplot(1, 3, 2)
        plt.hist(img_dct_flatModified, bins=max_val - min_val + 1, range=(min_val - 0.5, max_val + 0.5), alpha=0.5, label='JSTEG')
        plt.title('Histograma JSTEG')
        plt.xlabel('Valor')
        plt.ylabel('Frecuencia')
        plt.legend()

        plt.subplot(1, 3, 3)
        plt.hist(img_dct_flatModified_F3, bins=max_val - min_val + 1, range=(min_val - 0.5, max_val + 0.5), alpha=0.5, label='F3')
        plt.title('Histograma F3')
        plt.xlabel('Valor')
        plt.ylabel('Frecuencia')
        plt.legend()

        plt.tight_layout()
        plt.show()