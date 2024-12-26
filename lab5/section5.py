import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from Python_fuctions.bdct import bdct

def apartado51():
    plt.hist(img_array.flatten() , range=(0,256), bins=256)
    plt.title("Histograma del valores de píxeles")
    plt.xlabel("Valor del píxel")
    plt.ylabel("Frecuencia")
    plt.show()

def apartado52():
    img_array = np.array(img_grises).astype(float)
    img_dct = bdct(img_array)

    # Paso 6: Obtener coeficientes DCT 3x3
    dct_coefficients = img_dct[3::8, 3::8].flatten()

    # Paso 7: Redondear al entero más cercano
    dct_coefficients = np.round(dct_coefficients).astype(int)

    # Paso 8: Obtener el valor mínimo y máximo de cada coeficiente
    min_val = int(dct_coefficients.min())
    max_val = int(dct_coefficients.max())

    # Paso 9: Mostrar el histograma de los coeficientes DCT
    plt.hist(dct_coefficients, range=(min_val-0.5, max_val+0.5), bins=max_val - min_val + 1)
    plt.title("Histograma del coeficiente DCT")
    plt.xlabel("Valor del coeficiente")
    plt.ylabel("Frecuencia")
    plt.show()

def apartado53():
    img_save = Image.fromarray(img_array.astype(np.uint8))
    img_save.save("compressed_lena.jpg",quality=50)
    compressed_image = Image.open("compressed_lena.jpg").convert("L")
    compressed_array = np.array(compressed_image).astype(float)
    
    compressed_dct = bdct(compressed_array.copy())
    dct_coefficients = []
    for i in range(0, compressed_array.shape[0], 8):
        for j in range(0, compressed_array.shape[1], 8):
            dct_coefficients.append(compressed_dct[i+3, j+3])

    dct_coefficients = np.round(dct_coefficients).astype(int)
    
    min_val = np.min(dct_coefficients)
    max_val = np.max(dct_coefficients)

    plt.hist(dct_coefficients, range=(min_val-0.5, max_val+0.5), bins=max_val - min_val + 1)
    plt.title("Histograma del coeficiente DCT")
    plt.xlabel("Valor del coeficiente")
    plt.ylabel("Frecuencia")
    plt.show()

def apartado54():
    # Perform a right-down cyclic shift on the image
    shifted_array = np.roll(img_array, shift=(1, 1), axis=(0, 1))

    # Convert the shifted array to float
    shifted_array = shifted_array.astype(float)

    # Compute the DCT of the shifted image
    shifted_dct = bdct(shifted_array)

    dct_coefficients = []
    for i in range(0, shifted_array.shape[0], 8):
        for j in range(0, shifted_array.shape[1], 8):
            dct_coefficients.append(shifted_dct[i+3, j+3])

    dct_coefficients = np.round(dct_coefficients).astype(int)

    # Get the minimum and maximum values of the coefficients
    min_val = int(dct_coefficients.min())
    max_val = int(dct_coefficients.max())

    # Plot the histogram of the DCT coefficients
    plt.hist(dct_coefficients, range=(min_val-0.5, max_val+0.5), bins=max_val - min_val + 1)
    plt.title("Histograma del coeficiente DCT después del desplazamiento cíclico")
    plt.xlabel("Valor del coeficiente")
    plt.ylabel("Frecuencia")
    plt.show()

    shiftedImageSave = Image.fromarray(shifted_array.astype(np.uint8))
    shiftedImageSave.save("shifted_lena.jpg", quality=90)

    
def apartado55():
    opened_image = Image.open("shifted_lena.jpg").convert("L")
    opened_array = np.array(opened_image).astype(float)

    dct_transformed = bdct(opened_array)
    dct_coefficients = []
    for i in range(0, opened_array.shape[0], 8):
        for j in range(0, opened_array.shape[1], 8):
            dct_coefficients.append(dct_transformed[i+3, j+3])

    dct_coefficients = np.round(dct_coefficients).astype(int)

    min_val = np.min(dct_coefficients)
    max_val = np.max(dct_coefficients)

    plt.hist(dct_coefficients, range=(min_val-0.5, max_val+0.5), bins=max_val - min_val + 1)
    plt.title("Histograma del coeficiente DCT después de guardar y cargar")
    plt.xlabel("Valor del coeficiente")
    plt.ylabel("Frecuencia")
    plt.show()

    # Perform a left-up cyclic shift on the loaded image
    shiftedUpImage = np.roll(opened_array, shift=(-1, -1), axis=(0, 1))

    dct_coefficients = []
    dct_transformed = bdct(shiftedUpImage.copy())
    for i in range(0, shiftedUpImage.shape[0], 8):
        for j in range(0, shiftedUpImage.shape[1], 8):
            dct_coefficients.append(dct_transformed[i+3, j+3])

    dct_coefficients = np.round(dct_coefficients).astype(int)

    min_val = np.min(dct_coefficients)
    max_val = np.max(dct_coefficients)

    plt.hist(dct_coefficients, range=(min_val-0.5, max_val+0.5), bins=max_val - min_val + 1)
    plt.title("Histograma del coeficiente DCT después del desplazamiento cíclico hacia arriba a la izquierda")
    plt.xlabel("Valor del coeficiente")
    plt.ylabel("Frecuencia")
    plt.show()

if __name__ == '__main__':

    # Paso 1: Leer la imagen
    img = Image.open("lena.tif")
    
    # Paso 2: Convertir la imagen a escala de grises (ahorro computacional)
    img_grises = img.convert('L')

    # Paso 3: Convertir la imagen a un arreglo de numpy
    img_array = np.array(img_grises)

    # Apartado 5.1
    apartado51()

    # Apartado 5.2
    apartado52()

    # Apartado 5.3
    apartado53()

    # Apartado 5.4
    apartado54()

    # Apartado 5.5
    apartado55()


    

  