import numpy as np
from scipy.signal import convolve2d

def gauss_filter2d(image, kernel):
    return convolve2d(image, kernel, mode='same', boundary='symm')

def gauss(x, sigma):
    # Gaussian function
    return np.exp(-x**2 / (2 * sigma**2)) / (sigma * np.sqrt(2 * np.pi))

def dgauss(x, sigma):
    # First order derivative of Gaussian
    return -x * gauss(x, sigma) / sigma**2

def gaussgradient(IM, sigma):
    # Determine the size of the kernel
    epsilon = 1e-2
    halfsize = np.ceil(sigma * np.sqrt(-2 * np.log(np.sqrt(2 * np.pi) * sigma * epsilon)))
    sizefilt = int(2 * halfsize + 1)

    # Generate a 2-D Gaussian kernel along x direction
    hx = np.zeros((sizefilt, sizefilt))
    for i in range(sizefilt):
        for j in range(sizefilt):
            u = np.array([i - halfsize - 1, j - halfsize - 1])
            hx[i, j] = gauss(u[0], sigma) * dgauss(u[1], sigma)

    # Generate a 2-D Gaussian kernel along y direction
    hy = hx.T

    # Convolve the image with the kernels
    gx = gauss_filter2d(IM, hx)
    gy = gauss_filter2d(IM, hy)

    return gx, gy

def compute_mask(Image, kernelsize):
    # Function to compute the perceptual mask using a Gaussian edge detector
    imx, imy = gaussgradient(Image, kernelsize)
    mask = np.sqrt(imx ** 2 + imy ** 2)
    return mask

