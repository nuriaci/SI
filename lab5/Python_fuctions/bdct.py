from scipy.fft import dct

# This function computes the 2D-DCT of non-overlapping blocks of size block_sz=(8,8) (by default)
# Note that this function does not compute the 2D-DCT of partial blocks thay arise when the input matrix (im) size is not exactly divisible by the block size (block_sz).
def bdct(im, block_sz=(8,8)):
    h, w = im.shape
    m, n = block_sz
    for x in range(0, h, m):
        for y in range(0, w, n):
            block = im[x:x+m, y:y+n]
            block[:,:] = dct(dct(block.T, norm='ortho').T, norm='ortho')
    return im


