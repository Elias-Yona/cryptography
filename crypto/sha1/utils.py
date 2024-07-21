def SHA1CircularShift(bits, word):
    """ SHA1 circular left shift """
    return ((word << bits) & 0xFFFFFFFF) | (word >> (32 - bits))
