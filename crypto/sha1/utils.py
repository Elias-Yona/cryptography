def SHA1CircularShift(bits, word):
    return ((word << bits) & 0xFFFFFFFF) | (word >> (32 - bits))
