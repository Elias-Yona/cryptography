from .context import SHA1Context, SHA1_HASH_SIZE
from .utils import SHA1CircularShift

SHA_SUCCESS = 0
SHA_NULL = 1
SHA_INPUT_TOO_LONG = 2
SHA_STATE_ERROR = 3

def SHA1Reset(context):
    if context is None:
        return SHA_NULL

    context.length_low = 0
    context.length_high = 0
    context.message_block_index = 0

    context.intermediate_hash[0] = 0x67452301
    context.intermediate_hash[1] = 0xEFCDAB89
    context.intermediate_hash[2] = 0x98BADCFE
    context.intermediate_hash[3] = 0x10325476
    context.intermediate_hash[4] = 0xC3D2E1F0

    context.computed = 0
    context.corrupted = 0

    return SHA_SUCCESS

def SHA1Input(context, message_array, length):
    if length == 0:
        return SHA_SUCCESS

    if context is None or message_array is None:
        return SHA_NULL

    if context.computed:
        context.corrupted = SHA_STATE_ERROR
        return SHA_STATE_ERROR

    if context.corrupted:
        return context.corrupted

    index = 0
    while length > 0 and not context.corrupted:
        context.message_block[context.message_block_index] = message_array[index] & 0xFF
        context.message_block_index += 1

        context.length_low += 8
        if context.length_low == 0:
            context.length_high += 1
            if context.length_high == 0:
                context.corrupted = 1

        if context.message_block_index == 64:
            SHA1ProcessMessageBlock(context)
            context.message_block_index = 0

        index += 1
        length -= 1

    return SHA_SUCCESS

def SHA1ProcessMessageBlock(context):
    K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
    W = [0] * 80

    # Initialize the first 16 words in the array W
    for t in range(16):
        W[t] = (context.message_block[t * 4] << 24) | \
               (context.message_block[t * 4 + 1] << 16) | \
               (context.message_block[t * 4 + 2] << 8) | \
               context.message_block[t * 4 + 3]

    for t in range(16, 80):
        W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16])

    A = context.intermediate_hash[0]
    B = context.intermediate_hash[1]
    C = context.intermediate_hash[2]
    D = context.intermediate_hash[3]
    E = context.intermediate_hash[4]

    for t in range(20):
        temp = (SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0]) & 0xFFFFFFFF
        E = D
        D = C
        C = SHA1CircularShift(30, B)
        B = A
        A = temp

    for t in range(20, 40):
        temp = (SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1]) & 0xFFFFFFFF
        E = D
        D = C
        C = SHA1CircularShift(30, B)
        B = A
        A = temp

    for t in range(40, 60):
        temp = (SHA1CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2]) & 0xFFFFFFFF
        E = D
        D = C
        C = SHA1CircularShift(30, B)
        B = A
        A = temp

    for t in range(60, 80):
        temp = (SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3]) & 0xFFFFFFFF
        E = D
        D = C
        C = SHA1CircularShift(30, B)
        B = A
        A = temp

    context.intermediate_hash[0] = (context.intermediate_hash[0] + A) & 0xFFFFFFFF
    context.intermediate_hash[1] = (context.intermediate_hash[1] + B) & 0xFFFFFFFF
    context.intermediate_hash[2] = (context.intermediate_hash[2] + C) & 0xFFFFFFFF
    context.intermediate_hash[3] = (context.intermediate_hash[3] + D) & 0xFFFFFFFF
    context.intermediate_hash[4] = (context.intermediate_hash[4] + E) & 0xFFFFFFFF

    context.message_block_index = 0

def SHA1Result(context, message_digest):
    if context is None or message_digest is None:
        return SHA_NULL

    if context.corrupted:
        return context.corrupted

    if not context.computed:
        SHA1PadMessage(context)
        for i in range(64):
            context.message_block[i] = 0  # clear the message block

        context.length_low = 0   # clear the length
        context.length_high = 0
        context.computed = 1

    for i in range(SHA1_HASH_SIZE):
        message_digest[i] = (context.intermediate_hash[i >> 2] >> (8 * (3 - (i & 0x03)))) & 0xFF

    return SHA_SUCCESS

def SHA1PadMessage(context):
    if context.message_block_index > 55:
        context.message_block[context.message_block_index] = 0x80
        context.message_block_index += 1

        while context.message_block_index < 64:
            context.message_block[context.message_block_index] = 0
            context.message_block_index += 1

        SHA1ProcessMessageBlock(context)

        while context.message_block_index < 56:
            context.message_block[context.message_block_index] = 0
            context.message_block_index += 1
    else:
        context.message_block[context.message_block_index] = 0x80
        context.message_block_index += 1

        while context.message_block_index < 56:
            context.message_block[context.message_block_index] = 0
            context.message_block_index += 1

    context.message_block[56] = (context.length_high >> 24) & 0xFF
    context.message_block[57] = (context.length_high >> 16) & 0xFF
    context.message_block[58] = (context.length_high >> 8) & 0xFF
    context.message_block[59] = context.length_high & 0xFF
    context.message_block[60] = (context.length_low >> 24) & 0xFF
    context.message_block[61] = (context.length_low >> 16) & 0xFF
    context.message_block[62] = (context.length_low >> 8) & 0xFF
    context.message_block[63] = context.length_low & 0xFF

    SHA1ProcessMessageBlock(context)
