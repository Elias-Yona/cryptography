from .context import SHA1Context, SHA1_HASH_SIZE
from .utils import SHA1CircularShift

SHA_SUCCESS = 0
SHA_NULL = 1
SHA_INPUT_TOO_LONG = 2
SHA_STATE_ERROR = 3


def SHA1Reset(context):
    """
    Initialize the SHA1Context in preparation for computing a new SHA1 message digest.

    Parameters:
        context (Sha1Context): The context to reset. This parameter acts both as input and output,
                               as the function modifies the state of the context object.

    Returns:
        int: sha Error Code. The function returns an integer representing the status of the operation.
             A value of 0 typically indicates success, while other values indicate errors.
    """

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
    """
    Accept an array of octets as the next portion of the message.

    Parameters:
        context (Sha1Context): The SHA context to update. This parameter acts both as input and output,
                               as the function modifies the state of the context object.
        message_array (bytes): An array of characters representing the next portion of the message.
                              This parameter acts as input, providing the data to be hashed.
        length (int): The length of the message in message_array. This parameter specifies the size of the input data.

    Returns:
        int: sha Error Code. The function returns an integer representing the status of the operation.
             A value of 0 typically indicates success, while other values indicate errors.
    """

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
    """
    Process the next 512 bits of the message stored in the message_block array.

    Description:
        This function processes the next 512 bits of the message, which is assumed to be stored in an internal
        or globally accessible message_block array. The processing involves updating the hash computation based
        on the contents of this block.

    Parameters:
        None. This function does not accept external parameters; it operates on the message_block array directly.

    Returns:
        Nothing. This function does not return a value. Its primary role is to update the internal state of the hash computation.

    Comments:
        Many of the variable names in this code, especially the single character names, were used because those were the
        names used in the publication. This adherence to the original naming conventions helps maintain consistency with
        the theoretical underpinnings of the SHA-1 algorithm as described in relevant cryptographic literature.
    """

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
    """
    Return the 160-bit message digest into the message_digest array provided by the caller.

    Note: The first octet of the hash is stored in the 0th element,
          the last octet of the hash in the 19th element.

    Parameters:
        context (Sha1Context): The context to use to calculate the SHA-1 hash. This parameter acts both as input and output,
                               as the function modifies the state of the context object.
        message_digest (list): Where the digest is returned. This parameter acts as output, where the computed hash will be stored.

    Returns:
        int: sha Error Code. The function returns an integer representing the status of the operation.
             A value of 0 typically indicates success, while other values indicate errors.
    """

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
    """
    Pad the message according to SHA-1 specifications and process the padded message block.

    Description:
        According to the SHA-1 standard, the message must be padded to an even 512 bits. The first padding bit must be a '1'.
        The last 64 bits represent the length of the original message. All bits in between should be 0. This function pads the
        message according to those rules by filling the message_block array accordingly. It also calls the provided
        ProcessMessageBlock function to process the padded message block. Upon return, it can be assumed that the message
        digest has been computed.

    Parameters:
        context (Sha1Context): The context to pad. This parameter acts both as input and output, as the function modifies
                               the state of the context object.
        ProcessMessageBlock (function): The appropriate SHA*ProcessMessageBlock function to call for processing the padded
                                        message block. This parameter acts as input, specifying the processing function to use.

    Returns:
        Nothing. This function does not return a value. Its primary role is to modify the context and trigger the processing
               of the padded message block.
    """
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
