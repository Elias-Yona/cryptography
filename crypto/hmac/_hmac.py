import hashlib

# ipad and opad -> two fixed and different strings (the 'i' and 'o' are mnemonics 
# for inner and outer):
# opad = the byte 0x5C repeated B times.
trans_5C = bytes((x ^ 0x5C) for x in range(256))
# ipad = the byte 0x36 repeated B times
trans_36 = bytes((x ^ 0x36) for x in range(256))

def generate_hmac(key, msg, digest):
    """Implementation of HMAC.

    key: bytes or buffer, The key for the keyed hash object.
    msg: bytes or buffer, Input message.
    digest: A hash name suitable for hashlib.new()
    """

    # H -> cryptographic hash function (MD5, SHA-1, ...)
    if callable(digest):
        digest_cons = digest
    elif isinstance(digest, str):
        digest_cons = lambda d=b'': hashlib.new(digest, d)
    else:
        digest_cons = lambda d=b'': digest.new(d)

    inner = digest_cons()
    outer = digest_cons()
    blocksize = getattr(inner, 'block_size', 64)
    
    # K -> secret key (can be of any length upto B)
    # Applications that use keys longer than B bytes will first hash the key using H 
    # and then use the resultant L byte string as the actual key to HMAC. In any case 
    # the minimal recommended length for K is L bytes (as the hash output length).

    # B -> byte-length of blocks (B=64 for all the above mentioned examples of hash 
    # functions)

    # L -> the byte-length of hash outputs (L=16 for MD5, L=20 for SHA-1)
    if len(key) > blocksize:
        key = digest_cons(key).digest()
        
    # To compute HMAC over the data `text' we perform
    # H(K XOR opad, H(K XOR ipad, text))
    #
    # (1) append zeros to the end of K to create a B byte string
    #     (e.g., if K is of length 20 bytes and B=64, then K will be
    #      appended with 44 zero bytes 0x00)
    key = key + b'\x00' * (blocksize - len(key))
    
    # (2) XOR (bitwise exclusive-OR) the B byte string computed in step
    #     (1) with ipad
    inner.update(key.translate(trans_36))
    # (3) append the stream of data 'text' to the B byte string resulting
    #     from step (2)
    inner.update(msg)
    # (4) apply H to the stream generated in step (3)
    # (5) XOR (bitwise exclusive-OR) the B byte string computed in
    #     step (1) with opad
    outer.update(key.translate(trans_5C))
    # (6) append the H result from step (4) to the B byte string
    #     resulting from step (5)
    outer.update(inner.digest())
    print(f'HMAC (hex): {outer.hexdigest()}')
