SHA1_HASH_SIZE = 20

class SHA1Context:
    def __init__(self):
        # Intermediate Hash to store the message digest
        self.intermediate_hash = [0] * (SHA1_HASH_SIZE // 4)

        # Message length in bits
        self.length_low = 0
        self.length_high = 0

        # Index into message block array
        self.message_block_index = 0

        # 512-bit message blocks
        self.message_block = [0] * 64

        # Flags to check if the digest is computed or corrupted
        self.computed = 0
        self.corrupted = 0
