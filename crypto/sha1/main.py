import argparse
from .context import SHA1Context
from .sha1 import SHA1Reset, SHA1Input, SHA1Result

def compute_sha1(message):
    sha = SHA1Context()
    message_digest = [0] * 20

    err = SHA1Reset(sha)
    if err:
        print(f"SHA1Reset Error {err}.")
        return

    message_bytes = [ord(c) for c in message]
    length = len(message_bytes)
    err = SHA1Input(sha, message_bytes, length)
    if err:
        print(f"SHA1Input Error {err}.")
        return

    err = SHA1Result(sha, message_digest)
    if err:
        print(f"SHA1Result Error {err}, could not compute message digest.")
    else:
        print("\t", end="")
        for i in message_digest:
            print(f"{i:02X} ", end="")
        print()

def main():
    parser = argparse.ArgumentParser(description='Compute SHA-1 hash for a given message.')
    parser.add_argument('message', type=str, help='The message to hash')
    args = parser.parse_args()

    compute_sha1(args.message)

if __name__ == "__main__":
    main()
