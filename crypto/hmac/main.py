import argparse

from crypto.hmac import _hmac

def main():
    parser = argparse.ArgumentParser(description='Compute HMAC for a given message.')
    parser.add_argument('key', type=str, help='The key for the keyed hash object')
    parser.add_argument('message', type=str, help='Input message.')
    parser.add_argument('digest', type=str, help='Cryptographic hash function (MD5, SHA-1, ...)')
    args = parser.parse_args()

    _hmac.generate_hmac(args.key.encode(encoding='utf-8'), args.message.encode(encoding='utf-8'), args.digest)
   
    
if __name__ == "__main__":
    main()