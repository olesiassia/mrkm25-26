from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256


def load_private_key(path: str):
    with open(path, "rt") as f:
        return ECC.import_key(f.read())


def load_public_key(path: str):
    with open(path, "rt") as f:
        return ECC.import_key(f.read())


def hash_message(message: bytes):
    return SHA256.new(message)
