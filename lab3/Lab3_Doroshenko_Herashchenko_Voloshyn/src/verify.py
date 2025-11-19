import argparse
from Crypto.Signature import DSS
from utils import load_public_key, hash_message


def verify_message(pub_path: str, message_path: str, signature_path: str):
    pub = load_public_key(pub_path)

    with open(message_path, "rb") as f:
        msg = f.read()

    with open(signature_path, "rb") as f:
        signature = f.read()

    h = hash_message(msg)
    verifier = DSS.new(pub, 'fips-186-3')

    try:
        verifier.verify(h, signature)
        print("[✓] Підпис вірний")
    except ValueError:
        print("[✗] Підпис НЕВІРНИЙ")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Перевірка підпису")
    parser.add_argument("--pub", required=True, help="Публічний ключ")
    parser.add_argument("--in", dest="inp", required=True, help="Вхідний файл")
    parser.add_argument("--sig", required=True, help="Файл з підписом")

    args = parser.parse_args()
    verify_message(args.pub, args.inp, args.sig)
