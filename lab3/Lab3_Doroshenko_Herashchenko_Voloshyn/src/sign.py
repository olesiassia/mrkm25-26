import argparse
from Crypto.Signature import DSS
from utils import load_private_key, hash_message


def sign_message(private_key_path: str, message_path: str, output_path: str):
    key = load_private_key(private_key_path)

    with open(message_path, "rb") as f:
        msg = f.read()

    h = hash_message(msg)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)

    with open(output_path, "wb") as f:
        f.write(signature)

    print(f"[+] Підпис збережено у {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Підписати файл")
    parser.add_argument("--key", required=True, help="Приватний ключ")
    parser.add_argument("--in", dest="inp", required=True, help="Вхідний файл")
    parser.add_argument("--out", required=True, help="Файл з підписом")

    args = parser.parse_args()
    sign_message(args.key, args.inp, args.out)
