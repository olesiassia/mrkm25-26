import argparse
from Crypto.PublicKey import ECC


def generate_keys(priv_path: str, pub_path: str):
    key = ECC.generate(curve='P-256')
    pub = key.public_key()

    with open(priv_path, "wt") as f:
        f.write(key.export_key(format='PEM'))

    with open(pub_path, "wt") as f:
        f.write(pub.export_key(format='PEM'))

    print(f"[+] Приватний ключ збережено у {priv_path}")
    print(f"[+] Публічний ключ збережено у {pub_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Генерація ключів ECC")
    parser.add_argument("--priv", required=True, help="Шлях до приватного ключа")
    parser.add_argument("--pub", required=True, help="Шлях до публічного ключа")

    args = parser.parse_args()
    generate_keys(args.priv, args.pub)
