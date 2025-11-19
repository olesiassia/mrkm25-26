import argparse
import keygen
import sign
import verify


def main():
    parser = argparse.ArgumentParser(description="ECDSA CLI")
    sub = parser.add_subparsers(dest="command")

    # --- keygen ---
    p_keygen = sub.add_parser("keygen")
    p_keygen.add_argument("--priv", required=True)
    p_keygen.add_argument("--pub", required=True)

    # --- sign ---
    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--key", required=True)
    p_sign.add_argument("--in", dest="inp", required=True)
    p_sign.add_argument("--out", required=True)

    # --- verify ---
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--pub", required=True)
    p_verify.add_argument("--in", dest="inp", required=True)
    p_verify.add_argument("--sig", required=True)

    args = parser.parse_args()

    if args.command == "keygen":
        keygen.generate_keys(args.priv, args.pub)

    elif args.command == "sign":
        sign.sign_message(args.key, args.inp, args.out)

    elif args.command == "verify":
        verify.verify_message(args.pub, args.inp, args.sig)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
