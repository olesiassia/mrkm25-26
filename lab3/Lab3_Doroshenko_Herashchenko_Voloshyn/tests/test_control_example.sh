#!/bin/bash

echo "[1] Generating RSA key pair..."
python3 src/cli.py keygen --priv keys/priv.pem --pub keys/pub.pem

echo "[2] Signing sample_message.txt..."
python3 src/cli.py sign --key keys/priv.pem --in tests/sample_message.txt --out tests/sample.sig

echo "[3] Verifying signature..."
python3 src/cli.py verify --pub keys/pub.pem --in tests/sample_message.txt --sig tests/sample.sig

echo "Done."
