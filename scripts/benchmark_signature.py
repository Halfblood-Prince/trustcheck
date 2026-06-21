from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
from typing import Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sign(result: Path, private_key_pem: bytes, signature: Path) -> None:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("benchmark signing key must be RSA")
    value = key.sign(result.read_bytes(), padding.PKCS1v15(), hashes.SHA256())
    signature.write_text(base64.b64encode(value).decode("ascii") + "\n", encoding="ascii")


def verify(result: Path, public_key: Path, signature: Path) -> None:
    key = serialization.load_pem_public_key(public_key.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("benchmark public key must be RSA")
    try:
        key.verify(
            base64.b64decode(signature.read_text(encoding="ascii").strip(), validate=True),
            result.read_bytes(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("benchmark result signature is invalid") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign or verify raw benchmark results.")
    parser.add_argument("result")
    parser.add_argument("--signature", required=True)
    parser.add_argument("--public-key")
    parser.add_argument("--private-key-env")
    args = parser.parse_args(argv)
    result = Path(args.result)
    signature = Path(args.signature)
    if args.private_key_env:
        value = os.environ.get(args.private_key_env)
        if not value:
            parser.error(f"environment variable {args.private_key_env} is not set")
        sign(result, value.encode("utf-8"), signature)
        return 0
    if not args.public_key:
        parser.error("--public-key is required when verifying")
    verify(result, Path(args.public_key), signature)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
