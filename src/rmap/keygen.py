"""
Small utility to generate ASCII-armored PGP keypairs for testing RMAP,
for both the server and client identities.

Usage:
    python -m rmap.keygen --name "Group_01" --email group01@example.com \\
        --out-private keys/group01_priv.asc --out-public keys/group01_pub.asc \\
        [--passphrase mysecret]
"""

import argparse
import sys

import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)


def generate_keypair(name: str, email: str, passphrase: "str | None" = None):
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new(name, email=email)
    key.add_uid(
        uid,
        usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZIP],
    )
    if passphrase:
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate an ASCII-armored PGP keypair for RMAP testing.")
    parser.add_argument("--name", required=True, help="Display name for the key's user ID")
    parser.add_argument("--email", required=True, help="Email for the key's user ID")
    parser.add_argument("--out-private", required=True, help="Output path for the private key (.asc)")
    parser.add_argument("--out-public", required=True, help="Output path for the public key (.asc)")
    parser.add_argument("--passphrase", default=None, help="Optional passphrase to protect the private key")
    args = parser.parse_args(argv)

    key = generate_keypair(args.name, args.email, args.passphrase)

    with open(args.out_private, "w") as f:
        f.write(str(key))
    with open(args.out_public, "w") as f:
        f.write(str(key.pubkey))

    print(f"Wrote private key to {args.out_private}")
    print(f"Wrote public key to  {args.out_public}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
