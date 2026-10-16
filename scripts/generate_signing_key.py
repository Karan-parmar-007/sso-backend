"""Print env lines for a fresh RS256 signing key.

    python -m scripts.generate_signing_key
    # on the VPS, before the first RS256-capable deploy:
    docker run --rm ghcr.io/karan-parmar-007/sso-backend:latest python -m scripts.generate_signing_key

Standalone on purpose (no `app` imports): the app refuses to start in
production without a key, and this script is how you get one.

For a rotation, run it with the current JWT_PRIVATE_KEY_B64 / JWT_ACTIVE_KID
in the environment; it also prints the JWT_PREVIOUS_PUBLIC_KEYS line that keeps
the old key published until tokens it signed have expired.
"""

import base64
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    print(f"JWT_ACTIVE_KID=k{secrets.token_hex(6)}")
    print(f"JWT_PRIVATE_KEY_B64={base64.b64encode(pem).decode()}")

    current = os.environ.get("JWT_PRIVATE_KEY_B64", "").strip()
    current_kid = os.environ.get("JWT_ACTIVE_KID", "").strip()
    if current and current_kid:
        old = serialization.load_pem_private_key(base64.b64decode(current), password=None)
        public_pem = old.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        print(
            "# keep the previous key published until its tokens expire (> 15 min):\n"
            f"JWT_PREVIOUS_PUBLIC_KEYS={current_kid}:{base64.b64encode(public_pem).decode()}"
        )


if __name__ == "__main__":
    main()
