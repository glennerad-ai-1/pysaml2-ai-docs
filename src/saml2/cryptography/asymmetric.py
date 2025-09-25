"""Helpers for asymmetric cryptography operations used in SAML flows."""

import cryptography.hazmat.primitives.asymmetric as _asymmetric
import cryptography.hazmat.primitives.hashes as _hashes
import cryptography.hazmat.primitives.serialization as _serialization


def load_pem_private_key(data, password=None):
    """Load an RSA private key from PEM data.

    Args:
        data: PEM encoded key material.
        password: Optional passphrase protecting the key.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: Loaded key
        object.
    """
    key = _serialization.load_pem_private_key(data, password)
    return key


def key_sign(rsakey, message, digest):
    """Sign a message using PKCS#1 v1.5 padding.

    Args:
        rsakey: RSA private key used to sign the message.
        message: Bytes payload to sign.
        digest: Hash algorithm instance.

    Returns:
        bytes: Calculated signature.
    """
    padding = _asymmetric.padding.PKCS1v15()
    signature = rsakey.sign(message, padding, digest)
    return signature


def key_verify(rsakey, signature, message, digest):
    """Verify a PKCS#1 v1.5 signature using an RSA key.

    Args:
        rsakey: RSA key (private or public) used for verification.
        signature: Signature bytes to check.
        message: Original message bytes that were signed.
        digest: Hash algorithm instance.

    Returns:
        bool: ``True`` when the signature is valid, otherwise ``False``.
    """
    padding = _asymmetric.padding.PKCS1v15()
    if isinstance(rsakey, _asymmetric.rsa.RSAPrivateKey):
        rsakey = rsakey.public_key()

    try:
        rsakey.verify(signature, message, padding, digest)
    except Exception:
        return False
    else:
        return True


hashes = _hashes
