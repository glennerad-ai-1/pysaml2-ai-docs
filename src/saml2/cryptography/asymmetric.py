"""Helpers for asymmetric cryptography operations used in SAML flows."""

import cryptography.hazmat.primitives.asymmetric as _asymmetric
import cryptography.hazmat.primitives.hashes as _hashes
import cryptography.hazmat.primitives.serialization as _serialization


def load_pem_private_key(data, password=None):
    """Load an RSA private key from PEM data.

    :param data: PEM encoded key material.
    :param password: Optional passphrase protecting the key.
    :return: The loaded private key object.
    """
    key = _serialization.load_pem_private_key(data, password)
    return key


def key_sign(rsakey, message, digest):
    """Sign a message using PKCS#1 v1.5 padding.

    :param rsakey: RSA private key used to sign the message.
    :param message: Payload to sign.
    :param digest: Hash algorithm instance.
    :return: The calculated signature as bytes.
    """
    padding = _asymmetric.padding.PKCS1v15()
    signature = rsakey.sign(message, padding, digest)
    return signature


def key_verify(rsakey, signature, message, digest):
    """Verify a PKCS#1 v1.5 signature using an RSA key.

    :param rsakey: RSA key (private or public) used for verification.
    :param signature: Signature bytes to check.
    :param message: Original message bytes that were signed.
    :param digest: Hash algorithm instance.
    :return: ``True`` when the signature is valid, otherwise ``False``.
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
