"""This module provides methods for symmetric cryptography.

The default symmetric cryptography method used is Fernet by the cryptography
library. Reference: https://cryptography.io/en/latest/fernet/
"""

import base64 as _base64
import logging
import os as _os
from warnings import warn as _warn

import cryptography.fernet as _fernet
import cryptography.hazmat.primitives.ciphers as _ciphers

from .errors import SymmetricCryptographyError


logger = logging.getLogger(__name__)


class Fernet:
    """The default symmetric cryptography method."""

    @staticmethod
    def generate_key():
        """Return a new encryption key.

        Returns:
            bytes: Key suitable for Fernet encryption/decryption.
        """
        key = _fernet.Fernet.generate_key()
        return key

    def __init__(self, key=None):
        """Initialise the cipher with an optional pre-generated key.

        Args:
            key: Optional base64-encoded key material.
        """
        if key:
            fernet_key_error = SymmetricCryptographyError("Fernet key must be 32 url-safe base64-encoded bytes.")
            try:
                raw_key = _base64.b64decode(key)
            except Exception as e:
                raise fernet_key_error from e
            else:
                if len(raw_key) != 32:
                    raise fernet_key_error
        else:
            key = self.__class__.generate_key()

        self._symmetric = _fernet.Fernet(key)

    def encrypt(self, plaintext, *args, **kwargs):
        """Encrypt the given plaintext.

        Args:
            plaintext: Bytes representing the message to encrypt.
            *args: Deprecated positional arguments.
            **kwargs: Deprecated keyword arguments.

        Returns:
            bytes: Encrypted ciphertext.
        """
        if args or kwargs:
            _deprecation_msg = (
                "The '.encrypt' method does not take into account any arguements, "
                "other than the 'ciphertext' param. "
                "Remove any other arguements. "
                "In the next version, this method will not allow them."
            )
            logger.warning(_deprecation_msg)
            _warn(_deprecation_msg, DeprecationWarning)

        ciphertext = self._symmetric.encrypt(plaintext)
        return ciphertext

    def decrypt(self, ciphertext, *args, **kwargs):
        """Decrypt the given ciphertext.

        Args:
            ciphertext: Bytes representing the encrypted payload.
            *args: Deprecated positional arguments.
            **kwargs: Deprecated keyword arguments.

        Returns:
            bytes: Decrypted plaintext.
        """
        if args or kwargs:
            _deprecation_msg = (
                "The '.decrypt' method does not take into account any arguements, "
                "other than the 'ciphertext' param. "
                "Remove any other arguements. "
                "In the next version, this method will not allow them."
            )
            logger.warning(_deprecation_msg)
            _warn(_deprecation_msg, DeprecationWarning)

        plaintext = self._symmetric.decrypt(ciphertext)
        return plaintext

    def build_cipher(self, *args, **kwargs):
        """Warn callers that custom cipher construction is unsupported."""
        _deprecation_msg = (
            "The 'Fernet' class does not need a build_cipher method."
            "Remove any calls to this method. "
            "In the next version, this method will be removed."
        )
        logger.warning(_deprecation_msg)
        _warn(_deprecation_msg, DeprecationWarning)


class AESCipher:
    """[deprecated] Symmetric cryptography method using AES.

    The default parameter set is AES 128bit in CBC mode.
    """

    POSTFIX_MODE = {
        "cbc": _ciphers.modes.CBC,
        "cfb": _ciphers.modes.CFB,
    }

    AES_BLOCK_SIZE = int(_ciphers.algorithms.AES.block_size / 8)

    @classmethod
    def _deprecation_notice(cls):
        """Warn about deprecation of this class."""
        _deprecation_msg = (
            "{name} {type} is deprecated. "
            "It will be removed in the next version. "
            "Use saml2.cryptography.symmetric.Default "
            "or saml2.cryptography.symmetric.Fernet "
            "instead."
        ).format(name=cls.__name__, type=type(cls).__name__)
        logger.warning(_deprecation_msg)
        _warn(_deprecation_msg, DeprecationWarning)

    def __init__(self, key):
        """Initialise the legacy AES cipher helper.

        Args:
            key: Raw encryption key bytes.
        """
        self.__class__._deprecation_notice()
        self.key = key

    def build_cipher(self, alg="aes_128_cbc"):
        """Construct a cryptography cipher for the requested algorithm.

        Args:
            alg: Cipher algorithm descriptor, e.g. ``"aes_128_cbc"``.

        Returns:
            tuple[Cipher, bytes]: Cipher instance and random IV.
        """
        self.__class__._deprecation_notice()
        typ, bits, cmode = alg.lower().split("_")
        bits = int(bits)
        iv = _os.urandom(self.AES_BLOCK_SIZE)

        if len(iv) != self.AES_BLOCK_SIZE:
            raise Exception(f"Wrong iv size: {len(iv)}")

        if bits not in _ciphers.algorithms.AES.key_sizes:
            raise Exception(f"Unsupported key length: {bits}")

        if len(self.key) != bits / 8:
            raise Exception(f"Wrong Key length: {len(self.key)}")

        try:
            mode = self.POSTFIX_MODE[cmode]
        except KeyError:
            raise Exception(f"Unsupported chaining mode: {cmode}")

        cipher = _ciphers.Cipher(_ciphers.algorithms.AES(self.key), mode(iv))

        return cipher, iv

    def encrypt(self, msg, alg="aes_128_cbc", padding="PKCS#7", b64enc=True, block_size=AES_BLOCK_SIZE):
        """Encrypt a message using the legacy AES helper.

        Args:
            msg: Plaintext message to encrypt.
            alg: Cipher algorithm descriptor.
            padding: Padding strategy name (``"PKCS#7"`` or ``"PKCS#5"``).
            b64enc: Whether the result should be base64 encoded.
            block_size: Block size to use with PKCS#7 padding.

        Returns:
            bytes: Encrypted (optionally base64 encoded) message.
        """
        self.__class__._deprecation_notice()
        if padding == "PKCS#7":
            _block_size = block_size
        elif padding == "PKCS#5":
            _block_size = 8
        else:
            _block_size = 0

        if _block_size:
            plen = _block_size - (len(msg) % _block_size)
            c = chr(plen).encode()
            msg += c * plen

        cipher, iv = self.build_cipher(alg)
        encryptor = cipher.encryptor()
        cmsg = iv + encryptor.update(msg) + encryptor.finalize()

        if b64enc:
            enc_msg = _base64.b64encode(cmsg)
        else:
            enc_msg = cmsg

        return enc_msg

    def decrypt(self, msg, alg="aes_128_cbc", padding="PKCS#7", b64dec=True):
        """Decrypt a message using the legacy AES helper.

        Args:
            msg: Message to decrypt (base64 encoded by default).
            alg: Cipher algorithm descriptor.
            padding: Padding strategy name.
            b64dec: Whether to base64 decode the input before decryption.

        Returns:
            bytes: Decrypted plaintext.
        """
        self.__class__._deprecation_notice()
        data = _base64.b64decode(msg) if b64dec else msg

        cipher, iv = self.build_cipher(alg=alg)
        decryptor = cipher.decryptor()
        res = decryptor.update(data)[self.AES_BLOCK_SIZE :]
        res += decryptor.finalize()
        if padding in ["PKCS#5", "PKCS#7"]:
            idx = bytearray(res)[-1]
            res = res[:-idx]
        return res


class Default(Fernet):
    """Default class is saml2.cryptography.symmetric.Fernet"""
