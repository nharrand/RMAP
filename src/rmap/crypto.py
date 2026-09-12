"""
Low-level PGP encrypt/decrypt helpers shared by RMAPServer and RMAPClient.

These implement the RMAP wire format for an "encrypted message":

    {"payload": "<base64>"}

where <base64> is the ASCII-armored PGP message body with the
BEGIN/END/header/checksum lines stripped (see rmap.armor).
"""

import json
import logging
from contextlib import nullcontext
from pathlib import Path
from typing import Optional, Union

import pgpy
from pgpy.errors import PGPError

from .armor import strip_armor, wrap_armor
from .exceptions import (
    MalformedMessageException,
    DecryptionException,
    UnsupportedKeyException,
    PassphraseRequiredException,
)

PathLike = Union[str, "Path"]


def load_key(key_path: PathLike):
    """
    Load a single ASCII-armored PGP key (public or private) from a file.
    Returns the pgpy.PGPKey object. Raises UnsupportedKeyException on
    any failure to parse the file as a PGP key.
    """
    try:
        key, _ = pgpy.PGPKey.from_file(str(key_path))
        return key
    except Exception as e:
        raise UnsupportedKeyException(
            f"Could not load PGP key from '{key_path}': {e}"
        ) from e


def encrypt_json(data: dict, public_key: "pgpy.PGPKey") -> dict:
    """
    Serialize `data` to JSON, PGP-encrypt it for `public_key`, and return
    the RMAP wire-format dict: {"payload": "<base64>"}.
    """
    plaintext = json.dumps(data)
    pgp_message = pgpy.PGPMessage.new(plaintext)
    try:
        encrypted = public_key.encrypt(pgp_message)
    except Exception as e:
        raise DecryptionException(f"Failed to encrypt message: {e}") from e

    armored = str(encrypted)
    payload = strip_armor(armored)
    return {"payload": payload}


def decrypt_json(
    msg: dict,
    private_key: "pgpy.PGPKey",
    passphrase: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> dict:
    """
    Given an RMAP wire-format dict {"payload": "<base64>"}, reconstruct
    the PGP message, decrypt it with `private_key` (unlocking with
    `passphrase` first if the key is passphrase-protected), parse the
    decrypted plaintext as JSON, and return the resulting dict.

    Raises:
        MalformedMessageException - bad 'payload' field, bad base64,
            unparsable PGP data, or decrypted plaintext that isn't a
            valid JSON object.
        PassphraseRequiredException - key is locked and no/incorrect
            passphrase was supplied.
        DecryptionException - message could not be decrypted for any
            other reason (wrong key, corrupted ciphertext, etc.)
    """
    if not isinstance(msg, dict) or "payload" not in msg:
        raise MalformedMessageException("Message is missing the 'payload' field.")

    payload = msg["payload"]
    if not isinstance(payload, str):
        raise MalformedMessageException("'payload' field must be a string.")

    try:
        armored = wrap_armor(payload)
        pgp_message = pgpy.PGPMessage.from_blob(armored)
    except MalformedMessageException:
        raise
    except Exception as e:
        raise MalformedMessageException(f"Could not parse PGP message: {e}") from e

    unlock_ctx = nullcontext()
    if getattr(private_key, "is_protected", False):
        if not passphrase:
            raise PassphraseRequiredException(
                "Private key is passphrase-protected but no passphrase was provided."
            )
        unlock_ctx = private_key.unlock(passphrase)

    try:
        with unlock_ctx:
            decrypted = private_key.decrypt(pgp_message)
    except PassphraseRequiredException:
        raise
    except PGPError as e:
        if logger:
            logger.debug("PGP decryption failed: %s", e)
        raise DecryptionException(f"Failed to decrypt message: {e}") from e
    except Exception as e:
        if logger:
            logger.debug("Unexpected error while unlocking/decrypting: %s", e)
        raise PassphraseRequiredException(
            f"Could not unlock private key (wrong passphrase?): {e}"
        ) from e

    plaintext = decrypted.message
    if isinstance(plaintext, (bytes, bytearray)):
        plaintext = plaintext.decode("utf-8")

    try:
        data = json.loads(plaintext)
    except json.JSONDecodeError as e:
        raise MalformedMessageException(
            f"Decrypted payload is not valid JSON: {e}"
        ) from e

    if not isinstance(data, dict):
        raise MalformedMessageException("Decrypted JSON payload must be a JSON object.")

    return data
