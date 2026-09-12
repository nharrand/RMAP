"""
Exception hierarchy for the rmap library.

All exceptions raised deliberately by this library inherit from RMAPError,
so callers (e.g. a Flask route) can do:

    try:
        ...
    except rmap.RMAPError as e:
        return {"error": str(e)}, 400

and still catch more specific exceptions first if they want different
HTTP status codes for different failure modes.
"""


class RMAPError(Exception):
    """Base class for all exceptions explicitly raised by the rmap library."""


class MalformedMessageException(RMAPError):
    """
    Raised when a message does not conform to the expected RMAP wire format:
    missing 'payload' field, invalid base64/ASCII-armor, or a decrypted
    payload that is not valid JSON / not a JSON object.
    """


class UnknownIdentityException(RMAPError):
    """Raised when an operation references an identity that has not been
    loaded via loadIdentity()/loadIdentities()."""


class DecryptionException(RMAPError):
    """Raised when a well-formed PGP message cannot be decrypted (wrong key,
    corrupted ciphertext, unsupported algorithm, etc.)."""


class UnsupportedKeyException(RMAPError):
    """Raised when a key file cannot be parsed as a valid PGP key."""


class PassphraseRequiredException(RMAPError):
    """Raised when a private key is passphrase-protected but no passphrase
    (or an incorrect one) was supplied."""


class ProtocolStateException(RMAPError):
    """Raised when a message is received out of the expected protocol
    sequence (e.g. msg2 before msg1, or msg2 referencing a session that
    does not exist)."""
