"""
rmap - Reference implementation of the (intentionally flawed) Roger Michael
Authentication Protocol, for use in Software Security coursework.

Public API:
    RMAPServer      - server-side protocol state machine
    ClientInfo      - per-identity state tracked by the server
    RMAPClient      - client-side helper (used by the CLI test client)

Exceptions (see rmap.exceptions):
    RMAPError, MalformedMessageException, UnknownIdentityException,
    DecryptionException, UnsupportedKeyException, PassphraseRequiredException,
    ProtocolStateException
"""

from .exceptions import (
    RMAPError,
    MalformedMessageException,
    UnknownIdentityException,
    DecryptionException,
    UnsupportedKeyException,
    PassphraseRequiredException,
    ProtocolStateException,
)
from .server import RMAPServer, ClientInfo
from .client import RMAPClient

__all__ = [
    "RMAPServer",
    "ClientInfo",
    "RMAPClient",
    "RMAPError",
    "MalformedMessageException",
    "UnknownIdentityException",
    "DecryptionException",
    "UnsupportedKeyException",
    "PassphraseRequiredException",
    "ProtocolStateException",
]

__version__ = "1.0.0"
