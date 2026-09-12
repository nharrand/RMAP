"""
Server-side implementation of the RMAP protocol.

IMPORTANT: RMAP itself does not implement, require, or assume any HTTP
route for retrieving whatever the link ultimately unlocks, nor any
particular route names for the handshake endpoints themselves. This
library only handles the 4-message PGP handshake (msg1/resp1/msg2/resp2)
and computing the resulting `expectedLink` string. Your endpoint names
(e.g. "/msg1" vs "/api/rmap-initiate") and what the link value even
represents (a document ID, a session token, part of a URL, or nothing
URL-related at all) are entirely up to your Flask app. `expectedLink`
itself is just an opaque string you can use as a session/lookup key
however your project needs.

The decrypted resp2 payload is `{"result": "<link>"}` (matching this
course's API spec).

Typical usage inside a Flask app (the route names and linkPrefix below
are just one example of how a project *might* choose to expose things):

    server = RMAPServer(
        server_public_key_path="keys/server_pub.asc",
        server_private_key_path="keys/server_priv.asc",
        passphrase="hunter2",       # or None if the key isn't protected
        linkPrefix="http://localhost:5000/get-document/",
        verbose=True,
    )
    server.loadIdentities("keys/clients/")

    @app.post("/msg1")
    def msg1():
        identity, resp1 = server.receiveMsg1(request.get_json())
        return jsonify(resp1)

    @app.post("/msg2")
    def msg2():
        # expectedLink is always just the bare 32-hex-char link, even
        # though the value inside resp2 itself is prefixed with
        # linkPrefix - use expectedLink as your internal session key,
        # e.g. to remember which identity completed which handshake.
        identity, expectedLink, resp2 = server.receiveMsg2(request.get_json())
        sessions[expectedLink] = identity
        return jsonify(resp2)

    # This route, its name, and its URL shape are entirely up to your
    # project - RMAP has no opinion here. This is just one example.
    @app.get("/get-document/<id>")
    def get_document(id):
        ...
"""

import logging
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import pgpy

from .crypto import load_key, encrypt_json, decrypt_json
from .exceptions import (
    UnknownIdentityException,
    ProtocolStateException,
)
from .logging_utils import get_logger

PathLike = Union[str, Path]


@dataclass
class ClientInfo:
    """State the server tracks for a single loaded client identity."""

    identity: str
    publicKey: "pgpy.PGPKey"
    nonceClient: Optional[int] = None
    nonceServer: Optional[int] = None


class RMAPServer:
    """
    Server-side RMAP protocol state machine.

    Holds the server's own PGP keypair, a registry of known client
    identities (each with its public key), and per-identity handshake
    state (nonceClient / nonceServer) as clients go through the
    protocol.
    """

    def __init__(
        self,
        server_public_key_path: PathLike,
        server_private_key_path: PathLike,
        passphrase: Optional[str] = None,
        linkPrefix: str = "",
        verbose: bool = False,
        logger: Optional[logging.Logger] = None,
    ):
        """
        `linkPrefix` is prepended to the link value sent to the client
        inside resp2 - entirely optional, and entirely up to you. RMAP
        does not define or require any particular URL shape or endpoint
        name; set `linkPrefix` to whatever matches your own Flask app
        (e.g. "http://localhost:5000/get-document/", or leave it as ""
        to send the bare 32-hex-char link and handle routing/formatting
        yourself). It has no effect on `getExpectedLink()` or on the
        `expectedLink` value returned by `receiveMsg2()`, which always
        remain the bare 32-hex-char link - use that value as your
        internal session/lookup key regardless of what (if anything)
        you set `linkPrefix` to.
        """
        self.verbose = verbose
        self.logger = get_logger(logger, verbose)

        self.identities: Dict[str, ClientInfo] = {}

        self.serverPublicKey = load_key(server_public_key_path)
        self.serverPrivateKey = load_key(server_private_key_path)
        self._server_passphrase = passphrase
        self.linkPrefix = linkPrefix

        # Maps a nonceServer value back to the identity it was issued to,
        # so that receiveMsg2 (which only carries nonceServer) can figure
        # out which client session it belongs to.
        self._nonce_server_index: Dict[int, str] = {}

        self.logger.info("RMAPServer initialized.")

    # ------------------------------------------------------------------
    # Identity management
    # ------------------------------------------------------------------

    def loadIdentity(self, identity: str, keyFile: PathLike) -> None:
        """Load a single client's public key file and register it under `identity`."""
        public_key = load_key(keyFile)
        self.identities[identity] = ClientInfo(identity=identity, publicKey=public_key)
        self.logger.info("Loaded identity '%s' from %s", identity, keyFile)

    def loadIdentities(self, directory: PathLike) -> None:
        """
        Load every key file in `directory`, registering one identity per
        file. The identity name is the file's stem (file name without its
        extension) - e.g. a file named "Group_01.asc" registers the
        identity "Group_01".
        """
        directory = Path(directory)
        for entry in sorted(directory.iterdir()):
            if entry.is_file():
                self.loadIdentity(entry.stem, entry)

    # ------------------------------------------------------------------
    # Protocol messages
    # ------------------------------------------------------------------

    def receiveMsg1(self, msg1: dict) -> Tuple[str, dict]:
        """
        Process msg1 = Encrypt_ServerPublicKey({"identity": ..., "nonceClient": ...}).

        Returns (identity, resp1) where resp1 is the RMAP wire-format
        encrypted dict {"payload": ...} containing
        Encrypt_ClientPublicKey({"nonceClient": ..., "nonceServer": ...}).
        """
        data = decrypt_json(
            msg1, self.serverPrivateKey, self._server_passphrase, self.logger
        )

        identity = data["identity"]
        nonceClient = data["nonceClient"]

        if identity not in self.identities:
            raise UnknownIdentityException(f"Unknown identity: {identity!r}")

        client_info = self.identities[identity]
        client_info.nonceClient = nonceClient
        client_info.nonceServer = secrets.randbits(64)
        self._nonce_server_index[client_info.nonceServer] = identity

        self.logger.info("Received msg1 from identity '%s'", identity)

        resp1 = {"nonceClient": nonceClient, "nonceServer": client_info.nonceServer}
        encrypted = self.encrypt_for_identity(resp1, identity)
        return identity, encrypted

    def receiveMsg2(self, msg2: dict) -> Tuple[str, str, dict]:
        """
        Process msg2 = Encrypt_ServerPublicKey({"nonceServer": ...}).

        Returns (identity, expectedLink, resp2) where resp2 is the RMAP
        wire-format encrypted dict {"payload": ...} containing
        Encrypt_ClientPublicKey({"result": ...}).

        The value at that key is `self.linkPrefix + expectedLink` (so
        the client can receive a ready-to-use URL if `linkPrefix` was
        set). `expectedLink` itself - both the returned value here and
        `getExpectedLink()` - is always just the bare 32-hex-char link,
        unaffected by `linkPrefix`, so it can be used directly as an
        internal session/lookup key regardless of how it's presented to
        the client. RMAP itself has no opinion on what this string means
        or how it's served (a document ID, a session token, part of a
        URL, or nothing URL-related at all) - that's entirely up to your
        application.
        """
        data = decrypt_json(
            msg2, self.serverPrivateKey, self._server_passphrase, self.logger
        )

        nonceServer = data["nonceServer"]

        identity = self._nonce_server_index.get(nonceServer)
        if identity is None:
            raise ProtocolStateException(
                "No pending session matches the given nonceServer "
                "(was receiveMsg1 called first?)."
            )

        client_info = self.identities[identity]
        if client_info.nonceServer != nonceServer:
            raise ProtocolStateException(
                f"nonceServer does not match the stored session for identity '{identity}'."
            )

        self.logger.info("Received msg2 from identity '%s'", identity)

        expected_link = self.getExpectedLink(identity)
        resp2 = {"result": f"{self.linkPrefix}{expected_link}"}
        encrypted = self.encrypt_for_identity(resp2, identity)
        return identity, expected_link, encrypted

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def encrypt_for_identity(self, msg: dict, identity: str) -> dict:
        """Encrypt `msg` (a JSON-serializable dict) for the given client identity."""
        if identity not in self.identities:
            raise UnknownIdentityException(f"Unknown identity: {identity!r}")
        return encrypt_json(msg, self.identities[identity].publicKey)

    def decrypt(self, msg: dict, privateKey: "pgpy.PGPKey", passphrase: Optional[str] = None) -> dict:
        """Decrypt an RMAP wire-format message with an arbitrary private key."""
        return decrypt_json(msg, privateKey, passphrase, self.logger)

    def getExpectedLink(self, identity: str) -> str:
        """
        Return the link the server expects for `identity`, once both
        nonces are known: hex(nonceClient) || hex(nonceServer), each
        zero-padded to 16 hex characters (64-bit values), for 32 hex
        characters total.
        """
        if identity not in self.identities:
            raise UnknownIdentityException(f"Unknown identity: {identity!r}")

        client_info = self.identities[identity]
        if client_info.nonceClient is None or client_info.nonceServer is None:
            raise ProtocolStateException(
                f"Identity '{identity}' has not completed the handshake yet."
            )

        return f"{client_info.nonceClient:016x}{client_info.nonceServer:016x}"
