"""
Server-side implementation of the RMAP protocol.

Typical usage inside a Flask app:

    server = RMAPServer(
        server_public_key_path="keys/server_pub.asc",
        server_private_key_path="keys/server_priv.asc",
        passphrase="hunter2",       # or None if the key isn't protected
        verbose=True,
    )
    server.loadIdentities("keys/clients/")

    @app.post("/msg1")
    def msg1():
        identity, resp1 = server.receiveMsg1(request.get_json())
        return jsonify(resp1)

    @app.post("/msg2")
    def msg2():
        identity, expected_link, resp2 = server.receiveMsg2(request.get_json())
        return jsonify(resp2)

    @app.get("/get-link/<link>")
    def get_link(link):
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
        verbose: bool = False,
        logger: Optional[logging.Logger] = None,
    ):
        self.verbose = verbose
        self.logger = get_logger(logger, verbose)

        self.identities: Dict[str, ClientInfo] = {}

        self.serverPublicKey = load_key(server_public_key_path)
        self.serverPrivateKey = load_key(server_private_key_path)
        self._server_passphrase = passphrase

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
        file. The identity name is the file name (including extension).
        """
        directory = Path(directory)
        for entry in sorted(directory.iterdir()):
            if entry.is_file():
                self.loadIdentity(entry.name, entry)

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
        Encrypt_ClientPublicKey({"link": expectedLink}).
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
        resp2 = {"link": expected_link}
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
