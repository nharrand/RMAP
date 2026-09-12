"""
Client-side helper for RMAP, used by the bundled CLI test client
(rmap.cli_client) and available for students to script their own tests
against their Flask server.

This class does not perform any networking itself - it only builds and
decrypts the protocol messages, so it can be driven with any HTTP client
(requests, curl, Flask's own test client, etc.).
"""

import logging
import secrets
from pathlib import Path
from typing import Optional, Union

import pgpy

from .crypto import load_key, encrypt_json, decrypt_json
from .logging_utils import get_logger

PathLike = Union[str, Path]


class RMAPClient:
    """
    Client-side RMAP protocol helper.

    Typical flow:

        client = RMAPClient(identity, client_private_key_path,
                             server_public_key_path, passphrase=...)

        msg1 = client.build_msg1()             # POST this to the server
        nonce_client, nonce_server = client.process_resp1(resp1_json)

        msg2 = client.build_msg2()             # POST this to the server
        link = client.process_resp2(resp2_json)
    """

    def __init__(
        self,
        identity: str,
        client_private_key_path: PathLike,
        server_public_key_path: PathLike,
        passphrase: Optional[str] = None,
        verbose: bool = False,
        logger: Optional[logging.Logger] = None,
    ):
        self.identity = identity
        self.verbose = verbose
        self.logger = get_logger(logger, verbose)

        self.clientPrivateKey = load_key(client_private_key_path)
        self.serverPublicKey = load_key(server_public_key_path)
        self._passphrase = passphrase

        self.nonceClient: Optional[int] = None
        self.nonceServer: Optional[int] = None

    def build_msg1(self) -> dict:
        """Generate a fresh nonceClient and build the encrypted msg1."""
        self.nonceClient = secrets.randbits(64)
        payload = {"identity": self.identity, "nonceClient": self.nonceClient}
        self.logger.info(
            "Built msg1 for identity '%s' (nonceClient=%d)", self.identity, self.nonceClient
        )
        return encrypt_json(payload, self.serverPublicKey)

    def process_resp1(self, resp1: dict) -> tuple:
        """
        Decrypt resp1, sanity-check the returned nonceClient matches what
        we sent, and remember nonceServer. Returns (nonceClient, nonceServer).
        """
        data = decrypt_json(resp1, self.clientPrivateKey, self._passphrase, self.logger)

        returned_nonce_client = data["nonceClient"]
        nonce_server = data["nonceServer"]

        if returned_nonce_client != self.nonceClient:
            raise ValueError(
                "Server echoed back a different nonceClient than the one we sent "
                "-- possible tampering or a server-side bug."
            )

        self.nonceServer = nonce_server
        self.logger.info("Processed resp1: nonceServer=%d", nonce_server)
        return self.nonceClient, self.nonceServer

    def build_msg2(self) -> dict:
        """Build the encrypted msg2, echoing back nonceServer."""
        if self.nonceServer is None:
            raise ValueError("build_msg2() called before a successful process_resp1().")
        payload = {"nonceServer": self.nonceServer}
        self.logger.info("Built msg2 (nonceServer=%d)", self.nonceServer)
        return encrypt_json(payload, self.serverPublicKey)

    def process_resp2(self, resp2: dict) -> str:
        """Decrypt resp2 and return the link string."""
        data = decrypt_json(resp2, self.clientPrivateKey, self._passphrase, self.logger)
        link = data["link"]
        self.logger.info("Processed resp2: link=%s", link)
        return link

    @property
    def expected_link(self) -> Optional[str]:
        """The link we independently expect, once both nonces are known."""
        if self.nonceClient is None or self.nonceServer is None:
            return None
        return f"{self.nonceClient:016x}{self.nonceServer:016x}"
