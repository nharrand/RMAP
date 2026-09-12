"""
Shared pytest fixtures: generate throwaway PGP keypairs (server + two
clients, one passphrase-protected) in a temporary directory, and wire up
ready-to-use RMAPServer / RMAPClient instances.
"""

import pytest

from rmap.keygen import generate_keypair
from rmap.server import RMAPServer
from rmap.client import RMAPClient

CLIENT_PASSPHRASE = "correct horse battery staple"


def _write_keypair(tmp_path, filename_prefix, name, email, passphrase=None):
    key = generate_keypair(name, email, passphrase)
    priv_path = tmp_path / f"{filename_prefix}_priv.asc"
    pub_path = tmp_path / f"{filename_prefix}_pub.asc"
    priv_path.write_text(str(key))
    pub_path.write_text(str(key.pubkey))
    return priv_path, pub_path


@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    """Generate a server keypair and two client keypairs once per test session."""
    tmp_path = tmp_path_factory.mktemp("keys")

    server_priv, server_pub = _write_keypair(tmp_path, "server", "Server", "server@example.com")
    client_priv, client_pub = _write_keypair(tmp_path, "group01", "Group_01", "g1@example.com")
    protected_priv, protected_pub = _write_keypair(
        tmp_path, "group02", "Group_02", "g2@example.com", passphrase=CLIENT_PASSPHRASE
    )

    clients_dir = tmp_path / "clients"
    clients_dir.mkdir()
    (clients_dir / "Group_01.asc").write_text(client_pub.read_text())
    (clients_dir / "Group_02.asc").write_text(protected_pub.read_text())

    return {
        "server_priv": server_priv,
        "server_pub": server_pub,
        "client_priv": client_priv,
        "client_pub": client_pub,
        "protected_priv": protected_priv,
        "protected_pub": protected_pub,
        "clients_dir": clients_dir,
        "tmp_path": tmp_path,
    }


@pytest.fixture
def server(keys):
    """A fresh RMAPServer with both client identities loaded."""
    srv = RMAPServer(
        server_public_key_path=keys["server_pub"],
        server_private_key_path=keys["server_priv"],
    )
    srv.loadIdentities(keys["clients_dir"])
    return srv


@pytest.fixture
def client(keys):
    """An RMAPClient for the unprotected identity 'Group_01'."""
    return RMAPClient(
        identity="Group_01",
        client_private_key_path=keys["client_priv"],
        server_public_key_path=keys["server_pub"],
    )


@pytest.fixture
def protected_client(keys):
    """An RMAPClient for the passphrase-protected identity 'Group_02'."""
    return RMAPClient(
        identity="Group_02",
        client_private_key_path=keys["protected_priv"],
        server_public_key_path=keys["server_pub"],
        passphrase=CLIENT_PASSPHRASE,
    )
