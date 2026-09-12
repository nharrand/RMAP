import pytest

from rmap.server import RMAPServer
from rmap.exceptions import (
    UnknownIdentityException,
    ProtocolStateException,
    PassphraseRequiredException,
)


def test_load_identity_single(keys):
    srv = RMAPServer(keys["server_pub"], keys["server_priv"])
    srv.loadIdentity("Group_01", keys["client_pub"])
    assert "Group_01" in srv.identities


def test_load_identities_directory(keys):
    srv = RMAPServer(keys["server_pub"], keys["server_priv"])
    srv.loadIdentities(keys["clients_dir"])
    assert set(srv.identities.keys()) == {"Group_01", "Group_02"}


def test_full_handshake_happy_path(server, client):
    msg1 = client.build_msg1()
    identity, resp1 = server.receiveMsg1(msg1)
    assert identity == "Group_01"

    nonce_client, nonce_server = client.process_resp1(resp1)
    assert nonce_client == client.nonceClient
    assert nonce_server == server.identities["Group_01"].nonceServer

    msg2 = client.build_msg2()
    identity, expected_link, resp2 = server.receiveMsg2(msg2)
    assert identity == "Group_01"
    assert expected_link == server.getExpectedLink("Group_01")

    link = client.process_resp2(resp2)
    assert link == expected_link
    assert link == client.expected_link
    assert len(link) == 32
    int(link, 16)  # must be valid hex


def test_handshake_with_passphrase_protected_client(server, protected_client):
    msg1 = protected_client.build_msg1()
    identity, resp1 = server.receiveMsg1(msg1)
    assert identity == "Group_02"

    protected_client.process_resp1(resp1)
    msg2 = protected_client.build_msg2()
    identity, expected_link, resp2 = server.receiveMsg2(msg2)

    link = protected_client.process_resp2(resp2)
    assert link == expected_link


def test_receive_msg1_unknown_identity(server, keys):
    from rmap.client import RMAPClient

    stranger = RMAPClient(
        identity="Not_Registered",
        client_private_key_path=keys["client_priv"],
        server_public_key_path=keys["server_pub"],
    )
    msg1 = stranger.build_msg1()
    with pytest.raises(UnknownIdentityException):
        server.receiveMsg1(msg1)


def test_receive_msg2_without_prior_msg1(server, client):
    # Craft a well-formed msg2 (encrypted with the server's own key, as
    # the protocol requires) carrying a nonceServer the server never issued.
    from rmap.crypto import encrypt_json

    fake_msg2 = encrypt_json({"nonceServer": 999999}, server.serverPublicKey)

    with pytest.raises(ProtocolStateException):
        server.receiveMsg2(fake_msg2)


def test_get_expected_link_before_handshake(server):
    with pytest.raises(ProtocolStateException):
        server.getExpectedLink("Group_01")


def test_get_expected_link_unknown_identity(server):
    with pytest.raises(UnknownIdentityException):
        server.getExpectedLink("Nope")


def test_encrypt_for_identity_unknown_identity(server):
    with pytest.raises(UnknownIdentityException):
        server.encrypt_for_identity({"a": 1}, "Nope")


def test_server_requires_passphrase_for_protected_server_key(tmp_path, keys):
    from rmap.keygen import generate_keypair
    from rmap.crypto import encrypt_json, load_key

    server_key = generate_keypair("Protected Server", "server@example.com", passphrase="s3cr3t")
    server_priv_path = tmp_path / "protected_server_priv.asc"
    server_pub_path = tmp_path / "protected_server_pub.asc"
    server_priv_path.write_text(str(server_key))
    server_pub_path.write_text(str(server_key.pubkey))

    # No passphrase supplied.
    srv_no_pass = RMAPServer(server_pub_path, server_priv_path, passphrase=None)
    srv_no_pass.loadIdentity("Group_01", keys["client_pub"])

    msg1 = encrypt_json(
        {"identity": "Group_01", "nonceClient": 123},
        load_key(server_pub_path),
    )
    with pytest.raises(PassphraseRequiredException):
        srv_no_pass.receiveMsg1(msg1)

    # Correct passphrase supplied -> should work fine.
    srv_with_pass = RMAPServer(server_pub_path, server_priv_path, passphrase="s3cr3t")
    srv_with_pass.loadIdentity("Group_01", keys["client_pub"])
    identity, resp1 = srv_with_pass.receiveMsg1(msg1)
    assert identity == "Group_01"
