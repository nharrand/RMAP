import pytest

from rmap.crypto import encrypt_json


def test_client_build_msg1_generates_nonce(client):
    assert client.nonceClient is None
    msg1 = client.build_msg1()
    assert client.nonceClient is not None
    assert set(msg1.keys()) == {"payload"}


def test_client_detects_tampered_nonce_client_in_resp1(server, client):
    msg1 = client.build_msg1()
    identity, resp1 = server.receiveMsg1(msg1)

    # Tamper: re-encrypt a resp1 with a different nonceClient than the
    # one the client actually sent.
    tampered = encrypt_json(
        {"nonceClient": client.nonceClient + 1, "nonceServer": 42},
        client.clientPrivateKey.pubkey,
    )
    with pytest.raises(ValueError):
        client.process_resp1(tampered)


def test_client_build_msg2_before_resp1_raises(client):
    with pytest.raises(ValueError):
        client.build_msg2()


def test_client_expected_link_none_before_handshake(client):
    assert client.expected_link is None


def test_client_expected_link_after_handshake(server, client):
    msg1 = client.build_msg1()
    identity, resp1 = server.receiveMsg1(msg1)
    client.process_resp1(resp1)
    assert client.expected_link == f"{client.nonceClient:016x}{client.nonceServer:016x}"
