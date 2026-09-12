import json

import pgpy
import pytest

from rmap.crypto import load_key, encrypt_json, decrypt_json
from rmap.exceptions import (
    MalformedMessageException,
    DecryptionException,
    UnsupportedKeyException,
    PassphraseRequiredException,
)


def test_load_key_valid(keys):
    key = load_key(keys["server_pub"])
    assert isinstance(key, pgpy.PGPKey)


def test_load_key_invalid_file(tmp_path):
    bogus = tmp_path / "not_a_key.asc"
    bogus.write_text("this is definitely not a PGP key")
    with pytest.raises(UnsupportedKeyException):
        load_key(bogus)


def test_encrypt_decrypt_round_trip(keys):
    pub = load_key(keys["server_pub"])
    priv = load_key(keys["server_priv"])

    wire_msg = encrypt_json({"identity": "Group_01", "nonceClient": 42}, pub)
    assert set(wire_msg.keys()) == {"payload"}
    assert isinstance(wire_msg["payload"], str)

    data = decrypt_json(wire_msg, priv)
    assert data == {"identity": "Group_01", "nonceClient": 42}


def test_decrypt_with_wrong_key_fails(keys):
    # Encrypt for the server, but try to decrypt with the client's key.
    pub = load_key(keys["server_pub"])
    wrong_priv = load_key(keys["client_priv"])

    wire_msg = encrypt_json({"a": 1}, pub)
    with pytest.raises(DecryptionException):
        decrypt_json(wire_msg, wrong_priv)


def test_decrypt_missing_payload_field():
    priv = None  # never reached
    with pytest.raises(MalformedMessageException):
        decrypt_json({}, priv)


def test_decrypt_payload_not_a_string(keys):
    priv = load_key(keys["server_priv"])
    with pytest.raises(MalformedMessageException):
        decrypt_json({"payload": 12345}, priv)


def test_decrypt_invalid_base64(keys):
    priv = load_key(keys["server_priv"])
    with pytest.raises(MalformedMessageException):
        decrypt_json({"payload": "!!!not-base64!!!"}, priv)


def test_decrypt_plaintext_not_json(keys):
    pub = load_key(keys["server_pub"])
    priv = load_key(keys["server_priv"])

    msg = pgpy.PGPMessage.new("this is not json")
    encrypted = pub.encrypt(msg)
    from rmap.armor import strip_armor
    wire_msg = {"payload": strip_armor(str(encrypted))}

    with pytest.raises(MalformedMessageException):
        decrypt_json(wire_msg, priv)


def test_decrypt_json_array_instead_of_object(keys):
    pub = load_key(keys["server_pub"])
    priv = load_key(keys["server_priv"])

    msg = pgpy.PGPMessage.new(json.dumps([1, 2, 3]))
    encrypted = pub.encrypt(msg)
    from rmap.armor import strip_armor
    wire_msg = {"payload": strip_armor(str(encrypted))}

    with pytest.raises(MalformedMessageException):
        decrypt_json(wire_msg, priv)


def test_decrypt_protected_key_without_passphrase(keys):
    priv = load_key(keys["protected_priv"])
    pub = load_key(keys["protected_pub"])
    wire_msg = encrypt_json({"a": 1}, pub)

    with pytest.raises(PassphraseRequiredException):
        decrypt_json(wire_msg, priv)  # no passphrase given


def test_decrypt_protected_key_with_wrong_passphrase(keys):
    priv = load_key(keys["protected_priv"])
    pub = load_key(keys["protected_pub"])
    wire_msg = encrypt_json({"a": 1}, pub)

    with pytest.raises(PassphraseRequiredException):
        decrypt_json(wire_msg, priv, passphrase="definitely wrong")


def test_decrypt_protected_key_with_correct_passphrase(keys):
    priv = load_key(keys["protected_priv"])
    pub = load_key(keys["protected_pub"])
    wire_msg = encrypt_json({"a": 1}, pub)

    data = decrypt_json(wire_msg, priv, passphrase="correct horse battery staple")
    assert data == {"a": 1}
