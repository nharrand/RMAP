import pgpy
import pytest

from rmap.armor import strip_armor, wrap_armor
from rmap.exceptions import MalformedMessageException


def test_strip_wrap_round_trip(keys):
    import pgpy as _pgpy

    pub_key, _ = _pgpy.PGPKey.from_file(str(keys["server_pub"]))
    msg = pgpy.PGPMessage.new('{"hello": "world"}')
    encrypted = pub_key.encrypt(msg)
    armored = str(encrypted)

    payload = strip_armor(armored)
    assert "-----BEGIN" not in payload
    assert "-----END" not in payload
    assert "\n" not in payload

    reconstructed = wrap_armor(payload)
    assert reconstructed.startswith("-----BEGIN PGP MESSAGE-----")
    assert reconstructed.strip().endswith("-----END PGP MESSAGE-----")

    # And it should still be decryptable after the round trip.
    priv_key, _ = _pgpy.PGPKey.from_file(str(keys["server_priv"]))
    parsed = pgpy.PGPMessage.from_blob(reconstructed)
    decrypted = priv_key.decrypt(parsed)
    assert decrypted.message == '{"hello": "world"}'


def test_wrap_armor_rejects_invalid_base64():
    with pytest.raises(MalformedMessageException):
        wrap_armor("not-valid-base64!!!")
