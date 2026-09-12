from rmap.keygen import generate_keypair


def test_generate_keypair_unprotected():
    key = generate_keypair("Test", "test@example.com")
    assert key.is_protected is False
    armored_priv = str(key)
    armored_pub = str(key.pubkey)
    assert "PGP PRIVATE KEY BLOCK" in armored_priv
    assert "PGP PUBLIC KEY BLOCK" in armored_pub


def test_generate_keypair_protected():
    key = generate_keypair("Test", "test@example.com", passphrase="hunter2")
    assert key.is_protected is True
