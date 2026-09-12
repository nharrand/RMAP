from rmap import exceptions as exc


def test_all_exceptions_inherit_from_rmap_error():
    subclasses = [
        exc.MalformedMessageException,
        exc.UnknownIdentityException,
        exc.DecryptionException,
        exc.UnsupportedKeyException,
        exc.PassphraseRequiredException,
        exc.ProtocolStateException,
    ]
    for cls in subclasses:
        assert issubclass(cls, exc.RMAPError)
        assert issubclass(cls, Exception)


def test_exceptions_carry_message():
    e = exc.MalformedMessageException("bad stuff")
    assert str(e) == "bad stuff"
