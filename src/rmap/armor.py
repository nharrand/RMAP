"""
Helpers to convert between:
  - a full PGP ASCII-armored message (what pgpy produces/consumes), and
  - the "bare" base64 body used as the RMAP wire payload
    (i.e. an armored message with the "-----BEGIN/END-----" lines,
    header lines, and blank-line separator stripped away).

Per the RMAP spec, every encrypted message on the wire looks like:

    {"payload": "<base64>"}

where <base64> is "the ascii armored version of pgp message without
headers" - i.e. exactly the base64 body of the armor block.
"""

import base64

from pgpy.types import Armorable

from .exceptions import MalformedMessageException


def strip_armor(armored_text: str) -> str:
    """
    Given a full ASCII-armored PGP message (as produced by ``str(pgp_message)``),
    return just the base64 body, with the BEGIN/END lines, any armor headers
    (e.g. "Version:"), and the CRC24 checksum line removed.
    """
    lines = armored_text.strip().splitlines()
    lines = [line for line in lines if not line.startswith("-----")]

    # Drop any armor header lines (e.g. "Version: ..."), which appear
    # before the blank-line separator that precedes the base64 body.
    if "" in lines:
        blank_idx = lines.index("")
        lines = lines[blank_idx + 1:]

    # Drop the trailing CRC24 checksum line (starts with '=').
    if lines and lines[-1].startswith("="):
        lines = lines[:-1]

    return "".join(lines)


def wrap_armor(payload: str) -> str:
    """
    Given a bare base64 payload (as received on the wire), reconstruct a
    full ASCII-armored PGP message that pgpy can parse. This means
    re-wrapping the base64 to fixed-width lines and re-computing the
    CRC24 checksum line that pgpy's armor parser requires.
    """
    try:
        raw = base64.b64decode(payload, validate=True)
    except Exception as e:
        raise MalformedMessageException(f"'payload' is not valid base64: {e}") from e

    crc = Armorable.crc24(bytearray(raw))
    crc_b64 = base64.b64encode(crc.to_bytes(3, "big")).decode("ascii")

    wrapped_body = "\n".join(payload[i:i + 64] for i in range(0, len(payload), 64))

    return (
        "-----BEGIN PGP MESSAGE-----\n\n"
        f"{wrapped_body}\n"
        f"={crc_b64}\n"
        "-----END PGP MESSAGE-----\n"
    )
