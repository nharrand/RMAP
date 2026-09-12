# rmap

Reference implementation of the **Roger Michael Authentication Protocol
(RMAP)**, a PGP-based challenge/response authentication protocol, built
for a Software Security course. It provides a Flask-friendly
`RMAPServer` class your project can use to authenticate clients from a
list of known public keys and hand back a secret link.

> This is **v1.0.0**. It is a reference implementation for coursework
> and, like any piece of software, is not guaranteed to be bug-free -
> testing your integration against it is part of the exercise. A v2
> release will follow later in the course.

## How the protocol works

RMAP is a 4-message handshake between a **client** (identified by a
name, e.g. `Group_01`) and a **server**, each holding their own PGP
keypair and knowing the other's public key ahead of time.

```
Client                                              Server
  |--------------------- msg1 ------------------------>|
  |   Enc_ServerPublicKey({identity, nonceClient})      |
  |                                                      |
  |<-------------------- resp1 -------------------------|
  |   Enc_ClientPublicKey({nonceClient, nonceServer})    |
  |                                                      |
  |--------------------- msg2 ------------------------->|
  |   Enc_ServerPublicKey({nonceServer})                 |
  |                                                      |
  |<-------------------- resp2 --------------------------|
  |   Enc_ClientPublicKey({link})                        |
```

1. **msg1** (client -> server): the client picks a random `nonceClient`
   and sends `{"identity": "<string>", "nonceClient": <uint64>}`,
   encrypted with the **server's** public key.
2. **resp1** (server -> client): the server looks up `identity` among
   its known clients, generates its own random `nonceServer`, and
   replies with `{"nonceClient": <uint64>, "nonceServer": <uint64>}`,
   encrypted with **that client's** public key. Echoing `nonceClient`
   back lets the client confirm it's talking to a server that could
   actually decrypt msg1 (i.e. holds the corresponding private key).
3. **msg2** (client -> server): having decrypted resp1 with its own
   private key, the client proves it received `nonceServer` correctly
   by sending it back: `{"nonceServer": <uint64>}`, encrypted with the
   **server's** public key.
4. **resp2** (server -> client): the server replies with the secret
   link: `{"link": "<32 hex chars>"}`, encrypted with the **client's**
   public key.

The **link** is `hex(nonceClient) || hex(nonceServer)`, each nonce
zero-padded to 16 hex characters (64 bits), for 32 hex characters
total, meant to be understood as a path:
`http://host:port/get-link/<32HEX>`.

### Wire format

Every encrypted message on the wire is a single JSON object:

```json
{"payload": "<base64>"}
```

`<base64>` is the ASCII-armored PGP message (as PGP itself would print
it) with the `-----BEGIN/END PGP MESSAGE-----` lines, any armor
headers, the blank separator line, and the CRC24 checksum line
stripped away - i.e. just the raw base64 body of the armor block.

The content that gets encrypted (before armoring) is itself a JSON
string, e.g. for msg1: `{"identity": "Group_01", "nonceClient": 5465464}`.
Nonces are transmitted as plain **JSON integers** in msg1/resp1/msg2 -
they are only ever turned into a hex string for the final `link` field
in resp2.

## Installing this library in your project

This package is **not published on PyPI** - it's distributed via this
GitHub repository, either as a direct git dependency or by installing
a released wheel from the repo's GitHub Releases page.

### Option A: pip install directly from GitHub (a tagged version)

```bash
pip install "rmap @ git+https://github.com/YOUR-ORG/rmap-library.git@v1.0.0"
```

Or without pinning to a tag (tracks the default branch - not
recommended once you've started your project, since the library may
change):

```bash
pip install git+https://github.com/YOUR-ORG/rmap-library.git
```

In a `requirements.txt`:

```
rmap @ git+https://github.com/YOUR-ORG/rmap-library.git@v1.0.0
```

In a `pyproject.toml` (PEP 621 `dependencies`):

```toml
dependencies = [
    "rmap @ git+https://github.com/YOUR-ORG/rmap-library.git@v1.0.0",
]
```

### Option B: install a released wheel from GitHub Releases

Each tagged release publishes `rmap-<version>-py3-none-any.whl` (and an
sdist) as release assets. You can install the wheel directly by URL:

```bash
pip install https://github.com/YOUR-ORG/rmap-library/releases/download/v1.0.0/rmap-1.0.0-py3-none-any.whl
```

or download it first and install locally:

```bash
pip install ./rmap-1.0.0-py3-none-any.whl
```

Either way, once installed you `import rmap` like any other package.

## Keys

All keys are expected to be **ASCII-armored** PGP key files (`.asc`).
Private keys may optionally be passphrase-protected.

You can generate test keypairs with the bundled helper (installed as a
console script, or runnable as a module):

```bash
rmap-keygen --name "Server" --email server@example.com \
    --out-private keys/server_priv.asc --out-public keys/server_pub.asc

rmap-keygen --name "Group_01" --email group01@example.com \
    --out-private keys/group01_priv.asc --out-public keys/group01_pub.asc
```

Client public keys that the server should accept go in a directory,
one file per identity, **named after the identity** (e.g. a file named
`Group_01` registers the identity `Group_01` - the identity is exactly
the file name).

## Server-side usage (Flask)

```python
from flask import Flask, request, jsonify
from rmap import RMAPServer, RMAPError

app = Flask(__name__)

server = RMAPServer(
    server_public_key_path="keys/server_pub.asc",
    server_private_key_path="keys/server_priv.asc",
    passphrase=None,          # or a string if the key is protected
    verbose=True,
)
server.loadIdentities("keys/clients/")


@app.errorhandler(RMAPError)
def handle_rmap_error(e):
    return jsonify({"error": str(e)}), 400


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
    # look up `link` against the sessions you've completed and serve
    # whatever the "secret link" is supposed to unlock
    ...
```

## Exceptions

All library exceptions inherit from `rmap.RMAPError`:

| Exception | Raised when |
|---|---|
| `MalformedMessageException` | bad/missing `payload`, bad base64/PGP armor, decrypted body isn't valid JSON |
| `UnknownIdentityException` | identity not registered via `loadIdentity`/`loadIdentities` |
| `DecryptionException` | PGP decryption fails (wrong key, corrupted ciphertext, ...) |
| `UnsupportedKeyException` | a key file isn't a valid PGP key |
| `PassphraseRequiredException` | private key is locked and no/wrong passphrase was given |
| `ProtocolStateException` | message received out of sequence (e.g. `msg2` with no matching `msg1` session) |

Catch `RMAPError` for a catch-all, or the specific subclasses if you
want to map different failures to different HTTP status codes. Note
that a Flask `@app.errorhandler(RMAPError)` only catches the
exceptions this library documents and raises deliberately - it's still
good practice to also test your endpoints against unexpected/malformed
input and make sure your app doesn't leak a raw 500 in cases this
library doesn't already turn into a clean `RMAPError`.

## CLI test client

Once your Flask server is running, you can drive a full handshake
against it from the command line:

```bash
rmap-client \
    --url http://localhost:5000 \
    --identity Group_01 \
    --client-private-key keys/group01_priv.asc \
    --server-public-key keys/server_pub.asc \
    --fetch-link \
    --verbose
```

Run `rmap-client --help` for all options (custom endpoint paths,
passphrase handling, timeout, etc.).

## Logging

The library is silent by default. Pass `verbose=True` to `RMAPServer`/
`RMAPClient` to get basic console logging, or pass your own
`logger=your_logger` (e.g. `logger=app.logger` in Flask) to route
rmap's log messages into your own logging setup.

## Development

Clone the repo and install with the `dev` extra to get `pytest`:

```bash
git clone https://github.com/YOUR-ORG/rmap-library.git
cd rmap-library
pip install -e ".[dev]"
pytest -v
```

CI (`.github/workflows/tests.yml`) runs the test suite on every push
and pull request against Python 3.9-3.12. Tagged pushes (`vX.Y.Z`)
trigger `.github/workflows/release.yml`, which builds the sdist/wheel,
runs the tests, and attaches the built artifacts to the corresponding
GitHub Release.
