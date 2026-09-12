# rmap

Reference implementation of the **Roger Michael Authentication Protocol
(RMAP)**, a PGP-based challenge/response authentication protocol, built
for a Software Security course. It provides a Flask-friendly
`RMAPServer` class your project can use to authenticate clients from a
list of known public keys and hand back a secret link.

> This is **v1.0.2**. It is a reference implementation for coursework
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
   link: `{"result": "<32 hex chars>"}`, encrypted with the **client's**
   public key.

The **link** is `hex(nonceClient) || hex(nonceServer)`, each nonce
zero-padded to 16 hex characters (64 bits), for 32 hex characters
total.

> **Note:** RMAP itself does not implement, require, or assume any
> particular HTTP route for retrieving whatever the link unlocks.
> RMAP only computes the 32-hex-char string (`expectedLink`, see
> below) and, optionally, lets you prepend your own prefix to what's
> sent to the client (`linkPrefix`). What endpoint your project
> exposes, what it's called, and what `expectedLink` even represents in
> your app (a document ID, a session token, ...) is entirely up to your
> own Flask implementation.

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
they are only ever turned into a hex string for the final `result` field
in resp2.

## Installing this library in your project

This package is **not published on PyPI** - it's distributed via this
GitHub repository, either as a direct git dependency or by installing
a released wheel from the repo's GitHub Releases page.

### Option A: pip install directly from GitHub (a tagged version)

```bash
pip install "rmap @ git+https://github.com/nharrand/RMAP.git@v1.0.2"
```

Or without pinning to a tag (tracks the default branch - not
recommended once you've started your project, since the library may
change):

```bash
pip install git+https://github.com/nharrand/RMAP.git
```

In a `requirements.txt`:

```
rmap @ git+https://github.com/nharrand/RMAP.git@v1.0.2
```

In a `pyproject.toml` (PEP 621 `dependencies`):

```toml
dependencies = [
    "rmap @ git+https://github.com/nharrand/RMAP.git@v1.0.2",
]
```

### Option B: install a released wheel from GitHub Releases

Each tagged release publishes `rmap-<version>-py3-none-any.whl` (and an
sdist) as release assets. You can install the wheel directly by URL:

```bash
pip install https://github.com/nharrand/RMAP/releases/download/v1.0.2/rmap-1.0.2-py3-none-any.whl
```

or download it first and install locally:

```bash
pip install ./rmap-1.0.2-py3-none-any.whl
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
one file per identity, **named after the identity**. The identity is
the file's **stem** (file name without its extension) - e.g. a file
named `Group_01.asc` registers the identity `Group_01`. Any extension
works the same way (or none at all); only the final extension is
stripped, so avoid dots elsewhere in an identity name if you want the
full name preserved.

```bash
mkdir -p keys/clients
cp keys/group01_pub.asc keys/clients/Group_01.asc
```

## Server-side usage (Flask)

> The route names below (`/msg1`, `/msg2`, and especially the final
> "retrieve the resource" endpoint) are just an example project's
> choices, **not** something RMAP requires. RMAP only gives you
> `receiveMsg1`/`receiveMsg2` (the handshake logic) and `expectedLink`
> (an opaque string key); it has no opinion on your URL scheme,
> endpoint names, or what `expectedLink` represents in your app.

```python
from flask import Flask, request, jsonify
from rmap import RMAPServer, RMAPError

app = Flask(__name__)

server = RMAPServer(
    server_public_key_path="keys/server_pub.asc",
    server_private_key_path="keys/server_priv.asc",
    passphrase=None,          # or a string if the key is protected
    linkPrefix="http://localhost:5000/get-document/",
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
    # expectedLink is always the bare 32-hex-char link, even though the
    # "result" field *inside* resp2 is prefixed with linkPrefix. Use
    # expectedLink as your internal session/lookup key - here, to
    # remember which identity completed which handshake.
    identity, expectedLink, resp2 = server.receiveMsg2(request.get_json())
    sessions[expectedLink] = identity   # e.g. store however you track sessions
    return jsonify(resp2)


# This route - its name, its URL shape, what "id" means - is entirely
# up to your project. This example happens to reuse expectedLink as
# the id, but that's a choice, not a requirement.
@app.get("/get-document/<id>")
def get_document(id):
    identity = sessions.get(id)
    if identity is None:
        return jsonify({"error": "unknown or incomplete session"}), 404
    ...
```

### `linkPrefix`

`RMAPServer(..., linkPrefix="http://localhost:5000/get-document/")`
prepends that string to the `"result"` field the client receives inside
resp2, so the client gets back a ready-to-use, clickable URL instead of
a bare hex string. It defaults to `""` (no prefix). The prefix itself
is entirely your choice - RMAP does not require any particular scheme,
host, or path.

**This only affects what's sent to the client.** The `expectedLink`
value returned by `receiveMsg2()`, and the value returned by
`getExpectedLink()`, are always the bare 32-hex-char link, unaffected by
`linkPrefix` - so you can keep using it directly as an internal
session/lookup key no matter what prefix you configured, or whether you
use a prefix at all.

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

## Demonstration script

To see a full happy-path handshake end-to-end, with every message
printed both as it appears on the wire (encrypted) and decrypted, run:

```bash
python examples/demo_handshake.py
```

It generates throwaway keypairs, runs `RMAPServer`/`RMAPClient` directly
(no Flask, no network), and prints msg1, resp1, msg2, and resp2 at each
step in both forms, ending with the resulting secret link.

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

`--fetch-link` is an optional convenience: after the handshake, it
performs one extra GET to check the resulting link end-to-end. If your
server used `linkPrefix`, the CLI follows whatever absolute URL you
configured; otherwise it guesses `<url>/get-link/<link>` by default -
override that guess with `--get-link-path /get-document` (or whatever
matches your app), or just skip `--fetch-link` and test your own
endpoint separately. Either way, this is tooling built on top of RMAP,
not something RMAP itself requires or assumes.

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
git clone https://github.com/nharrand/RMAP.git
cd RMAP
pip install -e ".[dev]"
pytest -v
```

CI (`.github/workflows/tests.yml`) runs the test suite on every push
and pull request against Python 3.9-3.12. Tagged pushes (`vX.Y.Z`)
trigger `.github/workflows/release.yml`, which builds the sdist/wheel,
runs the tests, and attaches the built artifacts to the corresponding
GitHub Release.
