"""
Command-line RMAP test client.

Drives a full RMAP handshake (msg1 -> resp1 -> msg2 -> resp2) against a
running Flask server and prints the resulting link. Optionally performs
one extra HTTP GET afterwards as a convenience for manual testing (see
--fetch-link / --get-link-path below) - but note that RMAP itself does
not implement, require, or assume any particular "retrieve the secret
resource" endpoint. That endpoint (its name, URL shape, and what it
returns) is entirely defined by your own Flask app - it might be
/get-link/<hex>, /get-document/<id>, something else entirely, or not
be a GET on a URL path segment at all. --get-link-path is just this
CLI's configurable guess for the common case; override it (or skip
--fetch-link and test your endpoint separately) if your app's shape
doesn't match.

Example:

    python -m rmap.cli_client \\
        --url http://localhost:5000 \\
        --identity Group_01 \\
        --client-private-key keys/group01_priv.asc \\
        --server-public-key keys/server_pub.asc \\
        --fetch-link

Run with --help for all options.
"""

import argparse
import getpass
import json
import sys

import requests

from .client import RMAPClient
from .exceptions import RMAPError


def _prompt_passphrase_if_needed(client_private_key_path: str) -> "str | None":
    """
    Best-effort check for whether the given key file looks
    passphrase-protected; if so (or if we can't tell), prompt for one.
    Students can also just pass --client-passphrase directly.
    """
    import pgpy

    try:
        key, _ = pgpy.PGPKey.from_file(client_private_key_path)
    except Exception:
        return None
    if getattr(key, "is_protected", False):
        return getpass.getpass(f"Passphrase for {client_private_key_path}: ")
    return None


def run(args: argparse.Namespace) -> int:
    passphrase = args.client_passphrase
    if passphrase is None and not args.no_passphrase_prompt:
        passphrase = _prompt_passphrase_if_needed(args.client_private_key)

    client = RMAPClient(
        identity=args.identity,
        client_private_key_path=args.client_private_key,
        server_public_key_path=args.server_public_key,
        passphrase=passphrase,
        verbose=args.verbose,
    )

    base_url = args.url.rstrip("/")
    msg1_url = base_url + args.msg1_path
    msg2_url = base_url + args.msg2_path

    try:
        print(f"--> Sending msg1 to {msg1_url}")
        msg1 = client.build_msg1()
        r = requests.post(msg1_url, json=msg1, timeout=args.timeout)
        r.raise_for_status()
        resp1 = r.json()

        nonce_client, nonce_server = client.process_resp1(resp1)
        print(f"<-- Got resp1. nonceClient={nonce_client} nonceServer={nonce_server}")

        print(f"--> Sending msg2 to {msg2_url}")
        msg2 = client.build_msg2()
        r = requests.post(msg2_url, json=msg2, timeout=args.timeout)
        r.raise_for_status()
        resp2 = r.json()

        link = client.process_resp2(resp2)
    except RMAPError as e:
        print(f"RMAP protocol error: {e}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"HTTP error talking to server: {e}", file=sys.stderr)
        return 1

    print()
    print(f"Link returned by server:   {link}")
    print(f"Link expected by client:   {client.expected_link}")
    # The server may have been configured with a `linkPrefix` (e.g. a full
    # "http://host:port/get-link/" URL), in which case `link` won't be
    # exactly equal to the bare hex `client.expected_link` - it will just
    # end with it. Both cases are "OK"; only a link that neither matches
    # nor ends with the expected value indicates an actual problem.
    if link == client.expected_link:
        print("OK: link matches expected value.")
    elif link.endswith(client.expected_link):
        print("OK: link matches expected value (server applied a linkPrefix).")
    else:
        print("MISMATCH: server returned a different link than expected!")

    if args.fetch_link:
        if link.startswith("http://") or link.startswith("https://"):
            # The server already gave us a ready-to-use absolute URL
            # (linkPrefix was set) - use it as-is, whatever shape it is.
            link_url = link
        else:
            # No linkPrefix was set, so we only have the bare hex link.
            # --get-link-path is just this CLI's configurable guess at
            # where to fetch it from (default: /get-link/<link>) - RMAP
            # itself doesn't require or assume this. Override
            # --get-link-path, or skip --fetch-link and test your
            # endpoint separately, if your app's shape is different
            # (e.g. /get-document/<id> with an id unrelated to `link`).
            link_url = f"{base_url}{args.get_link_path}/{link}"
        print(f"\n--> Fetching {link_url}")
        try:
            r = requests.get(link_url, timeout=args.timeout)
            print(f"<-- HTTP {r.status_code}")
            try:
                print(json.dumps(r.json(), indent=2))
            except ValueError:
                print(r.text)
        except requests.RequestException as e:
            print(f"HTTP error fetching link: {e}", file=sys.stderr)
            return 1

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RMAP CLI test client - drives a full handshake against a running server."
    )
    parser.add_argument("--url", required=True, help="Base URL of the server, e.g. http://localhost:5000")
    parser.add_argument("--identity", required=True, help="Client identity to authenticate as")
    parser.add_argument("--client-private-key", required=True, help="Path to this client's ASCII-armored private key")
    parser.add_argument("--server-public-key", required=True, help="Path to the server's ASCII-armored public key")
    parser.add_argument("--client-passphrase", default=None, help="Passphrase for the client private key, if protected")
    parser.add_argument(
        "--no-passphrase-prompt",
        action="store_true",
        help="Don't attempt to auto-detect/prompt for a passphrase (assume unprotected key)",
    )
    parser.add_argument("--msg1-path", default="/msg1", help="Path of the msg1 endpoint (default: /msg1)")
    parser.add_argument("--msg2-path", default="/msg2", help="Path of the msg2 endpoint (default: /msg2)")
    parser.add_argument(
        "--get-link-path",
        default="/get-link",
        help=(
            "Only used with --fetch-link when the server did NOT set a "
            "linkPrefix (so the CLI only has the bare hex link and needs "
            "a guess at where to fetch it). Default: /get-link, so the "
            "full URL is <url>/get-link/<link>. RMAP does not require or "
            "assume this path - override it to match your own endpoint "
            "(e.g. --get-link-path /get-document), or skip --fetch-link "
            "entirely and test your endpoint separately."
        ),
    )
    parser.add_argument(
        "--fetch-link",
        action="store_true",
        help=(
            "After the handshake, GET the resulting link as a convenience "
            "check. This is optional tooling, not a protocol requirement - "
            "skip it if your endpoint doesn't fit a simple GET on the link."
        ),
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose protocol logging")
    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
