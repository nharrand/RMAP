"""
Command-line RMAP test client.

Drives a full RMAP handshake (msg1 -> resp1 -> msg2 -> resp2) against a
running Flask server, prints the resulting link, and optionally fetches
it via HTTP GET to check the server's "get-link" endpoint end-to-end.

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
    if link == client.expected_link:
        print("OK: link matches expected value.")
    else:
        print("MISMATCH: server returned a different link than expected!")

    if args.fetch_link:
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
        help="Path prefix of the get-link endpoint (default: /get-link, so the full URL is <url>/get-link/<link>)",
    )
    parser.add_argument("--fetch-link", action="store_true", help="After the handshake, GET the resulting link")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose protocol logging")
    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
