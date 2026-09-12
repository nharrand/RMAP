#!/usr/bin/env python3
"""
Standalone demonstration of a full RMAP handshake.

Generates throwaway PGP keypairs for a server and one client ("Group_01"),
then drives the full 4-message protocol (msg1 -> resp1 -> msg2 -> resp2)
directly through RMAPServer and RMAPClient - no Flask app, no network
involved. At every step it prints the message both as it appears "on the
wire" (encrypted, {"payload": "<base64>"}) and its decrypted plaintext
JSON content, so you can see exactly what each side sends and receives.

Run with:
    python examples/demo_handshake.py
(after installing the package: pip install -e ".[dev]" from the repo root)
"""

import json
import tempfile
from pathlib import Path

from rmap import RMAPServer, RMAPClient
from rmap.keygen import generate_keypair
from rmap.crypto import decrypt_json


def banner(text: str) -> None:
    print()
    print("=" * 72)
    print(text)
    print("=" * 72)


def print_wire(label: str, wire_msg: dict) -> None:
    print(f"--- {label}  [ENCRYPTED - on the wire] ---")
    print(json.dumps(wire_msg, indent=2))


def print_plain(label: str, data: dict) -> None:
    print(f"--- {label}  [DECRYPTED - plaintext content] ---")
    print(json.dumps(data, indent=2))
    print()


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)

        # ------------------------------------------------------------
        banner("STEP 0 - Generate throwaway PGP keypairs for demo purposes")
        # ------------------------------------------------------------
        server_key = generate_keypair("Demo Server", "server@example.com")
        client_key = generate_keypair("Group_01", "group01@example.com")

        server_priv_path = tmp / "server_priv.asc"
        server_pub_path = tmp / "server_pub.asc"
        server_priv_path.write_text(str(server_key))
        server_pub_path.write_text(str(server_key.pubkey))

        client_priv_path = tmp / "client_priv.asc"
        clients_dir = tmp / "clients"
        clients_dir.mkdir()
        client_priv_path.write_text(str(client_key))
        (clients_dir / "Group_01").write_text(str(client_key.pubkey))

        print(f"Generated server keypair:  {server_pub_path.name}, {server_priv_path.name}")
        print(f"Generated client keypair:  {client_priv_path.name} (identity 'Group_01')")

        # ------------------------------------------------------------
        banner("STEP 1 - Set up RMAPServer and RMAPClient")
        # ------------------------------------------------------------
        # linkPrefix is entirely a project choice - RMAP has no opinion
        # on endpoint names or URL shape. This demo uses "/get-document/"
        # to illustrate that it doesn't have to be "/get-link/" at all.
        server = RMAPServer(
            server_pub_path,
            server_priv_path,
            linkPrefix="http://localhost:5000/get-document/",
            verbose=False,
        )
        server.loadIdentities(clients_dir)
        print(f"Server loaded identities: {list(server.identities.keys())}")

        client = RMAPClient(
            identity="Group_01",
            client_private_key_path=client_priv_path,
            server_public_key_path=server_pub_path,
        )
        print("Client initialized for identity 'Group_01'")

        # ------------------------------------------------------------
        banner("STEP 2 - Client builds msg1: {identity, nonceClient}, encrypted for the server")
        # ------------------------------------------------------------
        msg1 = client.build_msg1()
        print_wire("msg1", msg1)
        # Decrypt it ourselves purely for display purposes, using the
        # server's private key - this is exactly what server.receiveMsg1()
        # does internally.
        msg1_plain = decrypt_json(msg1, server.serverPrivateKey)
        print_plain("msg1", msg1_plain)

        # ------------------------------------------------------------
        banner("STEP 3 - Server processes msg1 and builds resp1: {nonceClient, nonceServer}")
        # ------------------------------------------------------------
        identity, resp1 = server.receiveMsg1(msg1)
        print(f"Server identified the client as: '{identity}'")
        print()
        print_wire("resp1", resp1)
        resp1_plain = decrypt_json(resp1, client.clientPrivateKey)
        print_plain("resp1", resp1_plain)

        # ------------------------------------------------------------
        banner("STEP 4 - Client processes resp1 and builds msg2: {nonceServer}")
        # ------------------------------------------------------------
        nonce_client, nonce_server = client.process_resp1(resp1)
        print(f"Client verified the echoed nonceClient matches what it sent ({nonce_client})")
        print(f"Client learned nonceServer = {nonce_server}")
        print()
        msg2 = client.build_msg2()
        print_wire("msg2", msg2)
        msg2_plain = decrypt_json(msg2, server.serverPrivateKey)
        print_plain("msg2", msg2_plain)

        # ------------------------------------------------------------
        banner("STEP 5 - Server processes msg2 and builds resp2: {result}")
        # ------------------------------------------------------------
        identity, expected_link, resp2 = server.receiveMsg2(msg2)
        print(f"Server's internal expectedLink for '{identity}' (bare, unaffected by linkPrefix):")
        print(f"    {expected_link}")
        print()
        print_wire("resp2", resp2)
        resp2_plain = decrypt_json(resp2, client.clientPrivateKey)
        print_plain("resp2", resp2_plain)
        print(f"Note: the \"result\" field above has linkPrefix ({server.linkPrefix!r}) applied - "
              f"only what the client receives is prefixed.\n")

        # ------------------------------------------------------------
        banner("STEP 6 - Client processes resp2 and extracts the secret link")
        # ------------------------------------------------------------
        link = client.process_resp2(resp2)
        print(f"Link received by client (with linkPrefix): {link}")
        print(f"Bare link independently expected\n"
              f"  by the client:                           {client.expected_link}")
        print(f"Bare link independently expected\n"
              f"  by the server (expectedLink):             {expected_link}")

        assert link == f"{server.linkPrefix}{expected_link}"
        assert expected_link == client.expected_link

        banner("HANDSHAKE COMPLETE - all link values are consistent")
        print(f"\nSecret link (ready to use): {link}\n")


if __name__ == "__main__":
    main()
