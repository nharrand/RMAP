"""
Tests for rmap.cli_client, using a fake `requests` layer that routes
directly into an in-process RMAPServer instead of doing real HTTP. This
verifies the CLI orchestrates the handshake correctly without needing a
running Flask server or network access.
"""

import pytest

from rmap import cli_client


class _FakeResponse:
    def __init__(self, json_data, status_code=200):
        self._json_data = json_data
        self.status_code = status_code
        self.text = str(json_data)

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise cli_client.requests.HTTPError(f"HTTP {self.status_code}")


@pytest.fixture
def fake_requests(monkeypatch, server):
    """Patch rmap.cli_client.requests.post/get to talk directly to `server`."""
    completed_links = {}

    def fake_post(url, json=None, timeout=None):
        if url.endswith("/msg1"):
            identity, resp1 = server.receiveMsg1(json)
            return _FakeResponse(resp1)
        elif url.endswith("/msg2"):
            identity, expected_link, resp2 = server.receiveMsg2(json)
            completed_links[expected_link] = identity
            return _FakeResponse(resp2)
        raise AssertionError(f"Unexpected POST to {url}")

    def fake_get(url, timeout=None):
        link = url.rsplit("/", 1)[-1]
        if link in completed_links:
            return _FakeResponse({"status": "ok", "identity": completed_links[link]})
        return _FakeResponse({"status": "unknown link"}, status_code=404)

    monkeypatch.setattr(cli_client.requests, "post", fake_post)
    monkeypatch.setattr(cli_client.requests, "get", fake_get)
    return completed_links


def test_cli_full_handshake(fake_requests, keys, capsys):
    args = cli_client.build_arg_parser().parse_args([
        "--url", "http://fake-server",
        "--identity", "Group_01",
        "--client-private-key", str(keys["client_priv"]),
        "--server-public-key", str(keys["server_pub"]),
        "--no-passphrase-prompt",
        "--fetch-link",
    ])
    rc = cli_client.run(args)
    assert rc == 0

    out = capsys.readouterr().out
    assert "OK: link matches expected value." in out
    assert "HTTP 200" in out


def test_cli_arg_parser_requires_core_args():
    parser = cli_client.build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])  # missing --url/--identity/etc.


def test_cli_arg_parser_defaults():
    parser = cli_client.build_arg_parser()
    args = parser.parse_args([
        "--url", "http://x",
        "--identity", "Group_01",
        "--client-private-key", "priv.asc",
        "--server-public-key", "pub.asc",
    ])
    assert args.msg1_path == "/msg1"
    assert args.msg2_path == "/msg2"
    assert args.get_link_path == "/get-link"
    assert args.fetch_link is False
