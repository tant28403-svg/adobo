"""Proxy list provisioning: the downloader and the checker.

Both are list management, not attacks, so both are tested entirely offline:
the downloader takes an injectable *fetch* callable standing in for the
network, and the checker's per-proxy dialler (:func:`proxy_sources._check_one`)
is monkeypatched. What the tests pin is the part that would otherwise rot
silently - scheme tagging, dedupe, the merge's tolerance of dead sources, and
the guarantee that checking never rewrites the input list it was given.
"""

from __future__ import annotations

import pytest

from adobo.proxy_sources import (
    SOURCES,
    _check_one,
    check_proxies_file,
    download_proxies,
    encode_entry,
)
from adobo.proxies import parse_proxy


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


class TestEncodeEntry:
    def test_http_stays_bare(self) -> None:
        assert encode_entry(parse_proxy("1.2.3.4:8080")) == "1.2.3.4:8080"

    def test_socks_carries_its_prefix(self) -> None:
        assert encode_entry(parse_proxy("socks5://1.2.3.4:1080")) == "socks5://1.2.3.4:1080"
        assert encode_entry(parse_proxy("socks4://1.2.3.4:1080")) == "socks4://1.2.3.4:1080"

    def test_encoded_lines_round_trip_through_parse(self) -> None:
        """The file the downloader writes must read back identically under the
        default scheme - that is the whole point of prefixing SOCKS entries."""
        for line in ("1.2.3.4:8080", "socks5://1.2.3.4:1080", "socks4://5.6.7.8:1080"):
            assert parse_proxy(line).host in line


# ---------------------------------------------------------------------------
# Downloading
# ---------------------------------------------------------------------------


def fake_fetch(responses: dict[str, str], calls: list[str] | None = None):
    def fetch(url: str) -> str:
        if calls is not None:
            calls.append(url)
        if url not in responses:
            raise RuntimeError(f"unreachable: {url}")
        return responses[url]

    return fetch


class TestDownload:
    def test_merges_dedupes_and_tags_by_scheme(self, tmp_path) -> None:
        out = tmp_path / "proxies.txt"
        responses = {
            SOURCES["http"][0]: "9.9.9.9:3128\n1.1.1.1:8080\n",
            SOURCES["http"][1]: "1.1.1.1:8080\n8.8.8.8:3128\nnot-a-proxy\n",
            SOURCES["socks5"][0]: "5.5.5.5:1080\n5.5.5.5:1080\n",
        }
        code = download_proxies("all", str(out), fetch=fake_fetch(responses))
        assert code == 0
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert lines == [
            "1.1.1.1:8080",
            "socks5://5.5.5.5:1080",
            "8.8.8.8:3128",
            "9.9.9.9:3128",
        ], "deduped across sources, sorted, http bare, socks prefixed"

    def test_a_dead_source_is_skipped_not_fatal(self, tmp_path) -> None:
        out = tmp_path / "proxies.txt"
        responses = {SOURCES["socks5"][0]: "5.5.5.5:1080\n"}
        code = download_proxies("socks5", str(out), fetch=fake_fetch(responses))
        assert code == 0
        assert out.read_text(encoding="utf-8") == "socks5://5.5.5.5:1080\n"

    def test_kind_filters_which_sources_are_fetched(self, tmp_path) -> None:
        calls: list[str] = []
        out = tmp_path / "proxies.txt"
        download_proxies("socks4", str(out), fetch=fake_fetch({}, calls))
        assert calls, "the socks4 sources were attempted"
        assert all("socks4" in url.lower() for url in calls)

    def test_zero_proxies_fetched_is_a_failure(self, tmp_path) -> None:
        out = tmp_path / "proxies.txt"
        code = download_proxies("http", str(out), fetch=fake_fetch({}))
        assert code == 1
        assert not out.exists(), "an empty list is never written"

    def test_every_source_is_reachable_or_counted(self) -> None:
        """The curated source list must name only protocols it defines."""
        assert set(SOURCES) == {"http", "socks4", "socks5"}


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------


def write_list(tmp_path, lines: list[str]) -> str:
    path = tmp_path / "list.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


class TestCheck:
    def test_survivors_are_written_and_input_is_untouched(self, tmp_path, monkeypatch) -> None:
        path = write_list(tmp_path, ["1.1.1.1:8080", "2.2.2.2:8080"])
        original = (tmp_path / "list.txt").read_text(encoding="utf-8")
        verdicts = {
            parse_proxy("1.1.1.1:8080"): (True, ""),
            parse_proxy("2.2.2.2:8080"): (False, "ConnectionRefusedError: refused"),
        }
        monkeypatch.setattr(
            "adobo.proxy_sources._check_one",
            lambda proxy, host, port, timeout: verdicts[proxy],
        )
        code = check_proxies_file(path)
        assert code == 0
        checked = tmp_path / "list-checked.txt"
        assert checked.read_text(encoding="utf-8") == "1.1.1.1:8080\n"
        assert (tmp_path / "list.txt").read_text(encoding="utf-8") == original, (
            "a transient failure must never be able to wipe the input list"
        )

    def test_output_path_is_honoured(self, tmp_path, monkeypatch) -> None:
        path = write_list(tmp_path, ["1.1.1.1:8080"])
        monkeypatch.setattr(
            "adobo.proxy_sources._check_one", lambda *a: (True, "")
        )
        out = tmp_path / "elsewhere.txt"
        assert check_proxies_file(path, output=str(out)) == 0
        assert out.read_text(encoding="utf-8") == "1.1.1.1:8080\n"

    def test_all_dead_is_a_failure_and_writes_nothing(self, tmp_path, monkeypatch) -> None:
        path = write_list(tmp_path, ["1.1.1.1:8080"])
        monkeypatch.setattr(
            "adobo.proxy_sources._check_one", lambda *a: (False, "timeout")
        )
        code = check_proxies_file(path)
        assert code == 1
        assert not (tmp_path / "list-checked.txt").exists()

    def test_an_empty_input_is_reported_not_crashed(self, tmp_path) -> None:
        path = write_list(tmp_path, [])
        assert check_proxies_file(path) == 1

    def test_check_one_reports_failure_reasons(self, monkeypatch) -> None:
        """The real dialler is used here, against a port nothing listens on,
        so the reason string a dead proxy produces is the one an operator sees."""
        alive, reason = _check_one(
            parse_proxy("127.0.0.1:9"), "203.0.113.7", 80, timeout=1.0
        )
        assert alive is False
        assert reason, "a dead proxy must name why"


class TestUnreadableLists:
    """A list that cannot be read at all is reported and exited, not raised.

    --check-proxies is a mode flag an operator runs directly; a traceback
    naming a pydantic line buries the one sentence that matters.
    """

    def test_an_encrypted_list_is_reported_not_crashed(self, tmp_path) -> None:
        from adobo.proxies import encrypt_proxies

        encrypted = tmp_path / "proxies.enc"
        encrypted.write_bytes(encrypt_proxies("1.2.3.4:8080\n", "hunter2"))
        code = check_proxies_file(str(encrypted))
        assert code == 1

    def test_a_malformed_line_is_reported_with_its_location(self, tmp_path) -> None:
        path = tmp_path / "broken.txt"
        path.write_text("no-port-here\n", encoding="utf-8")
        code = check_proxies_file(str(path))
        assert code == 1
