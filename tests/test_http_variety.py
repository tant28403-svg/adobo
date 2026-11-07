"""Request-shape options for http_flood: method, path, cookies, referer, body.

The invariants these tests guard:

* **Byte-compat at the defaults.** Every new field at its default must produce
  the request that existed before the fields were introduced, byte for byte -
  the same requirement ``test_fingerprint`` enforces for personas. A default
  that merely produced an equivalent request would silently change every
  capture for every operator who never asked for the feature.
* **A POST body is framed, not decorated.** ``Content-Length`` must match the
  body exactly, the body must be the last bytes on the wire, and padding may
  never follow it - bytes after the body are read as the body's tail or as the
  start of a pipelined request, both of which corrupt the run's own counts.
* **A configured shape is the sent shape.** What the operator set on the
  profile is what appears in the request - nothing dropped, nothing reordered
  into ambiguity.

Validator tests sit here too, because the place a bad header value is refused
(model construction) is the place the operator meets the error.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from adobo.cli import build_parser, config_from_args
from adobo.models import AttackProfile, ProfileName, ProfileName as PN, Target
from adobo.transports import build_payload

TARGET = Target(host="lab.internal", port=80)

#: The exact header block a default run sends, from the request line through
#: the blank line. Pinned in full so any drift in order, spelling or spacing
#: fails loudly rather than quietly changing every capture.
DEFAULT_REQUEST_HEAD = (
    b"GET /api/data HTTP/1.1\r\n"
    b"Host: lab.internal\r\n"
    b"User-Agent: adobo-lab/0.1 (authorized testing)\r\n"
    b"Accept: */*\r\n"
    b"Connection: close\r\n"
    b"X-Ddosim-Seq: 7\r\n"
    b"\r\n"
)


def build(**kw) -> bytes:
    kw.setdefault("target", TARGET)
    kw.setdefault("seed", 7)
    return build_payload(PN.HTTP_FLOOD, kw.pop("size", 512), **kw)


# ---------------------------------------------------------------------------
# Byte compatibility at the defaults
# ---------------------------------------------------------------------------


class TestDefaultsAreUnchanged:
    @pytest.mark.parametrize("size", [128, 512, 1400])
    def test_default_request_starts_with_the_historical_bytes(self, size: int) -> None:
        """No option configured -> the request that always was, byte for byte.

        Everything after the header terminator is padding, which varies with
        size, so the assertion is on the head plus the terminator.
        """
        payload = build(size=size)
        assert payload.startswith(DEFAULT_REQUEST_HEAD)

    def test_default_request_is_a_get(self) -> None:
        assert build(size=64).startswith(b"GET /api/data HTTP/1.1\r\n")

    def test_no_stray_headers_when_options_are_unset(self) -> None:
        """Empty cookie/referer must omit the lines entirely, not send empty
        ones - ``Cookie: `` with no value is itself a fingerprint."""
        payload = build(size=512)
        assert b"Cookie" not in payload
        assert b"Referer" not in payload
        assert b"Content-Length" not in payload


# ---------------------------------------------------------------------------
# POST
# ---------------------------------------------------------------------------


class TestPost:
    def test_post_carries_a_framed_body(self) -> None:
        body = "a=1&b=2"
        payload = build(size=64, method="post", body=body)
        head, _, rest = payload.partition(b"\r\n\r\n")
        assert head.startswith(b"POST /api/data HTTP/1.1\r\n")
        assert b"Content-Type: application/x-www-form-urlencoded\r\n" in head
        assert f"Content-Length: {len(body)}\r\n".encode() in head
        assert rest == body.encode("utf-8"), "body is exactly the post-header bytes"

    def test_content_length_counts_bytes_not_characters(self) -> None:
        body = "héllo"  # 6 bytes in UTF-8, 5 characters
        payload = build(size=64, method="post", body=body)
        assert b"Content-Length: 6\r\n" in payload

    def test_padding_never_follows_a_body(self) -> None:
        """The historical failure mode, named in the builder's docstring: at a
        size above the natural request length, filler must go inside the header
        block, so the body remains the final bytes and total length is exact."""
        body = "a=1&b=2"
        payload = build(size=1000, method="post", body=body)
        assert len(payload) == 1000
        assert payload.endswith(body.encode("utf-8"))
        assert b"X-Pad: " in payload

    def test_no_padding_when_size_below_the_natural_length(self) -> None:
        body = "a=1&b=2"
        payload = build(size=64, method="post", body=body)
        assert b"X-Pad" not in payload
        assert payload.endswith(body.encode("utf-8"))

    def test_empty_body_is_a_valid_post(self) -> None:
        payload = build(size=64, method="post")
        assert b"Content-Length: 0\r\n" in payload
        assert payload.endswith(b"\r\n\r\n")

    def test_custom_content_type(self) -> None:
        payload = build(size=64, method="post", body="{}", content_type="application/json")
        assert b"Content-Type: application/json\r\n" in payload

    def test_keep_alive_post_framing_survives_reuse(self) -> None:
        """On a reused connection a wrong Content-Length stalls the peer's
        parser, so this framing is what makes post + keep-alive usable."""
        body = "a=1"
        payload = build(size=1000, method="post", body=body, keep_alive=True)
        assert b"Connection: keep-alive\r\n" in payload
        assert payload.endswith(body.encode("utf-8"))
        head, _, rest = payload.partition(b"\r\n\r\n")
        assert b"X-Pad: " in head, "padding lives in the header block, never after the body"
        assert rest == body.encode("utf-8")


# ---------------------------------------------------------------------------
# HEAD
# ---------------------------------------------------------------------------


class TestHead:
    def test_head_request_line(self) -> None:
        payload = build(size=128, method="head")
        assert payload.startswith(b"HEAD /api/data HTTP/1.1\r\n")

    def test_head_sends_no_body_framing(self) -> None:
        payload = build(size=512, method="head")
        assert b"Content-Length" not in payload
        expected = DEFAULT_REQUEST_HEAD.replace(b"GET ", b"HEAD ", 1)
        assert payload.startswith(expected)

    def test_head_still_carries_the_cache_buster(self) -> None:
        payload = build(size=128, method="head")
        assert b"X-Ddosim-Seq: 7\r\n" in payload


# ---------------------------------------------------------------------------
# Cookie and Referer
# ---------------------------------------------------------------------------


class TestCookieAndReferer:
    def test_cookie_line_is_sent_when_configured(self) -> None:
        payload = build(size=512, cookie_header="id=xxx; session=yyy")
        assert b"Cookie: id=xxx; session=yyy\r\n" in payload

    def test_referer_line_is_sent_when_configured(self) -> None:
        payload = build(size=512, referer="https://example.com/page")
        assert b"Referer: https://example.com/page\r\n" in payload

    def test_identity_headers_precede_connection(self) -> None:
        """Order is part of the request's identity, so the insertion point is
        pinned: persona block, then Referer, then Cookie, then Connection."""
        payload = build(
            size=512,
            cookie_header="a=b",
            referer="https://example.com/",
        )
        head = payload.partition(b"\r\n\r\n")[0]
        accept = head.index(b"Accept: */*")
        referer = head.index(b"Referer: ")
        cookie = head.index(b"Cookie: ")
        connection = head.index(b"Connection: close")
        assert accept < referer < cookie < connection

    def test_options_reach_head_and_post_alike(self) -> None:
        for method in ("post", "head"):
            payload = build(size=512, method=method, cookie_header="a=b", referer="https://x.test/")
            assert b"Cookie: a=b\r\n" in payload
            assert b"Referer: https://x.test/\r\n" in payload


# ---------------------------------------------------------------------------
# Path
# ---------------------------------------------------------------------------


class TestPath:
    def test_custom_path_is_used_verbatim(self) -> None:
        payload = build(size=128, path="/login?next=%2F")
        assert payload.startswith(b"GET /login?next=%2F HTTP/1.1\r\n")

    def test_default_path_is_unchanged(self) -> None:
        assert build(size=128).startswith(b"GET /api/data HTTP/1.1\r\n")


# ---------------------------------------------------------------------------
# Validators: a bad shape is refused before a run starts
# ---------------------------------------------------------------------------


def profile(**kw) -> AttackProfile:
    kw.setdefault("profile", ProfileName.HTTP_FLOOD)
    return AttackProfile(**kw)


class TestValidators:
    def test_unknown_method_is_refused_with_the_valid_set(self) -> None:
        with pytest.raises(ValidationError, match="get, post, head"):
            profile(http_method="delete")

    def test_method_is_normalised_to_lowercase(self) -> None:
        assert profile(http_method="POST").http_method == "post"

    def test_path_must_start_with_a_slash(self) -> None:
        with pytest.raises(ValidationError, match="must start with"):
            profile(http_path="api/data")

    def test_path_must_not_contain_a_raw_space(self) -> None:
        with pytest.raises(ValidationError, match="splits the request line"):
            profile(http_path="/a b")

    def test_crlf_in_a_header_value_is_refused(self) -> None:
        """A CR or LF inside a header ends the header block early; the bytes
        after it parse as a second request the run never configured."""
        with pytest.raises(ValidationError, match="second request"):
            profile(cookie_header="a=b\r\nX-Evil: 1")

    def test_crlf_in_referer_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="second request"):
            profile(referer="https://x.test/\r\nHost: evil.test")

    def test_crlf_in_path_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="control characters"):
            profile(http_path="/a\r\nX-Evil: 1")

    def test_crlf_in_content_type_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="second request"):
            profile(content_type="text/plain\r\nX-Evil: 1")

    def test_body_requires_post(self) -> None:
        with pytest.raises(ValidationError, match="requires http_method 'post'"):
            profile(http_body="a=1")

    def test_body_with_head_is_refused_too(self) -> None:
        with pytest.raises(ValidationError, match="requires http_method 'post'"):
            profile(http_method="head", http_body="a=1")

    def test_empty_body_with_get_is_fine(self) -> None:
        assert profile(http_body="").http_method == "get"


# ---------------------------------------------------------------------------
# CLI mapping
# ---------------------------------------------------------------------------


def parse(argv: list[str]):
    return build_parser().parse_args(["--host", "127.0.0.1", "--profile", "http_flood", *argv])


class TestCliMapping:
    def test_flags_reach_the_profile(self) -> None:
        config = config_from_args(
            parse(["--method", "post", "--path", "/login", "--data", "a=1&b=2",
                   "--cookie", "id=1", "--referer", "https://x.test/"])
        )
        attack = config.attack
        assert attack.http_method == "post"
        assert attack.http_path == "/login"
        assert attack.http_body == "a=1&b=2"
        assert attack.cookie_header == "id=1"
        assert attack.referer == "https://x.test/"

    def test_defaults_survive_a_namespace_without_the_flags(self) -> None:
        """Hand-built Namespaces in older tests predate these flags."""
        args = parse([])
        del args.method, args.http_path, args.cookie, args.referer
        del args.data, args.data_file, args.content_type
        config = config_from_args(args)
        assert config.attack.http_method == "get"
        assert config.attack.http_path == "/api/data"
        assert config.attack.http_body == ""

    def test_data_file_is_read_into_the_body(self, tmp_path) -> None:
        body_file = tmp_path / "body.json"
        body_file.write_text('{"a": 1}', encoding="utf-8")
        config = config_from_args(parse(["--method", "post", "--data-file", str(body_file)]))
        assert config.attack.http_body == '{"a": 1}'

    def test_data_file_overrides_data(self, tmp_path) -> None:
        body_file = tmp_path / "body.txt"
        body_file.write_text("from-file", encoding="utf-8")
        config = config_from_args(
            parse(["--method", "post", "--data", "from-flag", "--data-file", str(body_file)])
        )
        assert config.attack.http_body == "from-file"

    def test_missing_data_file_is_a_clean_exit_not_a_traceback(self) -> None:
        with pytest.raises(SystemExit):
            config_from_args(parse(["--method", "post", "--data-file", "does-not-exist.json"]))

    def test_bad_header_value_refused_at_config_time(self) -> None:
        """The refusal is a clean exit naming the field, not a pydantic
        traceback - the operator sees the one line that matters."""
        with pytest.raises(SystemExit):
            config_from_args(parse(["--cookie", "a=b\r\nX-Evil: 1"]))

    def test_the_refusal_names_the_field_and_reason(self, capsys) -> None:
        with pytest.raises(SystemExit):
            config_from_args(parse(["--cookie", "a=b\r\nX-Evil: 1"]))
        out = capsys.readouterr().out
        assert "cookie_header" in out
        assert "control characters" in out
