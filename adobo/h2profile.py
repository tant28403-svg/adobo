"""HTTP/2 connection preambles: what the client says before any request.

A persona from :mod:`adobo.fingerprint` describes a request - its headers, in
order. That is only half of what a client announces. Before a single byte of
HTTP/2 payload moves, the connection itself has already identified itself three
more times, in the SETTINGS frame, the connection-level WINDOW_UPDATE, and the
order of the pseudo-headers on every subsequent stream.

Those are passive-fingerprintable with no cooperation from the server, and they
are what the published HTTP/2 fingerprint scheme
(``[SETTINGS]|WINDOW_UPDATE|PRIORITY|Pseudo-Header-Order|HEADERS_FRAME|WINDOW_UPDATE*``)
is built from. A run that sends Firefox's headers over a preamble that is
plainly not Firefox's has not impersonated a browser; it has assembled one from
two sources, and the mismatch is the thing a detector looks for.

This module supplies a preamble per persona and, more importantly, supplies the
means to *check* it. :func:`decode_preamble` reads the frame bytes back off a
socket and renders them in the same canonical form as :meth:`H2Profile.fingerprint`.
Comparing the two strings is a real measurement of what went out, not a restatement
of what was intended. Every fidelity claim this codebase makes about HTTP/2 is
meant to be settled that way, by ``tests/test_h2profile.py`` and by
``adobo --inspect-h2``.

What is emulated, and what is not
----------------------------------

Three of the scheme's components are reachable in Python:

* **SETTINGS** - reproduced exactly, subject to the constraint below.
* **WINDOW_UPDATE** - reproduced exactly.
* **Pseudo-header order** - reproduced exactly.

Three are not, and are declined rather than faked:

* **PRIORITY frames.** Firefox's published priority tree uses stream weights of
  0. ``h2`` rejects them: ``ProtocolError: Weight must be between 1 and 256, not
  0`` (``h2/connection.py``). Emitting weight 1 instead would produce a
  fingerprint that differs from Firefox's in exactly the field being
  impersonated, so no priority tree is sent and :attr:`H2Profile.priority` is
  empty for every profile. See :attr:`H2Profile.incomplete_because`.
* **HEADERS_FRAME padding and weight.** ``h2`` offers no control over the
  priority weight on ``send_headers`` beyond the tree it already refuses, and
  pad length is not settable per-stream.
* **TLS / JA3.** Python's ``ssl`` module cannot control TLS extension *order*,
  which is the primary JA3 discriminator. Cipher list and ALPN can be matched; a
  browser cannot be reproduced. A partial match described as "Chrome-like" would
  be an overclaim, so it is not offered at all.

Any profile whose SETTINGS cannot be made exact says so in
:attr:`H2Profile.incomplete_because` rather than quietly emitting the nearest
thing it can.

The h2 dependency, and why this module is fragile
-------------------------------------------------

``h2`` provides **no supported way to set the initial SETTINGS frame**. Measured
on h2 4.4.1:

* ``conn.update_settings(...)`` before ``initiate_connection()`` queues frames
  ahead of the connection preamble. The peer sees a SETTINGS frame where the
  ``PRI * HTTP/2.0`` magic belongs and rejects it with
  ``ProtocolError: Invalid HTTP/2 preamble``.
* ``conn.update_settings(...)`` after ``initiate_connection()`` is legal but
  emits a **second** SETTINGS frame. Real browsers send exactly one, so the
  frame count alone is a fingerprint.
* ``conn.local_settings[k] = v`` appears to work and silently does nothing.
  ``h2.settings.Settings`` is a ``MutableMapping`` whose ``__setitem__`` queues a
  proposed value for acknowledgement rather than committing it, and its
  ``update()`` is the inherited ``MutableMapping`` one, so it inherits the same
  no-op. Verified by reading the value back: still the default.
* ``H2Configuration`` has no parameter for initial settings;
  ``H2Connection.__init__`` hardcodes
  ``initial_values={MAX_CONCURRENT_STREAMS: 100, MAX_HEADER_LIST_SIZE: 65536}``.

The one route that works is to rebuild the settings object from its documented
``initial_values`` constructor parameter before initiating, which is what
:meth:`H2Profile.apply` does. That is reaching around the library's public
surface: ``Settings(initial_values=...)`` is documented, *which attribute to
replace it on* is not. An h2 upgrade could break this silently.

That is why the load-bearing test in ``tests/test_h2profile.py`` does not assert
on ``h2``'s API. It drives the real transport, captures the bytes it puts on the
wire, decodes them, and asserts the decoded SETTINGS equal the declared profile.
If a future h2 makes this stop working, that test fails. A test written against
``h2``'s own API would keep passing while the tool quietly sent the wrong
preamble, which is the failure mode this module exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import DEFAULT_FINGERPRINT_KEY

__all__ = [
    "DEFAULT_PSEUDO_HEADER_ORDER",
    "H2_PROFILES",
    "H2Profile",
    "Preamble",
    "SETTING_NAMES",
    "apply_profile",
    "decode_pseudo_header_order",
    "decode_preamble",
    "h2_profile",
    "h2_profile_for_persona",
    "profile_keys",
    "setting_name",
]

SETTING_NAMES: dict[int, str] = {
    1: "HEADER_TABLE_SIZE",
    2: "ENABLE_PUSH",
    3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE",
    5: "MAX_FRAME_SIZE",
    6: "MAX_HEADER_LIST_SIZE",
    8: "ENABLE_CONNECT_PROTOCOL",
}
"""Setting identifier to RFC name, for rendering a fingerprint readably."""

_SHORT_PSEUDO = {":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}

DEFAULT_PSEUDO_HEADER_ORDER: tuple[str, ...] = (":method", ":path", ":authority", ":scheme")
"""The order adobo has always sent, and the order Firefox uses.

Kept as the default so that a run with no persona configured emits precisely the
bytes it emitted before this module existed. ``m,p,a,s`` is Firefox's order,
coincidentally the order the code was written in - which is why impersonating
Chrome requires changing it explicitly rather than inheriting it.
"""


@dataclass(frozen=True)
class H2Profile:
    """One HTTP/2 connection preamble.

    Frozen for the same reason :class:`~adobo.fingerprint.Fingerprint` is: a
    profile is shared across worker threads for the life of a run and is read,
    never written.

    Attributes:
        key: Stable identifier used on the command line and in reports.
        label: Human-readable description.
        settings: Ordered ``(code, value)`` pairs to advertise, in the order
            they are sent. Order is part of the fingerprint - a SETTINGS frame
            whose entries are reordered is a different fingerprint - so this is a
            tuple of pairs and never a dict.
        window_update: Connection-level flow-control increment to send directly
            after the SETTINGS frame, or ``None`` to send none.
        pseudo_header_order: Order of the four HTTP/2 pseudo-headers on every
            stream.
        incomplete_because: Human-readable statement of which parts of the
            published scheme this profile cannot reproduce, or ``None`` when it
            can reproduce all of them. Surfaced in the report and by
            ``--inspect-h2``. An empty string is never used: absence means
            "nothing is missing", so the note cannot be confused with silence.
        source: Where the values were transcribed from. Kept as data rather than
            prose in a docstring so that a report can print it next to the
            numbers, which is what lets a reader judge them.
    """

    key: str
    label: str
    settings: tuple[tuple[int, int], ...]
    window_update: int | None = None
    pseudo_header_order: tuple[str, ...] = DEFAULT_PSEUDO_HEADER_ORDER
    incomplete_because: str | None = None
    source: str = ""

    def setting_map(self) -> dict[int, int]:
        """The settings as a mapping, for comparison and rendering."""
        return dict(self.settings)

    def fingerprint(self) -> str:
        """Render this profile in the published fingerprint scheme.

        The first four components, which are the four that exist at connection
        time and the four this module either reproduces or declines::

            [1:65536;3:1000;4:6291456]|15663105|0|m,a,s,p

        ``0`` in the third field means "no PRIORITY frames", which is the
        scheme's own notation for an empty priority tree and not a placeholder.

        Settings are rendered in ascending code order regardless of the order this
        profile declares them in, because that is how the published captures are
        written and because :meth:`Preamble.fingerprint` cannot know the wire
        order it is decoding into the same string. Rendering both sides ascending
        is what makes the two comparable. Wire order is a separate signal and is
        reported by :meth:`Preamble.settings_wire_order`.

        This string is what :func:`decode_preamble` is expected to reproduce from
        real bytes. Equality between the two is the only claim of fidelity worth
        making, and it is a measurement.
        """
        body = ";".join(
            f"{code}:{value}" for code, value in sorted(self.setting_map().items())
        )
        window = "0" if self.window_update is None else str(self.window_update)
        order = ",".join(_SHORT_PSEUDO[name] for name in self.pseudo_header_order)
        return f"[{body}]|{window}|0|{order}"

    def short(self) -> str:
        """The settings and window only, for a one-line summary."""
        body = ";".join(
            f"{setting_name(code)}={value}" for code, value in self.settings
        )
        return f"{body} window={self.window_update or 0}"

    def apply(self, conn: object) -> None:
        """Configure *conn* so its preamble matches this profile.

        Must be called **before** ``initiate_connection()``: that method is what
        serialises ``local_settings`` into the single SETTINGS frame, and it is
        the only moment at which those values can be influenced.

        Replaces ``conn.local_settings`` wholesale rather than assigning into it,
        because assigning into it does nothing - see the module docstring.
        ``max_inbound_frame_size`` is re-derived afterwards for the same reason:
        ``H2Connection.__init__`` derives it from the settings it built, so
        changing ``MAX_FRAME_SIZE`` without re-deriving would leave the two
        disagreeing and the connection would mis-frame.

        The connection-level WINDOW_UPDATE is **not** sent here. It must follow
        ``initiate_connection()``, because ``increment_flow_control_window``
        emits a frame immediately and anything emitted before the
        ``PRI * HTTP/2.0`` magic is a malformed preface. :meth:`window_increment`
        returns the value for the caller to apply at the right moment.
        """
        from h2.settings import SettingCodes, Settings

        initial = {SettingCodes(code): value for code, value in self.settings}
        # ``client=True`` matches how H2Connection builds a client-side Settings:
        # ENABLE_PUSH defaults to 1 for a client. Passing the wrong one would
        # silently flip the push setting relative to every other value.
        conn.local_settings = Settings(client=True, initial_values=initial)
        conn.max_inbound_frame_size = conn.local_settings.max_frame_size

    def window_increment(self) -> int | None:
        """The WINDOW_UPDATE to send after initiating, or ``None`` for none."""
        return self.window_update


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------
#
# Values are transcribed from published passive-fingerprinting captures, not
# invented. Each profile records where it came from in its ``source`` field so a
# report can show it alongside the numbers; a reader who disagrees with a value
# can see what to check.
#
# One constraint applies to all of them and is worth stating plainly: h2 always
# includes the settings from RFC 7540's defaults that a browser may omit, because
# a profile can add and override settings but cannot remove them. A browser that
# does not send SETTINGS_MAX_CONCURRENT_STREAMS cannot be reproduced by a client
# that always does. Whether that leaves a given profile exact is asserted in the
# tests against decoded wire bytes rather than assumed here.

_H2_LIBRARY = H2Profile(
    key="h2_library",
    label="h2 library defaults (adobo's existing behaviour)",
    settings=(
        (1, 4096),
        (2, 1),
        (4, 65535),
        (5, 16384),
        (8, 0),
        (3, 100),
        (6, 65536),
    ),
    window_update=None,
    pseudo_header_order=DEFAULT_PSEUDO_HEADER_ORDER,
    source="h2 4.4.1 H2Connection.__init__ defaults",
)
"""What adobo sends today.

Exists so that "no persona" is a nameable profile rather than an absence, which
is what lets ``--inspect-h2`` print the same thing for every input and lets a
test assert the default path is untouched by comparing it against this.
"""

_CHROME_131 = H2Profile(
    key="chrome_131",
    label="Chrome 131 connection preamble",
    settings=(
        (1, 65536),
        (2, 0),
        (4, 6291456),
        (5, 16384),
        (8, 0),
        (3, 1000),
        (6, 262144),
    ),
    window_update=15663105,
    pseudo_header_order=(":method", ":authority", ":scheme", ":path"),
    source=(
        "Published passive HTTP/2 captures of Chrome (LRZ / Akamai h2 scheme), "
        "carried forward to 131; these values have been stable across recent "
        "Chrome releases"
    ),
)

_FIREFOX_133 = H2Profile(
    key="firefox_133",
    label="Firefox 133 connection preamble",
    settings=(
        (1, 65536),
        (4, 131072),
        (5, 16384),
    ),
    window_update=12517377,
    pseudo_header_order=(":method", ":path", ":authority", ":scheme"),
    incomplete_because=(
        "Firefox's priority tree uses stream weights of 0, which h2 rejects "
        "(ProtocolError: Weight must be between 1 and 256, not 0), so no "
        "PRIORITY frames are sent. h2 also always advertises ENABLE_PUSH and "
        "ENABLE_CONNECT_PROTOCOL from RFC 7540's defaults, which Firefox does "
        "not send. Measured on decoded wire bytes, this preamble matches Firefox "
        "on SETTINGS_INITIAL_WINDOW_SIZE and SETTINGS_MAX_FRAME_SIZE, matches "
        "exactly on the connection WINDOW_UPDATE, and matches on pseudo-header "
        "order; it carries two settings Firefox does not send and omits the "
        "priority tree."
    ),
    source=(
        "Published passive HTTP/2 captures of Firefox (LRZ / Akamai h2 scheme), "
        "carried forward to 133"
    ),
)

_SAFARI_18 = H2Profile(
    key="safari_18",
    label="Safari 18 connection preamble",
    settings=(
        (1, 4096),
        (2, 0),
        (4, 4194304),
        (5, 16384),
    ),
    window_update=10485760,
    pseudo_header_order=(":method", ":authority", ":scheme", ":path"),
    incomplete_because=(
        "h2 always advertises ENABLE_CONNECT_PROTOCOL from RFC 7540's defaults, "
        "which Safari does not send. Measured on decoded wire bytes, this "
        "preamble matches Safari on the settings it declares, matches exactly "
        "on the connection WINDOW_UPDATE, and matches on pseudo-header order; "
        "it carries one setting Safari does not send. These Safari values are "
        "less well corroborated than the Chrome and Firefox ones and should be "
        "checked against a fresh capture with --inspect-h2 before being relied "
        "on."
    ),
    source="Published Safari HTTP/2 captures; values less corroborated than Chrome/Firefox",
)

H2_PROFILES: dict[str, H2Profile] = {
    profile.key: profile
    for profile in (_H2_LIBRARY, _CHROME_131, _FIREFOX_133, _SAFARI_18)
}


def profile_keys() -> list[str]:
    """Every profile key, in registry order, ``h2_library`` first."""
    return list(H2_PROFILES)


def h2_profile(key: str) -> H2Profile:
    """Look up a preamble profile by key.

    Raises:
        ValueError: with the valid keys listed. ``ValueError`` rather than
            ``KeyError`` because this runs inside pydantic validators, which
            convert ``ValueError`` and let a ``KeyError`` escape raw.
    """
    try:
        return H2_PROFILES[key]
    except KeyError:
        raise ValueError(
            f"unknown h2 profile {key!r}; choose one of: " + ", ".join(profile_keys())
        ) from None


def setting_name(code: int) -> str:
    """RFC name for a settings identifier, or its hex if unrecognised."""
    return SETTING_NAMES.get(code, f"UNKNOWN_0x{code:x}")


def h2_profile_for_persona(persona_key: str) -> H2Profile | None:
    """The preamble that matches an HTTP persona, or ``None`` if there is none.

    Pairs the two halves of the same identity so that ``--fingerprint
    chrome_131_win --http2`` does not produce a Chrome User-Agent over a preamble
    no Chrome sends. A persona assembled from two incoherent sources is more
    detectable than either half on its own, and coherence is the entire reason
    personas exist.

    Matched by stem, because personas are per-platform (``chrome_131_win``,
    ``chrome_131_mac``) while the HTTP/2 preamble is a property of the browser
    engine and does not vary by OS. So all four Chrome personas resolve to the one
    ``chrome_131`` preamble.

    Returns ``None`` for the self-identifying lab client, and for any persona with
    no matching preamble. ``None`` means "send no preamble change", which is a
    deliberate state rather than a failure: it leaves the bytes exactly as they
    were, and the caller reports it rather than substituting a near-miss profile.
    """
    if persona_key == DEFAULT_FINGERPRINT_KEY:
        return None
    stem = persona_key.rsplit("_", 1)[0] if "_" in persona_key else persona_key
    return H2_PROFILES.get(stem)


def apply_profile(conn: object, profile: H2Profile) -> None:
    """Module-level alias for :meth:`H2Profile.apply`.

    Exists so a caller holding a profile object and a connection can apply
    without caring which of the two owns the method.
    """
    profile.apply(conn)


# ---------------------------------------------------------------------------
# Decoding real bytes back into the same notation
# ---------------------------------------------------------------------------

_FRAME_NAMES = {
    0: "DATA",
    1: "HEADERS",
    2: "PRIORITY",
    3: "RST_STREAM",
    4: "SETTINGS",
    5: "PUSH_PROMISE",
    6: "PING",
    7: "GOAWAY",
    8: "WINDOW_UPDATE",
    9: "CONTINUATION",
}

_CLIENT_PREAMBLE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


@dataclass(frozen=True)
class Preamble:
    """What a client actually put on the wire.

    Produced by :func:`decode_preamble` from raw bytes rather than from an ``h2``
    event object, deliberately. The event objects report the *peer's* view after
    validation, which during this work disagreed with the bytes on the wire -
    reading ``RemoteSettingsChanged`` suggested settings had not been applied
    when they had, and vice versa. A frame walk over the socket is the only
    source that cannot disagree with the wire.
    """

    magic_ok: bool
    frames: tuple[dict[str, object], ...]

    def settings(self) -> dict[int, int]:
        """The SETTINGS frame's contents, merged across frames if repeated."""
        merged: dict[int, int] = {}
        for frame in self.frames:
            if frame["type"] == "SETTINGS":
                merged.update(frame["settings"])  # type: ignore[arg-type]
        return merged

    def window_update(self) -> int | None:
        """The first connection-level WINDOW_UPDATE, or ``None``."""
        for frame in self.frames:
            if frame["type"] == "WINDOW_UPDATE":
                return frame["increment"]  # type: ignore[return-value]
        return None

    def settings_frame_count(self) -> int:
        """How many SETTINGS frames were sent.

        Reported because a second frame is itself a fingerprint: browsers send
        one, and a client that emits ``update_settings`` after connecting sends
        two.
        """
        return sum(1 for f in self.frames if f["type"] == "SETTINGS")

    def settings_wire_order(self) -> tuple[int, ...]:
        """Setting identifiers in the order the frame actually carried them.

        Separate from :meth:`settings` because the published fingerprint renders
        settings in ascending code order, so two preambles that differ only in
        SETTINGS ordering produce the *same* fingerprint string. They are not
        the same fingerprint. This accessor exists so ``--inspect-h2`` can show
        ordering rather than hide it behind a sorted comparison.

        Worth knowing when reading the results: h2 emits 1, 2, 4, 5, 8, 3, 6 -
        RFC 7540's defaults in its own order, then the two non-spec settings
        ``H2Connection`` adds. Published Chrome captures are ascending. So the
        ordering of the settings adobo sends does not match a real Chrome's,
        independently of the values, and no profile in this module claims
        otherwise.
        """
        for frame in self.frames:
            if frame["type"] == "SETTINGS":
                return tuple(frame["settings"])  # type: ignore[return-value]
        return ()

    def fingerprint(self, pseudo_order: tuple[str, ...] | None = None) -> str:
        """Render the observed preamble in the published scheme.

        *pseudo_order* is the order seen on a HEADERS frame when one was decoded;
        pass ``None`` to render ``0``, which is correct for a preamble captured
        before any request was sent. Pseudo-header order cannot be read from a
        SETTINGS frame - it lives on HEADERS, which is why this module sets it at
        send time rather than at connect time.
        """
        body = ";".join(
            f"{code}:{value}" for code, value in sorted(self.settings().items())
        )
        increment = self.window_update()
        window = "0" if increment is None else str(increment)
        if pseudo_order is None:
            order = "0"
        else:
            order = ",".join(_SHORT_PSEUDO.get(name, "?") for name in pseudo_order)
        return f"[{body}]|{window}|0|{order}"

    def describe(self) -> list[str]:
        """Frame-by-frame summary, for ``--inspect-h2`` output."""
        lines: list[str] = []
        if not self.magic_ok:
            lines.append("  !! connection preamble magic is missing or misplaced")
        for frame in self.frames:
            name = frame["type"]
            if name == "SETTINGS":
                body = ", ".join(
                    f"{setting_name(int(code))}={value}"
                    for code, value in sorted(frame["settings"].items())  # type: ignore[union-attr]
                )
                lines.append(f"  {name:14} {body}")
            elif name == "WINDOW_UPDATE":
                lines.append(f"  {name:14} increment={frame['increment']}")
            elif name == "PRIORITY":
                lines.append(
                    f"  {name:14} stream={frame['stream']} "
                    f"depends_on={frame['depends_on']} weight={frame['weight']}"
                )
            else:
                lines.append(f"  {name:14} length={frame['len']}")
        return lines


def decode_preamble(data: bytes) -> Preamble:
    """Decode a client connection preamble from raw bytes.

    Handles the 24-byte client magic and then walks frames. Tolerates a partial
    trailing frame, because a capture taken mid-handshake is normal and should
    yield what was readable rather than an exception.
    """
    magic_ok = data.startswith(_CLIENT_PREAMBLE)
    body = data[len(_CLIENT_PREAMBLE):] if magic_ok else data
    frames: list[dict[str, object]] = []
    index = 0
    while index + 9 <= len(body):
        length = int.from_bytes(body[index:index + 3], "big")
        frame_type = body[index + 3]
        payload = body[index + 9:index + 9 + length]
        if len(payload) < length:
            break  # truncated trailing frame
        entry: dict[str, object] = {
            "type": _FRAME_NAMES.get(frame_type, f"UNKNOWN_{frame_type}"),
            "type_code": frame_type,
            "len": length,
        }
        if frame_type == 4 and length % 6 == 0:
            entry["settings"] = {
                int.from_bytes(payload[i:i + 2], "big"): int.from_bytes(
                    payload[i + 2:i + 6], "big"
                )
                for i in range(0, length, 6)
            }
        elif frame_type == 8 and length == 4:
            entry["increment"] = (
                int.from_bytes(payload, "big") & 0x7FFFFFFF
            )
        elif frame_type == 2 and length == 5:
            dependency = int.from_bytes(payload[1:5], "big")
            entry["stream"] = int.from_bytes(payload[0:1], "big")
            entry["depends_on"] = dependency & 0x7FFFFFFF
            entry["exclusive"] = bool(dependency & 0x80000000)
            entry["weight"] = payload[4]
        frames.append(entry)
        index += 9 + length
    return Preamble(magic_ok=magic_ok, frames=tuple(frames))


def decode_pseudo_header_order(headers: list[tuple[str, str]]) -> tuple[str, ...]:
    """Extract pseudo-header order from a decoded HEADERS list.

    Takes the names in the order they appeared and keeps only the four
    pseudo-headers, which is what the fingerprint scheme's fourth field records.
    """
    wanted = (":method", ":authority", ":scheme", ":path")
    return tuple(name for name, _ in headers if name in wanted)
