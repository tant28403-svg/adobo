"""Measure what adobo's HTTP/2 preamble actually puts on the wire.

:mod:`adobo.h2profile` says what a profile *claims*. This module says what the
bytes *are*, by connecting to a loopback server, capturing the connection
preamble, and decoding it with the same :func:`~adobo.h2profile.decode_preamble`
the tests use.

The reason to build a network harness at all rather than printing the declared
values: the h2 library offers no supported way to set the initial SETTINGS frame
(see the ``adobo.h2profile`` docstring for the four ways it was measured to fail),
so the code that installs those values reaches around h2's public surface. A
declaration that reads back correctly proves nothing about whether the frame on the
wire is right. Only the bytes settle it.

Everything here binds to 127.0.0.1 on an ephemeral port, makes no outbound
connection, and is reachable only from the CLI's ``--inspect-h2`` flag. It never
opens a socket to the target: an inspection of what adobo *would* send must not
send it.

Deliberately cleartext. The HTTP/2 fingerprint lives above TLS, so a plain socket
shows every component this tool claims to reproduce; a TLS handshake would add a
certificate requirement and hide the frames behind a layer that is not part of the
claim. It does mean the inspection cannot speak about JA3 - see the declined list
in :mod:`adobo.h2profile`.
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field

from .h2profile import (
    DEFAULT_PSEUDO_HEADER_ORDER,
    H2Profile,
    Preamble,
    decode_preamble,
    setting_name,
)

__all__ = ["Inspection", "capture_preamble", "inspect_profile", "render_inspection"]

_INSPECT_TIMEOUT = 5.0
"""Seconds to wait for the loopback exchange. Generous for loopback, and finite so
a hung inspection cannot wedge the CLI."""

_PRE_READ = 4096
"""Bytes to pull off the loopback socket. One preamble plus one HEADERS frame is
well under this; anything more is ignored, and anything less is reported as a
short capture rather than padded."""


@dataclass
class Inspection:
    """The result of one inspection. Every field is a measurement or an absence.

    Absence is reported rather than implied: ``preamble is None`` means the
    exchange produced nothing decodable, which is a different outcome from
    ``error is None and preamble.settings() is empty``, which means the frames
    arrived and declared no settings. Collapsing the two would let a broken
    harness report as a clean result.
    """

    profile: H2Profile
    preamble: Preamble | None
    pseudo_header_order: tuple[str, ...] | None = None
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Whether the exchange completed and the preamble was decodable."""
        return self.preamble is not None and self.error is None

    def settings_match(self) -> bool | None:
        """Whether observed SETTINGS equal the declared ones, or ``None`` unknown."""
        if self.preamble is None:
            return None
        return self.preamble.settings() == self.profile.setting_map()

    def window_matches(self) -> bool | None:
        """Whether the observed WINDOW_UPDATE equals the declared one."""
        if self.preamble is None:
            return None
        return self.preamble.window_update() == self.profile.window_increment()

    def extra_settings(self) -> dict[int, int]:
        """Settings observed that the profile did not declare.

        Reported separately from a mismatch because for two of the three browser
        profiles this is *expected*: h2 always emits RFC 7540's default settings
        and a profile can override a setting but cannot remove one. It is the
        difference between "we sent what we said plus what h2 always sends" and
        "we sent the wrong thing", and the reader is better served by seeing which.
        """
        if self.preamble is None:
            return {}
        declared = self.profile.setting_map()
        return {k: v for k, v in self.preamble.settings().items() if k not in declared}

    def absent_settings(self) -> dict[int, int]:
        """Declared settings that did not appear on the wire.

        Empty in normal operation. Non-empty means the profile is not being applied
        at all, which is the failure this whole tool exists to make visible.
        """
        if self.preamble is None:
            return {}
        return {k: v for k, v in self.profile.setting_map().items() if k not in self.preamble.settings()}


def _serve_once(listener: socket.socket, captured: dict[str, object]) -> None:
    """Accept one connection, capture its bytes, and decode its pseudo-header order.

    Decoding pseudo-header order needs HPACK, which means handing the capture to a
    server-side h2 connection rather than reading the HEADERS frame directly. So
    the SETTINGS and WINDOW_UPDATE numbers come from a raw frame walk and the
    pseudo-header order comes from h2. Two independent readers of the same bytes,
    which is why the report can say they agree.

    Errors are recorded rather than raised: an inspection that cannot complete is
    a result, and a traceback would tell the operator less than a sentence.
    """
    import h2.config
    import h2.connection
    import h2.events

    try:
        conn, _ = listener.accept()
    except OSError as exc:
        captured["error"] = f"loopback accept failed: {exc}"
        return

    try:
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        chunks: list[bytes] = []
        order: list[str] = []
        # Feed bytes to the h2 server connection as they arrive rather than
        # reading to a guessed length: the client sends the connection preamble
        # and the first HEADERS frame as two separate writes, so a fixed read
        # either stops early and reports no pseudo-header order or blocks waiting
        # for bytes that will never come. RequestReceived is the signal that the
        # capture holds everything the fingerprint needs.
        conn.settimeout(0.5)
        deadline = _INSPECT_TIMEOUT
        while order == [] and deadline > 0:
            try:
                chunk = conn.recv(_PRE_READ - sum(len(c) for c in chunks))
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            deadline -= 0.5
            joined = b"".join(chunks)
            captured["raw"] = joined
            try:
                for event in server.receive_data(chunk):
                    if isinstance(event, h2.events.RequestReceived):
                        for name, _ in event.headers:
                            if name in (":method", ":authority", ":scheme", ":path"):
                                order.append(name)
            except Exception:  # noqa: BLE001 - partial captures are expected here
                break
        captured["raw"] = b"".join(chunks)
        captured["order"] = tuple(order)
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        captured["error"] = f"loopback decode failed: {type(exc).__name__}: {exc}"
    finally:
        try:
            conn.close()
        except OSError:
            pass


def capture_preamble(profile: H2Profile, *, pseudo_header_order: tuple[str, ...] | None = None) -> Inspection:
    """Send *profile*'s preamble to a loopback listener and report what came back.

    Builds the preamble through the same :meth:`H2Profile.apply` the transport
    uses, so this measures the shipping code path and not a reimplementation of it.
    The one thing it does not exercise is the transport's own call site, which
    ``tests/test_h2profile.py`` covers separately - the two together mean neither
    the harness nor the call site can be wrong alone and still look right.

    Args:
        profile: The preamble to send. ``None`` is never passed here; a caller with
            no preamble should not inspect one, and passing a profile is how it
            becomes explicit which bytes are on trial.
        pseudo_header_order: Order to send a request's pseudo-headers in, so the
            fourth fingerprint component can be measured too. Defaults to the
            profile's own order.
    """
    import h2.config
    import h2.connection

    inspection = Inspection(profile=profile, preamble=None)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    captured: dict[str, object] = {}
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(_INSPECT_TIMEOUT)

        server_thread = threading.Thread(
            target=_serve_once, args=(listener, captured), daemon=True
        )
        server_thread.start()

        conn = socket.create_connection(listener.getsockname(), timeout=_INSPECT_TIMEOUT)
        try:
            h2_conn = h2.connection.H2Connection(
                config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            )
            profile.apply(h2_conn)
            h2_conn.initiate_connection()
            increment = profile.window_increment()
            if increment:
                h2_conn.increment_flow_control_window(increment)
            conn.sendall(h2_conn.data_to_send())

            order = pseudo_header_order or profile.pseudo_header_order
            values = {
                ":method": "GET",
                ":path": "/",
                ":authority": "inspect.local",
                ":scheme": "https",
            }
            stream_id = h2_conn.get_next_available_stream_id()
            h2_conn.send_headers(
                stream_id,
                [(name, values[name]) for name in order],
                end_stream=True,
            )
            conn.sendall(h2_conn.data_to_send())
        finally:
            try:
                conn.close()
            except OSError:
                pass

        server_thread.join(timeout=_INSPECT_TIMEOUT)
        if server_thread.is_alive():
            inspection.error = "loopback listener did not finish within the timeout"
            return inspection
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        inspection.error = f"inspection could not run: {type(exc).__name__}: {exc}"
        return inspection
    finally:
        try:
            listener.close()
        except OSError:
            pass

    if captured.get("error"):
        inspection.error = str(captured["error"])
    raw = captured.get("raw")
    if not raw:
        inspection.error = inspection.error or "loopback listener captured no bytes"
        return inspection

    inspection.preamble = decode_preamble(raw)
    order = captured.get("order")
    inspection.pseudo_header_order = tuple(order) if order else None

    if not inspection.preamble.magic_ok:
        inspection.notes.append(
            "connection preamble magic missing or misplaced: the peer would "
            "reject this connection outright"
        )
    if inspection.preamble.settings_frame_count() > 1:
        inspection.notes.append(
            f"{inspection.preamble.settings_frame_count()} SETTINGS frames sent; "
            "browsers send exactly one, so the frame count is itself a fingerprint"
        )
    if inspection.absent_settings():
        missing = ", ".join(
            setting_name(code) for code in sorted(inspection.absent_settings())
        )
        inspection.notes.append(
            f"declared but absent from the wire: {missing} - the profile is not "
            "being applied"
        )
    return inspection


def inspect_profile(profile: H2Profile | None) -> Inspection:
    """Inspect *profile*, or explain that there is nothing to inspect.

    A run with no preamble is a legitimate configuration, not an error, so this
    reports it as such. Returning an :class:`Inspection` with a populated ``error``
    and a ``None`` preamble keeps the caller from having to special-case ``None``,
    which is the shape of code that grows a second, untested path.
    """
    if profile is None:
        sentinel = H2Profile(
            key="none",
            label="no preamble configured",
            settings=(),
            pseudo_header_order=DEFAULT_PSEUDO_HEADER_ORDER,
            incomplete_because=(
                "this run configures no HTTP/2 preamble, so the connection "
                "presents h2's library defaults and impersonates no browser"
            ),
        )
        return Inspection(profile=sentinel, preamble=None, error="no preamble configured")
    return capture_preamble(profile)


def render_inspection(inspection: Inspection) -> list[str]:
    """Format an inspection for the terminal.

    Ordering is deliberate: the verdict first, then the evidence. A reader who
    stops after the first line gets the answer; a reader who wants to know why
    keeps going.
    """
    profile = inspection.profile
    lines = [f"HTTP/2 connection preamble: {profile.label}  [{profile.key}]"]

    if inspection.preamble is None:
        lines.append(f"  ! {inspection.error or 'nothing was captured'}")
        lines.append(f"  declared fingerprint: {profile.fingerprint()}")
        if profile.incomplete_because:
            lines.append(f"  incomplete because: {profile.incomplete_because}")
        return lines

    preamble = inspection.preamble
    settings_ok = inspection.settings_match()
    window_ok = inspection.window_matches()

    if inspection.error:
        lines.append(f"  ! {inspection.error}")
    lines.append(
        "  verdict: "
        + (
            "declared settings and window update match the bytes on the wire"
            if settings_ok and window_ok
            else "declared values DO NOT match the bytes on the wire"
            if settings_ok is False or window_ok is False
            else "could not be measured"
        )
    )

    lines.append(f"  declared: {profile.fingerprint()}")
    observed_order = inspection.pseudo_header_order
    lines.append(
        "  observed: "
        + preamble.fingerprint(observed_order)
        if observed_order
        else f"  observed: {preamble.fingerprint()}"
    )

    lines.append("")
    lines.append("  frames as sent:")
    for line in preamble.describe():
        lines.append(line)

    wire_order = preamble.settings_wire_order()
    if wire_order:
        lines.append(
            "  settings order on the wire: "
            + ",".join(setting_name(code) for code in wire_order)
        )
        lines.append(
            "    (the fingerprint string above sorts these ascending, per the "
            "published scheme; browsers send them ascending and h2 does not)"
        )

    if inspection.pseudo_header_order:
        declared_order = profile.pseudo_header_order
        agrees = inspection.pseudo_header_order == declared_order
        lines.append(
            f"  pseudo-header order: {'agrees' if agrees else 'DIFFERS'} with the "
            f"profile (observed {inspection.pseudo_header_order[0]}, "
            f"{len(inspection.pseudo_header_order)} fields)"
        )
        if not agrees:
            lines.append(
                f"    declared {declared_order}, observed "
                f"{inspection.pseudo_header_order}"
            )

    extra = inspection.extra_settings()
    if extra:
        listed = ", ".join(
            f"{setting_name(code)}={value}" for code, value in sorted(extra.items())
        )
        lines.append(f"  sent in addition to the profile: {listed}")
        lines.append(
            "    (h2 always emits RFC 7540's default settings; a profile can "
            "override one but not remove it)"
        )

    absent = inspection.absent_settings()
    if absent:
        listed = ", ".join(
            f"{setting_name(code)}={value}" for code, value in sorted(absent.items())
        )
        lines.append(f"  declared but NOT sent: {listed}")

    for note in inspection.notes:
        lines.append(f"  ! {note}")

    if profile.incomplete_because:
        lines.append("")
        lines.append(f"  incomplete because: {profile.incomplete_because}")
        lines.append(f"  values transcribed from: {profile.source}")

    lines.append("")
    lines.append(
        "  Not reproduced, and not claimed: the priority tree (h2 rejects Firefox's "
        "weight-0 streams), and JA3 (Python's ssl cannot order TLS extensions). "
        "A request built from these bytes and a real browser's TLS handshake is "
        "still a combination no browser produces."
    )
    return lines
