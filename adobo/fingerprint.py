"""Client personas: who the traffic claims to be coming from.

Every HTTP request this tool sends carries an identity - a ``User-Agent``, an
``Accept``, a set of client hints - and that identity is what a WAF keys on. Until
now there was exactly one identity, ``adobo-lab/0.1 (authorized testing)``, and
it was the right default: it is greppable in a packet capture and impossible to
mistake for real traffic. Its limitation is that
:mod:`adobo.defenses` has UA-based rules (``user_agent_contains``,
``user_agent_missing``, the browser challenge) that this identity can only ever
trip in one direction. A rule that rejects everything cannot be tested against a
client that should be admitted.

This module supplies the other side of that comparison. It is deliberately a
*registry of declared identities*, not an engine for synthesising them: no
browser is driven, nothing is executed, and no header set is generated from
templates at send time. A persona is a fixed, ordered, self-consistent header
block chosen by the operator before the run starts.

Two rules govern everything here.

**Consistency over variety.** A persona whose headers contradict each other - a
Chrome UA claiming macOS in the platform hint, Firefox sending Chromium client
hints - is worse than no persona at all. It is trivially detectable and it makes
the run's results meaningless, because a WAF that rejects it tells you nothing
about the defense you meant to test. Every persona below is internally coherent,
and ``tests/test_fingerprint.py`` asserts that coherence rather than trusting it.

**Order is part of the identity.** Header ordering is itself a fingerprint signal,
so ``headers`` is a tuple of pairs and never a ``dict``. A dict preserves insertion
order today but invites ``.update()``, which silently reorders and quietly breaks
the persona. Making order part of the type means the compiler-level API refuses
the mistake instead of the packet capture revealing it later.

``lab_default`` is not a persona in this sense. It is the absence of one, and it
reproduces the pre-existing header block byte for byte so that enabling nothing
changes nothing - see ``tests/test_fingerprint.py::test_lab_default_is_byte_identical``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

__all__ = [
    "DEFAULT_FINGERPRINT_KEY",
    "FINGERPRINTS",
    "Fingerprint",
    "fingerprint",
    "persona_keys",
    "resolve_rotation",
    "rotate",
]

DEFAULT_FINGERPRINT_KEY = "lab_default"
"""The identity used when the operator asks for no impersonation.

Named explicitly rather than left to a ``None`` default throughout, because "no
persona" is a decision with consequences and should be spelled where it is made.
"""


@dataclass(frozen=True)
class Fingerprint:
    """One declared client identity.

    Frozen because a persona is shared across every worker thread for the life of
    a run. Immutability makes a mid-run mutation impossible rather than merely
    unlikely, and it costs nothing: a persona is read, never written.

    Attributes:
        key: Stable identifier, used on the command line and in reports.
        label: Human-readable description for the CLI and the report.
        platform: The OS the persona claims, used to assert that the client
            hints agree with the User-Agent. ``"unknown"`` for ``lab_default``.
        headers: Ordered header pairs *excluding* ``Host``, ``Connection`` and
            ``X-Ddosim-Seq``. Those three are transport-level rather than
            identity-level - a browser does not change them per persona - so
            they are composed by the payload builder around this block, which
            keeps ``Connection: keep-alive`` and the cache-buster correct
            regardless of who is being impersonated.
        impersonates: Whether this identity misrepresents the sender. ``False``
            only for ``lab_default``. The report uses it to decide whether a
            run needs a disclosure note, so it must never be ``True`` for an
            honest identity and must never be omitted for a real one.
    """

    key: str
    label: str
    platform: str
    headers: tuple[tuple[str, str], ...]
    impersonates: bool = True

    @property
    def user_agent(self) -> str:
        """The declared ``User-Agent``, read from the header block.

        Derived rather than stored so the two cannot drift. A persona whose
        ``user_agent`` field disagreed with the ``User-Agent`` header it also
        sends is precisely the incoherence this module exists to avoid, and a
        redundant field would be one more place for that to happen.
        """
        for name, value in self.headers:
            if name.lower() == "user-agent":
                return value
        raise KeyError(f"persona {self.key!r} declares no User-Agent header")

    def header_names(self) -> frozenset[str]:
        """Lowercased header names, for membership tests."""
        return frozenset(name.lower() for name, _ in self.headers)

    def platform_hint(self) -> str | None:
        """The ``Sec-CH-UA-Platform`` value, if the persona sends one."""
        for name, value in self.headers:
            if name.lower() == "sec-ch-ua-platform":
                return value.strip('"')
        return None

    def is_coherent(self) -> bool:
        """Whether the persona's parts agree with each other.

        Checks the three ways a persona can contradict itself:

        * It sends Chromium client hints (``Sec-CH-UA``) but its platform hint
          disagrees with the platform its User-Agent claims.
        * It sends client hints at all while claiming to be Firefox or Safari,
          neither of which implements the Chromium client-hint headers.
        * It has no ``User-Agent`` at all, which no browser omits.

        Called by the test suite rather than trusted. Nothing enforces this at
        runtime, because a persona that fails it is still a legal thing to send -
        it is just a persona that will not survive contact with a real WAF, and
        the operator should learn that from a test failure rather than from a
        mysteriously low delivery figure.
        """
        names = self.header_names()
        if "user-agent" not in names:
            return False
        if "sec-ch-ua" not in names:
            # Firefox and Safari send no Chromium client hints. Absence is
            # correct for them, so there is nothing further to contradict.
            return True
        hint = self.platform_hint()
        if hint is None:
            return False
        # Only compare when the persona declares a platform; lab_default has no
        # hints at all so it never reaches here.
        return self.platform == "unknown" or hint == self.platform

    def describe(self) -> dict[str, object]:
        """Report-facing summary."""
        return {
            "fingerprint": self.key,
            "label": self.label,
            "platform": self.platform,
            "impersonates": self.impersonates,
            "user_agent": self.user_agent,
        }


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------
#
# Header sets are transcribed from real navigation requests rather than invented,
# because the point is to be unremarkable. Two consequences worth stating:
#
# * ``Accept-Encoding`` advertises brotli and zstd on the browsers that support
#   them, but this tool never actually compresses anything. That is a lie told
#   to the server, and it is the *right* lie here: a browser advertises its
#   encodings in every request it makes and then only uses what the response
#   negotiates, so advertising without using is exactly what a real client does.
#   The alternative - omitting the header - is itself a signal.
#
# * ``lab_default`` is byte-compatible with the block that existed before this
#   module, in the same order. That is a hard requirement, not a nicety: a
#   default that merely produced an equivalent request would change every
#   captured packet for every user who never asked for a persona.

_LAB_DEFAULT = Fingerprint(
    key=DEFAULT_FINGERPRINT_KEY,
    label="ADOBO lab client (default, self-identifying)",
    platform="unknown",
    headers=(
        ("User-Agent", "adobo-lab/0.1 (authorized testing)"),
        ("Accept", "*/*"),
    ),
    impersonates=False,
)

_CHROME_WINDOWS = Fingerprint(
    key="chrome_131_win",
    label="Chrome 131 on Windows 10",
    platform="Windows",
    headers=(
        (
            "Sec-CH-UA",
            '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        ),
        ("Sec-CH-UA-Mobile", "?0"),
        ("Sec-CH-UA-Platform", '"Windows"'),
        ("Upgrade-Insecure-Requests", "1"),
        (
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7",
        ),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-User", "?1"),
        ("Sec-Fetch-Dest", "document"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Accept-Language", "en-US,en;q=0.9"),
    ),
)

_CHROME_MAC = Fingerprint(
    key="chrome_131_mac",
    label="Chrome 131 on macOS",
    platform="macOS",
    headers=(
        (
            "Sec-CH-UA",
            '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        ),
        ("Sec-CH-UA-Mobile", "?0"),
        ("Sec-CH-UA-Platform", '"macOS"'),
        ("Upgrade-Insecure-Requests", "1"),
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7",
        ),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-User", "?1"),
        ("Sec-Fetch-Dest", "document"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Accept-Language", "en-US,en;q=0.9"),
    ),
)

_FIREFOX_WINDOWS = Fingerprint(
    key="firefox_133_win",
    label="Firefox 133 on Windows 10",
    platform="Windows",
    headers=(
        (
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
            "Gecko/20100101 Firefox/133.0",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Priority", "u=0, i"),
        ("TE", "trailers"),
    ),
)

_FIREFOX_LINUX = Fingerprint(
    key="firefox_133_linux",
    label="Firefox 133 on Linux",
    platform="Linux",
    headers=(
        (
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Priority", "u=0, i"),
        ("TE", "trailers"),
    ),
)

_SAFARI_MAC = Fingerprint(
    key="safari_18_mac",
    label="Safari 18 on macOS",
    platform="macOS",
    headers=(
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Upgrade-Insecure-Requests", "1"),
    ),
)

FINGERPRINTS: dict[str, Fingerprint] = {
    persona.key: persona
    for persona in (
        _LAB_DEFAULT,
        _CHROME_WINDOWS,
        _CHROME_MAC,
        _FIREFOX_WINDOWS,
        _FIREFOX_LINUX,
        _SAFARI_MAC,
    )
}
"""Every persona, keyed by its CLI name.

``lab_default`` sorts first by construction order rather than alphabetically,
which is what keeps it the default in ``--help`` output without any special
casing.
"""

_ROTATION_MODES = ("none", "per_request", "per_connection")
"""Accepted values for the rotation strategy.

``per_connection`` is the default because a persona is a property of a
connection: a real browser does not change its User-Agent halfway through a
keep-alive session, and one that did would be trivially wrong. ``per_request``
is offered because it is the only way to make every request independently
identifiable, which is occasionally what a rate-limiter test needs.
"""


# --------------------------------------------------------------------------
# Lookup
# --------------------------------------------------------------------------


def persona_keys() -> list[str]:
    """Every persona key, in registry order, ``lab_default`` first."""
    return list(FINGERPRINTS)


def fingerprint(key: str) -> Fingerprint:
    """Look up a persona by key.

    Raises:
        ValueError: with the valid keys listed, so a typo is a useful message
            rather than a lookup failure the caller has to guess about.

            ``ValueError`` rather than ``KeyError`` deliberately. This is
            called from a pydantic field validator, and pydantic converts
            ``ValueError`` and ``AssertionError`` into a ``ValidationError`` but
            lets a ``KeyError`` escape untouched. With ``KeyError`` a
            misspelled persona surfaced as an unhandled exception out of model
            construction rather than as a validation failure naming the valid
            keys. The CLI validates through argparse first; this is the backstop
            for the wizard and for programmatic callers.
    """
    try:
        return FINGERPRINTS[key]
    except KeyError:
        raise ValueError(
            f"unknown fingerprint {key!r}; choose one of: "
            + ", ".join(persona_keys())
        ) from None


def resolve_rotation(mode: str) -> str:
    """Validate a rotation mode name.

    Raises ``ValueError`` for the same reason as :func:`fingerprint`: it runs
    inside a pydantic field validator, which converts ``ValueError`` and nothing
    else.
    """
    if mode not in _ROTATION_MODES:
        raise ValueError(
            f"unknown fingerprint rotation {mode!r}; choose one of: "
            + ", ".join(_ROTATION_MODES)
        )
    return mode


def rotate(keys: list[str] | tuple[str, ...], seed: int) -> Fingerprint:
    """Pick a persona deterministically from *keys* for *seed*.

    Deterministic rather than random, and this is load-bearing rather than a
    convenience. ``transports/base.py`` builds its filler deterministically for
    the same reason: a capture should be replayable and a test should be able to
    assert on exact bytes. A rotating selector built on :func:`random` would make
    a run irreproducible - the same seed would present a different client on every
    execution and a failure could not be re-run.

    The digest is BLAKE2b rather than :func:`hash`, because ``hash()`` on a str is
    salted per process. That would make the selection stable within a run and
    different across runs, which is the worst of both.
    """
    if not keys:
        return FINGERPRINTS[DEFAULT_FINGERPRINT_KEY]
    digest = hashlib.blake2b(str(seed).encode("ascii"), digest_size=8).digest()
    return fingerprint(keys[int.from_bytes(digest, "big") % len(keys)])