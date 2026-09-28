"""Run the lab target: ``python -m adobo.target``.

This exists because the target was the one part of the tool with no way to
start. Everything it measured - ``/stats`` request counts, ``/healthz``
response times, the difference a defense makes - was unreachable without an
entry point, and a measurement you cannot take is not evidence for anything.

Two forms are accepted for convenience, because the flag and the subcommand
disagree about which is which:

    python -m adobo.target                       # loopback, no defenses
    python -m adobo.target --defenses all        # everything enabled
    python -m adobo.target --defenses rate_limit,waf

``adobo --serve-target`` reaches the same runner and is wired to the same
argument parser, so the two cannot drift.
"""

from __future__ import annotations

import argparse
from typing import Sequence

from ..models import DefenseName
from .app import TargetSettings, run_target

__all__ = ["build_parser", "settings_from_args", "main", "ALL_DEFENSES"]

ALL_DEFENSES: tuple[DefenseName, ...] = (
    DefenseName.RATE_LIMIT,
    DefenseName.CONNECTION_CAP,
    DefenseName.WAF,
    DefenseName.CIRCUIT_BREAKER,
    DefenseName.CHALLENGE_PAGE,
)

DEFENSE_CHOICES: tuple[str, ...] = ("none", "all") + tuple(
    d.value for d in ALL_DEFENSES
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adobo-target",
        description="Serve the lab target: a deliberately fragile service you can harden.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "interface to bind (default: 127.0.0.1). Loopback by default because "
            "serving an intentionally fragile service on a routable interface is "
            "the situation the allowlist exists to prevent"
        ),
    )
    parser.add_argument("--port", type=int, default=8000, help="port to bind (default: 8000)")
    parser.add_argument(
        "--defenses",
        default="none",
        help=(
            "comma-separated mitigations to enable, or 'all' / 'none' "
            f"(default: none). One of: {', '.join(DEFENSE_CHOICES)}"
        ),
    )
    parser.add_argument(
        "--work-ms",
        type=int,
        default=None,
        help="simulated database work per /api/data request, in ms",
    )
    parser.add_argument("--log-level", default="warning", help="uvicorn log level (default: warning)")
    return parser


def parse_defenses(raw: str) -> list[DefenseName]:
    """Turn a ``--defenses`` string into a defense list.

    Accepts ``all``, ``none``, and comma-separated names, because the ordering a
    user reaches for is "all" when they want to see the hardened case and a list
    when they want to isolate one mitigation. Unrecognised names raise rather
    than being ignored: silently starting a baseline target when the operator
    asked for defenses would produce a run that looks like the defenses failed.
    """
    text = raw.strip().lower()
    if text in ("", "none"):
        return []
    if text == "all":
        return list(ALL_DEFENSES)

    chosen: list[DefenseName] = []
    for part in text.split(","):
        name = part.strip()
        if not name:
            continue
        try:
            chosen.append(DefenseName(name))
        except ValueError:
            valid = ", ".join(DEFENSE_CHOICES)
            raise SystemExit(f"unknown defense {name!r}. One of: {valid}") from None
        if chosen[-1] is DefenseName.NONE:
            return []
    return chosen


def settings_from_args(args: argparse.Namespace) -> TargetSettings:
    """Build :class:`TargetSettings` from parsed arguments.

    ``--work-ms`` is only forwarded when given, because ``None`` is not a value
    the constructor accepts and passing it through would overwrite the tuned
    default with something the endpoint cannot use.
    """
    kwargs: dict[str, object] = {
        "defenses": parse_defenses(args.defenses),
        "host": args.host,
        "port": args.port,
    }
    if args.work_ms is not None:
        kwargs["work_ms"] = args.work_ms
    return TargetSettings(**kwargs)  # type: ignore[arg-type]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = settings_from_args(args)

    print(f"adobo lab target on http://{settings.host}:{settings.port}")
    print(f"  defenses: {', '.join(settings.active()) or 'none (baseline)'}")
    print(f"  work_ms:  {settings.work_ms}")
    print("  read /stats for the target's own request count")
    print("  Ctrl-C to stop")

    try:
        run_target(settings, log_level=args.log_level)
    except KeyboardInterrupt:
        print("\nstopped")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
