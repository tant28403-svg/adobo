"""Minimal 4-prompt wizard for UDP stress testing."""

from __future__ import annotations

from .models import AttackProfile, ProfileName, RunConfig, Target, TransportKind

__all__ = ["wizard"]


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            answer = input(f"{prompt}{suffix}: ").strip()
        except EOFError:
            return default or ""
        if answer:
            return answer
        if default is not None:
            return default
        print("  a value is required")


def _ask_int(prompt: str, default: int) -> int:
    while True:
        raw = _ask(prompt, str(default))
        try:
            return int(raw)
        except ValueError:
            print(f"  {raw!r} is not a whole number")


def _ask_float(prompt: str, default: float) -> float:
    while True:
        raw = _ask(prompt, str(default))
        try:
            return float(raw)
        except ValueError:
            print(f"  {raw!r} is not a number")


def wizard() -> RunConfig:
    """Ask for target, port, PPS, duration. Return RunConfig."""
    print("\n=== UDP Stress Test ===")
    host = _ask("Target IP")
    port = _ask_int("Port", 80)
    pps = _ask_int("PPS", 5000)
    duration = _ask_float("Duration (s)", 10.0)

    return RunConfig(
        target=Target(host=host, port=port),
        attack=AttackProfile(
            profile=ProfileName.UDP_FLOOD,
            pps=pps,
            duration_seconds=duration,
            payload_size=512,
            workers=4,
        ),
        transport=TransportKind.SOCKET,
        defenses=[],
        label="simple run",
    )