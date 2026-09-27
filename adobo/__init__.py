"""Network Stress Testing and DDoS Resilience Simulator.

An authorized-lab tool for generating controlled volumetric traffic against a
locally hosted target, and measuring how well that target's mitigations hold
up. It is deliberately loopback-by-default and cannot target an address that
is not written into an allowlist.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
