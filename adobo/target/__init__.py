"""The lab target: a deliberately fragile local service you can harden.

See :mod:`adobo.target.app`.
"""

from .app import TargetSettings, create_app, run_target

__all__ = ["TargetSettings", "create_app", "run_target"]
