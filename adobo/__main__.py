"""Entry point for ``python -m ddosim`` and for the frozen executable.

PyInstaller runs its entry script as ``__main__`` with no package context, so the
relative import that works under ``python -m ddosim`` fails there. Importing the
absolute package name works in both cases, and ``__package__`` is set so the
frozen build resolves the same module object rather than a second copy.
"""

import multiprocessing as mp

from ddosim.cli import main

if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
