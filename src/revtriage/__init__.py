"""revtriage — offline triage of a suspicious file.

The package is import-safe: nothing here touches the network, spawns a process or
executes the sample. Analysis is pure parsing and pattern matching over bytes.
"""

__version__ = "0.1.0"

TOOL_NAME = "revtriage"
PROJECT_URL = "https://github.com/earbona23/revtriage"

__all__ = ["__version__", "TOOL_NAME", "PROJECT_URL"]
