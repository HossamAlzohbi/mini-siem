"""Log parsers. Each parser turns raw lines/files into normalised ``Event`` objects."""
from __future__ import annotations

from . import nginx, ssh, windows

PARSERS = {
    "nginx": nginx.parse_file,
    "ssh": ssh.parse_file,
    "windows": windows.parse_file,
}

__all__ = ["PARSERS", "nginx", "ssh", "windows"]
