from __future__ import annotations

import re

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_timespan(text: str | int | float) -> float:
    """Parse Sigma-style timespans such as ``30s``, ``5m``, ``1h``, ``1d``."""
    if isinstance(text, (int, float)):
        return float(text)
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", str(text))
    if not m:
        raise ValueError(f"invalid timespan {text!r} (use e.g. 30s, 5m, 1h, 1d)")
    return int(m.group(1)) * _UNITS[m.group(2)]
