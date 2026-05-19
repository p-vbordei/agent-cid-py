"""RFC 8785 JCS canonical encoding."""

from __future__ import annotations

from typing import Any

import jcs as _jcs


def canonical_encode(value: Any) -> bytes:
    return _jcs.canonicalize(value)
