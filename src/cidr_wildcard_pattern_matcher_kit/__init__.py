"""CIDR wildcard pattern matcher kit.

Exports the public API for matching IPv4 addresses against glob-style
wildcard patterns such as ``192.168.*.*``. See :mod:`core` for details.
"""

from .core import CIDRWildcardMatcher, PatternError

__all__ = ["CIDRWildcardMatcher", "PatternError"]
