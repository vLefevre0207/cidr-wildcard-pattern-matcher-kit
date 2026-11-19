"""Match IPv4 addresses against glob-style wildcard patterns.

Legacy firewall and ACL configurations commonly express address groups as
patterns like ``192.168.*.*`` or ``10.0.0.0/8``. This module implements one
clear interpretation of those patterns:

* A pattern is a dot-separated sequence of four octets.
* Each octet is either ``*`` (matches any octet 0-255) or a decimal number
  0-255 with no leading zeros.
* A pattern may instead be a CIDR block ``a.b.c.d/prefix`` with prefix
  0-32. The address part must be a literal dotted quad; CIDR and wildcards
  are not mixed.

Decision: wildcard patterns always match the full 32-bit address. We do not
support partial-octet wildcards such as ``192.168.1.*`` being written as
``192.168.1.10-20``; that is a different feature and mixing it in would make
the matcher ambiguous.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Union


class PatternError(ValueError):
    """Raised when a pattern string is not a valid wildcard or CIDR block."""


class CIDRWildcardMatcher:
    """Compile and match IPv4 addresses against wildcard and CIDR patterns.

    The matcher is deliberately tiny and dependency-free. It stores patterns
    as a list of octet masks so matching is a constant-time comparison per
    pattern after parsing.

    Example::

        m = CIDRWildcardMatcher(["192.168.*.*", "10.0.0.0/8"])
        assert m.matches("192.168.1.5")
        assert m.matches("10.1.2.3")
        assert not m.matches("172.16.0.1")
    """

    def __init__(self, patterns: Iterable[str]):
        """Compile *patterns* into an internal form.

        :param patterns: iterable of wildcard or CIDR pattern strings.
        :raises PatternError: if any pattern is malformed.
        """
        self._patterns: list[Union[tuple[list[int], list[bool]], tuple[bytes, int]]] = []
        for raw in patterns:
            self._patterns.append(self._compile(raw))

    @staticmethod
    def _compile(pattern: str) -> Union[tuple[list[int], list[bool]], tuple[bytes, int]]:
        """Turn one pattern string into a matchable structure.

        Wildcards become ``(octets, wildcard_flags)`` where ``octets`` holds
        the literal value for fixed positions and 0 for wildcard positions.
        CIDR blocks become ``(network_bytes, prefix_len)``.
        """
        if not isinstance(pattern, str):
            raise PatternError("pattern must be a string")
        pattern = pattern.strip()
        if not pattern:
            raise PatternError("empty pattern")

        if "/" in pattern:
            return CIDRWildcardMatcher._compile_cidr(pattern)
        return CIDRWildcardMatcher._compile_wildcard(pattern)

    @staticmethod
    def _compile_cidr(pattern: str) -> tuple[bytes, int]:
        """Parse ``a.b.c.d/prefix`` into packed bytes and a prefix length."""
        if pattern.count("/") != 1:
            raise PatternError(f"invalid CIDR pattern: {pattern!r}")
        addr_part, prefix_part = pattern.split("/", 1)
        if not prefix_part.isdigit():
            raise PatternError(f"invalid CIDR prefix: {pattern!r}")
        prefix = int(prefix_part)
        if prefix < 0 or prefix > 32:
            raise PatternError(f"CIDR prefix out of range: {pattern!r}")
        try:
            addr = ipaddress.IPv4Address(addr_part)
        except ipaddress.AddressValueError as exc:
            raise PatternError(f"invalid CIDR address: {pattern!r}") from exc
        return addr.packed, prefix

    @staticmethod
    def _compile_wildcard(pattern: str) -> tuple[list[int], list[bool]]:
        """Parse ``a.b.c.d`` where each octet is a number or ``*``."""
        parts = pattern.split(".")
        if len(parts) != 4:
            raise PatternError(f"wildcard pattern must have 4 octets: {pattern!r}")
        octets: list[int] = []
        wildcards: list[bool] = []
        for part in parts:
            if part == "*":
                octets.append(0)
                wildcards.append(True)
                continue
            if not part.isdigit():
                raise PatternError(f"invalid octet in pattern: {pattern!r}")
            # Reject leading zeros so "010" is not silently read as 10.
            if len(part) > 1 and part[0] == "0":
                raise PatternError(f"leading zero in octet: {pattern!r}")
            value = int(part)
            if value > 255:
                raise PatternError(f"octet out of range: {pattern!r}")
            octets.append(value)
            wildcards.append(False)
        return octets, wildcards

    def matches(self, address: str) -> bool:
        """Return True if *address* matches any compiled pattern.

        :param address: dotted-quad IPv4 string.
        :raises ValueError: if *address* is not a valid IPv4 address.
        """
        try:
            packed = ipaddress.IPv4Address(address).packed
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"invalid IPv4 address: {address!r}") from exc
        return self._matches_packed(packed)

    def _matches_packed(self, packed: bytes) -> bool:
        for entry in self._patterns:
            if isinstance(entry[0], bytes):
                network, prefix = entry  # type: ignore[misc]
                if self._cidr_matches(packed, network, prefix):
                    return True
            else:
                octets, wildcards = entry  # type: ignore[misc]
                if self._wildcard_matches(packed, octets, wildcards):
                    return True
        return False

    @staticmethod
    def _cidr_matches(packed: bytes, network: bytes, prefix: int) -> bool:
        """Compare the first *prefix* bits of two packed addresses."""
        full_bytes, remainder = divmod(prefix, 8)
        if packed[:full_bytes] != network[:full_bytes]:
            return False
        if remainder == 0:
            return True
        mask = (0xFF << (8 - remainder)) & 0xFF
        return (packed[full_bytes] & mask) == (network[full_bytes] & mask)

    @staticmethod
    def _wildcard_matches(packed: bytes, octets: list[int], wildcards: list[bool]) -> bool:
        """Compare each octet, skipping wildcard positions."""
        for i, (value, is_wild) in enumerate(zip(octets, wildcards)):
            if is_wild:
                continue
            if packed[i] != value:
                return False
        return True

    def __len__(self) -> int:
        """Number of compiled patterns."""
        return len(self._patterns)

    def __repr__(self) -> str:
        return f"CIDRWildcardMatcher({len(self._patterns)} patterns)"
