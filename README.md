# cidr-wildcard-pattern-matcher-kit

Match IPv4 addresses against legacy glob-style wildcard patterns and CIDR
blocks. The library exports one class and one exception:

```python
from cidr_wildcard_pattern_matcher_kit import CIDRWildcardMatcher, PatternError

matcher = CIDRWildcardMatcher(["192.168.*.*", "10.0.0.0/8"])
assert matcher.matches("192.168.1.5")
assert matcher.matches("10.1.2.3")
assert not matcher.matches("172.16.0.1")

try:
    CIDRWildcardMatcher(["192.168.1.999"])
except PatternError as exc:
    print(exc)
```

The public names are exactly `CIDRWildcardMatcher` and `PatternError`.
`CIDRWildcardMatcher(patterns)` compiles an iterable of pattern strings;
`.matches(address)` returns a boolean. `PatternError` is a subclass of
`ValueError` and is raised while compiling malformed patterns. An invalid
address passed to `.matches()` raises plain `ValueError`.

## Why this exists

Firewall and ACL exports often contain wildcard address groups such as
`192.168.*.*` alongside CIDR blocks such as `10.0.0.0/8`. Checking them by
hand is error-prone, and pulling in a full networking library for a few string
comparisons is heavy. This kit parses both forms once and then matches with a
few byte comparisons.

The trade-off is scope: we support exactly two pattern shapes and nothing
else. Wildcards must be whole octets (`*` or a number 0-255), and a CIDR block
must use a literal dotted-quad address. Patterns that mix the two, such as
`192.168.*.0/24`, are rejected rather than guessed at. That keeps the meaning
of every accepted pattern unambiguous.

## The awkward edge

Wildcard octets must be whole octets. `192.168.1.*` is fine, but
`192.168.1.10-20` is not a supported pattern and raises `PatternError`.
Leading zeros are rejected too, so `192.168.001.1` is an error rather than
being read as `192.168.1.1`.
