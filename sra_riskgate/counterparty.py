"""Counterparty policy: who is on the other side of the payment.

Two caller-supplied address lists, both matched exactly after normalising (trim, lowercase):

* ``blocked_addresses``: a payment from or to any of these is a REJECT (``BLOCKLISTED_ADDRESS``).
* ``known_recipients``: the payees you have paid before or verified. When this list is given, a
  payment to any other address is a HOLD (``NEW_COUNTERPARTY``): the first payment to a new payee
  should be confirmed through a channel you control. This is the standard control against vendor
  impersonation and payment-redirection fraud ("our bank details have changed").

A recipient that is NOT on ``known_recipients`` but looks like one of them (the same first and last hex
characters, the part a wallet shows) is a REJECT (``LOOKALIKE_RECIPIENT``): that is address poisoning, where an
attacker sends a tiny transfer from a look-alike address so it appears in the wallet's history, and waits for the
next payment to be copied from there. A look-alike shares at least 7 hex characters with a known payee, at
least 3 at each end; a random address does that about once in 140 million tries per known payee, so a match is
not chance.

``None`` means "not configured" and turns a check off. An empty ``known_recipients`` list is
different: it means no payee is known yet, so every payment is held.

The lists come only from your own configuration. Nothing in the payment request, memo or
``untrusted_request`` can add an address to ``known_recipients``.
"""
from __future__ import annotations

from typing import Iterable, Optional

from sra_riskgate.sanctions import _normalise

BLOCKLIST_FLAG = "BLOCKLISTED_ADDRESS"
NEW_COUNTERPARTY_FLAG = "NEW_COUNTERPARTY"
LOOKALIKE_FLAG = "LOOKALIKE_RECIPIENT"

# A look-alike shares at least this many hex characters at the start and at the end, and this many in total.
LOOKALIKE_MIN_EACH_END = 3
LOOKALIKE_MIN_TOTAL = 7


def parse_address_list(name: str, value: Optional[Iterable[str]]) -> Optional[frozenset]:
    """Normalise a list of EVM addresses. ``None`` stays ``None``.

    Raises ValueError on a bare string (a common mistake that would otherwise be read one
    character at a time) or on any entry that is not a 0x-prefixed 40-hex address, so a typo in a
    policy list can never silently weaken it.
    """
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or isinstance(value, dict) or not isinstance(value, Iterable):
        raise ValueError(f"{name} must be a list of addresses or None, got {type(value).__name__}.")
    parsed = set()
    for entry in value:
        n = _normalise(entry)
        if n is None:
            raise ValueError(f"{name} contains an entry that is not an EVM address: {entry!r}.")
        parsed.add(n)
    return frozenset(parsed)


def merge(a: Optional[frozenset], b: Optional[frozenset]) -> Optional[frozenset]:
    """Union of two parsed lists, where ``None`` means not configured."""
    if a is None:
        return b
    if b is None:
        return a
    return a | b


def _shared(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def find_lookalike(recipient: object, known: Optional[frozenset]) -> Optional[tuple]:
    """The known payee that ``recipient`` imitates, as (address, shared prefix, shared suffix), or None.

    Only a recipient that is not itself known can be a look-alike. Addresses are compared without the 0x,
    case-insensitively. Of several matches, the closest (most shared characters) is returned.
    """
    r = _normalise(recipient)
    if r is None or not known or r in known:
        return None
    rh = r[2:]
    best = None
    for k in known:
        kh = k[2:]
        prefix, suffix = _shared(rh, kh), _shared(rh[::-1], kh[::-1])
        if prefix >= LOOKALIKE_MIN_EACH_END and suffix >= LOOKALIKE_MIN_EACH_END and prefix + suffix >= LOOKALIKE_MIN_TOTAL:
            if best is None or prefix + suffix > best[1] + best[2]:
                best = (k, prefix, suffix)
    return best
