"""Counterparty policy: who is on the other side of the payment.

Two caller-supplied address lists, both matched exactly after normalising (trim, lowercase):

* ``blocked_addresses``: a payment from or to any of these is a REJECT (``BLOCKLISTED_ADDRESS``).
* ``known_recipients``: the payees you have paid before or verified. When this list is given, a
  payment to any other address is a HOLD (``NEW_COUNTERPARTY``): the first payment to a new payee
  should be confirmed through a channel you control. This is the standard control against vendor
  impersonation and payment-redirection fraud ("our bank details have changed").

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
