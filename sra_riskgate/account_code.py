"""Is the agent's own account still its own? Read from its on-chain code (EIP-7702 delegation designator).

Once an EOA has been delegated under EIP-7702, ``eth_getCode`` on it returns ``0xef0100`` followed by the
20-byte address of the delegate contract, and that contract can move everything the account holds. An
authorization signed outside the agent's guarded client (another app, a phished signature, a leaked key) leaves
exactly this trace. So before each payment, read the account's code and pass it in as ``account_code``: if the
account is delegated to a contract you did not expect, every payment is held (``ACCOUNT_DELEGATED``).

The checks stay offline: sra-riskgate never calls an RPC itself. Read the code with your own client, for example
``w3.eth.get_code(address)`` (web3.py) or ``client.getCode({address})`` (viem), and pass the result.
Suggested by Carlos (Bloqarl) on DEV.to.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from sra_riskgate.counterparty import parse_address_list
from sra_riskgate.models import ActionDecision, RiskAssessment

DELEGATION_DESIGNATOR = "ef0100"
DELEGATED_FLAG = "ACCOUNT_DELEGATED"
_HEX = re.compile(r"^(0x)?([0-9a-f]*)$")


def _code_hex(code: Any) -> Optional[str]:
    """The code as lowercase hex without 0x, or None if it is not hex. Accepts str, bytes and HexBytes."""
    if isinstance(code, (bytes, bytearray)):
        return bytes(code).hex()
    hexer = getattr(code, "hex", None)
    if not isinstance(code, str) and callable(hexer):  # HexBytes and similar
        code = hexer()
    if not isinstance(code, str):
        return None
    m = _HEX.match(code.strip().lower())
    if m is None or len(m.group(2)) % 2:
        return None
    return m.group(2)


def delegate_from_code(code: Any) -> Optional[str]:
    """The delegate address if ``code`` is an EIP-7702 delegation designator (0xef0100 + address), else None."""
    h = _code_hex(code)
    if h is None or len(h) != 46 or not h.startswith(DELEGATION_DESIGNATOR):
        return None
    return "0x" + h[6:]


def check_account_code(code: Any, *, expected_delegates: Optional[Iterable[str]] = None) -> Optional[RiskAssessment]:
    """A HOLD if the account's code shows an unexpected EIP-7702 delegation (or cannot be read), else None.

    ``code`` is the ``eth_getCode`` result for the agent's own account. Empty code (a plain EOA) and ordinary
    contract code (a smart-contract wallet) are fine. A delegation designator is fine only if its delegate is in
    ``expected_delegates`` (for example the smart-account implementation your wallet provider uses on purpose).
    """
    h = _code_hex(code)
    if h is None:
        return RiskAssessment(decision=ActionDecision.HOLD, risk_score=0.65, flags=["INVALID_ACCOUNT_CODE"],
                              explanation=f"The account code passed in is not hex ({str(code)[:40]!r}), so it "
                                          f"cannot be checked; the payment is held.",
                              required_actions=["manual_review"])
    delegate = delegate_from_code(code)
    if delegate is None:
        return None
    expected = parse_address_list("expected_delegates", expected_delegates) or frozenset()
    if delegate in expected:
        return None
    return RiskAssessment(
        decision=ActionDecision.HOLD, risk_score=0.95, flags=[DELEGATED_FLAG],
        explanation=(f"The paying account is delegated under EIP-7702 to {delegate} (its code is 0xef0100 followed "
                     f"by that address), which is not one of your expected_delegates. That contract can move "
                     f"everything the account holds, so the account may no longer be yours alone. Stop all payments "
                     f"and signatures from it until a person has checked."),
        required_actions=["manual_review", "stop_signing"])
