"""Check the EIP-3009 authorization an agent is about to sign for an x402 payment.

In x402's ``exact`` scheme on EVM chains the agent never sends a transaction. It signs an EIP-712
``TransferWithAuthorization`` message, and whoever holds that signature can move the USDC until it
expires. ``check_transaction`` cannot see this path, so ``check_authorization`` checks the typed data
itself: that it is a USDC authorization on a supported chain, from the right wallet, valid only for a short
time, and then runs the decoded payment through ``check_payment`` with your policy. Fails closed.

Circle Gateway's batched x402 payments (nanopayments) are recognised too: the same
``TransferWithAuthorization``, signed for the ``GatewayWalletBatched`` domain with Circle's GatewayWallet
contract as ``verifyingContract``. It draws on the payer's Gateway balance, and Gateway requires it to stay
valid for at least three days, so it gets its own validity limit (``max_gateway_validity_seconds``).
"""
from __future__ import annotations

import json
import time
from decimal import Decimal
from typing import Any, Mapping, Optional

from sra_riskgate.chains import (GATEWAY_BATCHED_DOMAIN, GATEWAY_WALLET_ADDRESSES, USDC_ADDRESSES, USDC_DECIMALS,
                                 is_gateway_wallet, is_usdc)
from sra_riskgate.check import _verdict, check_payment
from sra_riskgate.models import ActionDecision, RiskAssessment
from sra_riskgate.transaction import _POLICY_KEYS, _UNLIMITED, _int, _same

_AUTH_FIELDS = [("from", "address"), ("to", "address"), ("value", "uint256"), ("validAfter", "uint256"),
                ("validBefore", "uint256"), ("nonce", "bytes32")]
_AUTH_TYPES = {"TransferWithAuthorization", "ReceiveWithAuthorization"}
DEFAULT_MAX_VALIDITY_SECONDS = 3600
# Gateway rejects batched authorizations valid for less than three days; its own examples use five.
GATEWAY_MIN_VALIDITY_SECONDS = 3 * 86400
DEFAULT_MAX_GATEWAY_VALIDITY_SECONDS = 7 * 86400
_CLOCK_SKEW_SECONDS = 60


def _hold(flags: list, why: str) -> RiskAssessment:
    return _verdict(ActionDecision.HOLD, flags, f"SRA-RiskGate cannot approve this authorization: {why}",
                    ["manual_review"])


def _fields(types: Any, name: str) -> Optional[list]:
    """The struct definition for ``name`` as (name, type) pairs, or None if it is malformed."""
    try:
        return [(f["name"], f["type"]) for f in types[name]]
    except Exception:
        return None


def _is_address(a: Any) -> bool:
    if not isinstance(a, str) or not a.startswith(("0x", "0X")) or len(a) != 42:
        return False
    try:
        int(a[2:], 16)
        return True
    except ValueError:
        return False


def _is_bytes32(n: Any) -> bool:
    if isinstance(n, (bytes, bytearray)):
        return len(n) == 32
    if not isinstance(n, str) or not n.startswith(("0x", "0X")) or len(n) != 66:
        return False
    try:
        int(n[2:], 16)
        return True
    except ValueError:
        return False


def check_authorization(
    typed_data: Any,
    *,
    sender: Optional[str] = None,
    chain_id: Optional[int] = None,
    now: Optional[float] = None,
    max_validity_seconds: float = DEFAULT_MAX_VALIDITY_SECONDS,
    max_gateway_validity_seconds: float = DEFAULT_MAX_GATEWAY_VALIDITY_SECONDS,
    **policy: Any,
) -> RiskAssessment:
    """Check EIP-712 typed data before the agent signs it. Never raises; anything unexpected becomes HOLD.

    ``typed_data`` is the full EIP-712 payload (``domain``, ``primaryType``, ``message``, and optionally
    ``types``) as a mapping or a JSON string, exactly as it would be passed to ``eth_signTypedData_v4``.
    ``sender`` and ``chain_id``, when given, must match the message's ``from`` and the domain's ``chainId``.
    ``now`` (Unix seconds) defaults to the current time.

    A ``TransferWithAuthorization`` (or ``ReceiveWithAuthorization``) for USDC is decoded and passed to
    ``check_payment`` with every keyword in ``policy`` (``known_recipients``, ``blocked_addresses``,
    ``max_amount``, ``untrusted_request``, ``peg_deviation_pct``, ...). Before that, it is HOLD with:

    * ``TOKEN_APPROVAL`` for an EIP-2612 ``Permit`` (plus ``UNLIMITED_APPROVAL`` for an effectively
      unlimited value): a signed permit lets another address spend the wallet's USDC later.
    * ``UNSUPPORTED_SIGNATURE`` for any other primary type.
    * ``UNSUPPORTED_CHAIN`` or ``UNSUPPORTED_ASSET`` when the domain is not USDC on a supported chain.
    * ``AUTHORIZATION_MISMATCH`` when ``from`` or ``chainId`` disagree with the arguments.
    * ``AUTHORIZATION_EXPIRED`` when ``validBefore`` has passed, ``AUTHORIZATION_NOT_YET_VALID`` when
      ``validAfter`` is in the future, and ``LONG_LIVED_AUTHORIZATION`` when it stays valid for more than
      ``max_validity_seconds`` (default one hour): a long-lived signature can be used long after the
      agent has moved on.
    * ``INVALID_AUTHORIZATION`` for missing or malformed fields, or a ``types`` definition that is not
      the USDC one.

    A Circle Gateway batched payment (domain name ``GatewayWalletBatched``, version ``"1"``, with the
    GatewayWallet contract for that chain as ``verifyingContract``) gets the same checks, except that its
    validity limit is ``max_gateway_validity_seconds`` (default seven days) instead of
    ``max_validity_seconds``. A Gateway-named domain with any other contract is ``UNSUPPORTED_ASSET``;
    version ``"2"`` (EURC and cirBTC) is ``UNSUPPORTED_ASSET``; any primary type other than
    ``TransferWithAuthorization`` is ``UNSUPPORTED_SIGNATURE``. A Gateway authorization valid for less
    than three days is ``GATEWAY_VALIDITY_TOO_SHORT``: Gateway would reject it, so it is held rather than
    signed for nothing.

    Only sign if ``result.decision`` is ``ActionDecision.APPROVE``.
    """
    unknown = sorted(set(policy) - _POLICY_KEYS)
    if unknown:
        return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                        f"The risk gate is misconfigured: unknown argument(s) {', '.join(unknown)}.",
                        ["fix_configuration"])
    try:
        if isinstance(typed_data, (str, bytes, bytearray)):
            try:
                typed_data = json.loads(typed_data)
            except ValueError:
                return _hold(["INVALID_AUTHORIZATION"], "the typed data is not valid JSON.")
        if not isinstance(typed_data, Mapping):
            return _hold(["INVALID_AUTHORIZATION"], "the typed data is not a mapping.")
        domain, message = typed_data.get("domain"), typed_data.get("message")
        primary, types = typed_data.get("primaryType"), typed_data.get("types")
        if not isinstance(domain, Mapping) or not isinstance(message, Mapping) or not isinstance(primary, str):
            return _hold(["INVALID_AUTHORIZATION"], "domain, message and primaryType are required.")

        raw_chain = domain.get("chainId")
        try:
            if raw_chain is None or isinstance(raw_chain, bool):
                raise ValueError
            dom_chain = _int(raw_chain)
        except (TypeError, ValueError):
            return _hold(["INVALID_AUTHORIZATION"], f"domain chainId {raw_chain!r} is not a number.")
        if chain_id is not None and chain_id != dom_chain:
            return _hold(["AUTHORIZATION_MISMATCH"], f"it is for chain {dom_chain}, not {chain_id}.")
        if dom_chain not in USDC_ADDRESSES:
            return _hold(["UNSUPPORTED_CHAIN"], f"chain {dom_chain} is not checked.")
        contract = domain.get("verifyingContract")
        gateway = domain.get("name") == GATEWAY_BATCHED_DOMAIN
        if gateway:
            if not is_gateway_wallet(dom_chain, contract):
                return _hold(["UNSUPPORTED_ASSET"],
                             f"it names Circle Gateway's {GATEWAY_BATCHED_DOMAIN} domain but is for contract "
                             f"{contract}, not Circle's GatewayWallet on chain {dom_chain} "
                             f"({GATEWAY_WALLET_ADDRESSES[dom_chain]}).")
            if str(domain.get("version")) != "1" or domain.get("salt") is not None:
                return _hold(["UNSUPPORTED_ASSET"],
                             f"only USDC Gateway payments (domain version \"1\", no salt) are checked; this is "
                             f"version {domain.get('version')!r}, which Gateway uses for EURC and cirBTC.")
            if primary != "TransferWithAuthorization":
                return _hold(["UNSUPPORTED_SIGNATURE"],
                             f"only TransferWithAuthorization is checked on the Gateway domain; this is {primary}.")
        elif not is_usdc(dom_chain, contract):
            return _hold(["UNSUPPORTED_ASSET"],
                         f"it is for contract {contract}, which is not the USDC contract on chain {dom_chain} "
                         f"({USDC_ADDRESSES[dom_chain]}).")

        if primary == "Permit":
            flags = ["TOKEN_APPROVAL"]
            why = "it is an EIP-2612 permit, which lets another address spend this wallet's USDC later."
            try:
                if _int(message.get("value")) >= _UNLIMITED:
                    flags.append("UNLIMITED_APPROVAL")
                    why += " The value is effectively unlimited."
            except (TypeError, ValueError):
                pass
            if message.get("spender"):
                why += f" Spender: {message.get('spender')}."
            return _hold(flags, why)
        if primary not in _AUTH_TYPES:
            return _hold(["UNSUPPORTED_SIGNATURE"],
                         f"only USDC TransferWithAuthorization is checked; this is {primary}.")
        if types is not None and _fields(types, primary) != _AUTH_FIELDS:
            return _hold(["INVALID_AUTHORIZATION"],
                         f"the {primary} type definition is not the USDC (EIP-3009) one.")

        frm, to, nonce = message.get("from"), message.get("to"), message.get("nonce")
        if not _is_address(frm) or not _is_address(to):
            return _hold(["INVALID_AUTHORIZATION"], "from and to must be 20-byte hex addresses.")
        if not _is_bytes32(nonce):
            return _hold(["INVALID_AUTHORIZATION"], "nonce must be 32 bytes of hex.")
        if sender is not None and not _same(sender, frm):
            return _hold(["AUTHORIZATION_MISMATCH"], f"it is from {frm}, not {sender}.")
        if any(message.get(k) is None for k in ("value", "validAfter", "validBefore")):
            return _hold(["INVALID_AUTHORIZATION"], "value, validAfter and validBefore are required.")
        try:
            value = _int(message.get("value"))
            valid_after = _int(message.get("validAfter"))
            valid_before = _int(message.get("validBefore"))
        except (TypeError, ValueError):
            return _hold(["INVALID_AUTHORIZATION"], "value, validAfter and validBefore must be integers.")
        if min(value, valid_after, valid_before) < 0 or max(value, valid_after, valid_before) >= 2**256:
            return _hold(["INVALID_AUTHORIZATION"], "value, validAfter and validBefore must be uint256.")

        t = time.time() if now is None else float(now)
        if valid_before <= t:
            return _hold(["AUTHORIZATION_EXPIRED"], f"validBefore {valid_before} has already passed.")
        if valid_after > t + _CLOCK_SKEW_SECONDS:
            return _hold(["AUTHORIZATION_NOT_YET_VALID"],
                         f"validAfter {valid_after} is in the future, so this is a post-dated payment.")
        lifetime = valid_before - max(t, valid_after)
        limit = max_gateway_validity_seconds if gateway else max_validity_seconds
        if lifetime > limit:
            return _hold(["LONG_LIVED_AUTHORIZATION"],
                         f"it stays valid for {lifetime / 3600:.1f} hours, more than the "
                         f"{limit / 3600:g}-hour limit{' for Circle Gateway payments' if gateway else ''}; "
                         f"anyone holding the signature can submit it until then.")
        if gateway and valid_before - t < GATEWAY_MIN_VALIDITY_SECONDS:
            return _hold(["GATEWAY_VALIDITY_TOO_SHORT"],
                         f"Circle Gateway requires a batched authorization to stay valid for at least three "
                         f"days, and this one expires in {(valid_before - t) / 3600:.1f} hours, so Gateway "
                         f"would reject it.")

        amount = float(Decimal(value) / (Decimal(10) ** USDC_DECIMALS))
        return check_payment(chain_id=dom_chain, sender=frm, recipient=to, amount=amount, **policy)
    except Exception as e:  # fail closed: no error path may approve
        return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                        f"The authorization check failed ({type(e).__name__}), so it is held.", ["manual_review"])
