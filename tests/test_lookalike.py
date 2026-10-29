"""0.15.0: address poisoning. A recipient that imitates a known payee is rejected (LOOKALIKE_RECIPIENT)."""
import pytest

from sra_riskgate import ActionDecision, check_authorization, check_payment, check_transaction
from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.counterparty import find_lookalike, parse_address_list

ME = "0x" + "a" * 40
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"


def poison(prefix: int, suffix: int, real: str = PAYEE) -> str:
    """An address sharing exactly `prefix` leading and `suffix` trailing hex characters with `real`."""
    h = real[2:]
    middle = "".join("0" if c != "0" else "1" for c in h[prefix:40 - suffix])
    # make sure the characters just inside each end differ, so the shared lengths are exact
    return "0x" + h[:prefix] + middle + h[40 - suffix:]


def pay(recipient, **kw):
    kw.setdefault("known_recipients", [PAYEE])
    return check_payment(chain_id=8453, sender=ME, recipient=recipient, amount=20.0, peg_deviation_pct=0.1, **kw)


@pytest.mark.parametrize("prefix,suffix", [(4, 4), (6, 4), (4, 6), (3, 4), (4, 3), (10, 10)])
def test_lookalikes_are_rejected(prefix, suffix):
    fake = poison(prefix, suffix)
    r = pay(fake)
    assert r.decision == ActionDecision.REJECT and r.flags == ["LOOKALIKE_RECIPIENT"]
    assert PAYEE in r.explanation and "reject_payment" in r.required_actions


def test_explanation_shows_the_matching_ends():
    r = pay(poison(4, 4))
    assert "start 0x2ffb" in r.explanation and "end b7ee" in r.explanation


@pytest.mark.parametrize("prefix,suffix", [(3, 3), (2, 6), (6, 2), (0, 0), (1, 1)])
def test_ordinary_new_payees_are_only_held(prefix, suffix):
    r = pay(poison(prefix, suffix))
    assert r.decision == ActionDecision.HOLD and r.flags == ["NEW_COUNTERPARTY"]


def test_known_payee_and_case_differences_are_fine():
    assert pay(PAYEE).decision == ActionDecision.APPROVE
    assert pay(PAYEE.upper().replace("0X", "0x")).decision == ActionDecision.APPROVE


def test_off_without_known_recipients():
    assert pay(poison(4, 4), known_recipients=None).decision == ActionDecision.APPROVE


def test_closest_known_payee_is_named():
    other = "0x2ffb" + "1" * 32 + "b7ee"  # also a 4+4 match, but less close than the real payee
    known = parse_address_list("k", [PAYEE, other])
    fake = poison(6, 6)
    assert find_lookalike(fake, known)[0] == PAYEE


def test_sanctions_and_blocklist_still_come_first():
    fake = poison(4, 4)
    r = pay(fake, blocked_addresses=[fake])
    assert r.flags[0] == "BLOCKLISTED_ADDRESS"


def test_applies_to_transactions_and_x402():
    fake = poison(4, 4)
    data = "0xa9059cbb" + fake[2:].zfill(64) + format(1_000_000, "064x")
    r = check_transaction({"to": USDC_ADDRESSES[8453], "data": data, "chainId": 8453, "from": ME},
                          known_recipients=[PAYEE], peg_deviation_pct=0.1)
    assert r.flags == ["LOOKALIKE_RECIPIENT"]
    import time
    now = int(time.time())
    td = {"primaryType": "TransferWithAuthorization",
          "domain": {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC_ADDRESSES[8453]},
          "message": {"from": ME, "to": fake, "value": "1000000", "validAfter": str(now - 60),
                      "validBefore": str(now + 300), "nonce": "0x" + "ab" * 32}}
    assert check_authorization(td, known_recipients=[PAYEE], peg_deviation_pct=0.1).flags == ["LOOKALIKE_RECIPIENT"]


def test_poison_helper_is_exact():
    for p, s in [(4, 4), (3, 3), (0, 0)]:
        fake = poison(p, s)
        assert len(fake) == 42 and fake != PAYEE
        h, k = fake[2:], PAYEE[2:]
        assert h[:p] == k[:p] and (p == 40 or h[p] != k[p])
        assert h[40 - s:] == k[40 - s:] and (s == 40 or h[39 - s] != k[39 - s])
