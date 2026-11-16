"""Spending budgets and payee anomaly checks across payments (1.8.0+).

A per-payment ceiling does not stop an agent being drained by many small payments. ``SpendGuard`` keeps a local
ledger of what each agent wallet has been approved to pay and holds a payment that would break a rolling budget
or looks unlike the wallet's own history:

    guard = SpendGuard(SpendLedger("~/.sra-riskgate/ledger.jsonl"),
                       total_limit=200, per_payee_limit=50, window_seconds=86_400,   # budgets
                       max_payments_per_hour=60, amount_spike_factor=5)              # anomalies
    result = check_payment(..., spend_guard=guard)

Flags (all HOLD, never REJECT: the payment may be fine, a person should look):

- ``BUDGET_EXCEEDED``: this payment would take the wallet's total over ``total_limit`` within the window.
- ``PAYEE_BUDGET_EXCEEDED``: it would take the total paid to this payee over ``per_payee_limit`` within the window.
- ``RATE_SPIKE``: the wallet already made ``max_payments_per_hour`` approved payments in the last hour.
- ``AMOUNT_SPIKE``: the amount is more than ``amount_spike_factor`` times the median of the wallet's last
  payments to this payee (needs ``spike_min_history`` earlier payments, so new payees are not flagged by it;
  ``known_recipients`` covers new payees).

Amounts are in the stablecoin's own units and every listed stablecoin is pegged to the US dollar, so totals add
across tokens. Budgets apply per sender wallet (case-insensitive) and across chains.

Recording: with ``reserve_on_approve=True`` (the default), an approved payment is written to the ledger when it is
approved, so two payments checked one after the other both count. A payment that was approved but never sent can
be removed with ``guard.release(payment_id)`` if you passed ``payment_id``. Counting approvals rather than
settlements errs on the safe side: an unsent payment can only make the budget stricter. Inside a smart-account
UserOperation each payee's batch total is recorded once.

The ledger is a JSON Lines file (or memory only, with no path). It is local and per machine: several processes
writing the same file are serialised with a lock on POSIX, but separate machines need separate budgets or a shared
ledger of your own (subclass ``SpendLedger``). An unreadable or corrupt ledger makes every check fail closed (HOLD).
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import math
import os
import statistics
import threading
import time
from typing import Any, Callable, Iterator, List, Optional, Tuple

__all__ = ["SpendLedger", "SpendGuard", "SpendEntry"]

_RETAIN_SECONDS = 31 * 86_400  # entries older than this are dropped when the file is compacted
_suppress_record: contextvars.ContextVar[bool] = contextvars.ContextVar("sra_suppress_record", default=False)


@contextlib.contextmanager
def suppress_recording() -> Iterator[None]:
    """Inside this block ``check_payment`` evaluates budgets but does not record (used for UserOperation batches)."""
    token = _suppress_record.set(True)
    try:
        yield
    finally:
        _suppress_record.reset(token)


def recording_suppressed() -> bool:
    return _suppress_record.get()


SpendEntry = dict  # {"t": unix seconds, "chain_id", "sender", "recipient", "token", "amount", "id"}


def _positive(name: str, v: Any, *, integer: bool = False) -> Any:
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
        raise ValueError(f"{name} must be a positive number")
    if integer and int(v) != v:
        raise ValueError(f"{name} must be a whole number")
    return int(v) if integer else float(v)


class SpendLedger:
    """Approved payments, per wallet. ``path=None`` keeps them in memory only (lost when the process exits)."""

    def __init__(self, path: Optional[str] = None):
        self.path = os.path.expanduser(path) if path else None
        self._lock = threading.Lock()
        self._mem: List[dict] = []
        if self.path:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)

    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        if not self.path:
            yield
            return
        lock_path = self.path + ".lock"
        with open(lock_path, "a") as fh:
            try:
                import fcntl  # POSIX only
                fcntl.flock(fh, fcntl.LOCK_EX)
            except ImportError:  # pragma: no cover - Windows: the thread lock still applies
                pass
            try:
                yield
            finally:
                try:
                    import fcntl
                    fcntl.flock(fh, fcntl.LOCK_UN)
                except ImportError:  # pragma: no cover
                    pass

    def _read(self) -> List[dict]:
        if not self.path:
            return list(self._mem)
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)  # a corrupt line raises: callers fail closed
                if not isinstance(e, dict) or not isinstance(e.get("t"), (int, float)) \
                        or not isinstance(e.get("amount"), (int, float)) or not isinstance(e.get("sender"), str):
                    raise ValueError(f"ledger line {n} is not a valid entry")
                out.append(e)
        return out

    def entries(self, sender: str, since: float) -> List[dict]:
        """Entries for ``sender`` at or after unix time ``since``, oldest first."""
        s = sender.lower()
        with self._lock, self._file_lock():
            return [e for e in self._read() if e["sender"] == s and e["t"] >= since]

    def append(self, entry: dict) -> None:
        with self._lock, self._file_lock():
            if not self.path:
                self._mem.append(entry)
                return
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

    def remove(self, payment_id: str) -> int:
        """Remove every entry with this ``payment_id``; returns how many were removed."""
        with self._lock, self._file_lock():
            rows = self._read()
            keep = [e for e in rows if e.get("id") != payment_id]
            self._write(keep)
            return len(rows) - len(keep)

    def compact(self, now: Optional[float] = None) -> int:
        """Drop entries older than 31 days; returns how many were dropped."""
        cutoff = (now if now is not None else time.time()) - _RETAIN_SECONDS
        with self._lock, self._file_lock():
            rows = self._read()
            keep = [e for e in rows if e["t"] >= cutoff]
            self._write(keep)
            return len(rows) - len(keep)

    def _write(self, rows: List[dict]) -> None:
        if not self.path:
            self._mem = rows
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for e in rows:
                fh.write(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n")
        os.replace(tmp, self.path)


class SpendGuard:
    """Rolling budgets and anomaly limits, checked against a ``SpendLedger``. Every limit is optional."""

    def __init__(self, ledger: Optional[SpendLedger] = None, *, total_limit: Optional[float] = None,
                 per_payee_limit: Optional[float] = None, window_seconds: float = 86_400,
                 max_payments_per_hour: Optional[int] = None, amount_spike_factor: Optional[float] = None,
                 spike_min_history: int = 5, reserve_on_approve: bool = True,
                 clock: Optional[Callable[[], float]] = None):
        if ledger is not None and not isinstance(ledger, SpendLedger):
            raise ValueError("ledger must be a SpendLedger")
        self.ledger = ledger if ledger is not None else SpendLedger()
        self.total_limit = _positive("total_limit", total_limit)
        self.per_payee_limit = _positive("per_payee_limit", per_payee_limit)
        self.window_seconds = _positive("window_seconds", window_seconds)
        self.max_payments_per_hour = _positive("max_payments_per_hour", max_payments_per_hour, integer=True)
        self.amount_spike_factor = _positive("amount_spike_factor", amount_spike_factor)
        if self.amount_spike_factor is not None and self.amount_spike_factor <= 1:
            raise ValueError("amount_spike_factor must be greater than 1")
        self.spike_min_history = _positive("spike_min_history", spike_min_history, integer=True)
        if not isinstance(reserve_on_approve, bool):
            raise ValueError("reserve_on_approve must be True or False")
        if all(v is None for v in (self.total_limit, self.per_payee_limit, self.max_payments_per_hour,
                                   self.amount_spike_factor)):
            raise ValueError("SpendGuard needs at least one limit: total_limit, per_payee_limit, "
                             "max_payments_per_hour or amount_spike_factor")
        self.reserve_on_approve = reserve_on_approve
        self._clock = clock or time.time

    def evaluate(self, *, sender: str, recipient: str, amount: float) -> List[Tuple[str, str]]:
        """``[(flag, reason), ...]`` for every limit this payment would break; empty when it is within all of them."""
        now = self._clock()
        horizon = max(self.window_seconds, 3600.0, 0.0)
        rows = self.ledger.entries(sender, now - (_RETAIN_SECONDS if self.amount_spike_factor else horizon))
        r = recipient.lower()
        win = [e for e in rows if e["t"] >= now - self.window_seconds]
        out: List[Tuple[str, str]] = []
        hours = self.window_seconds / 3600

        if self.total_limit is not None:
            spent = sum(e["amount"] for e in win)
            if spent + amount > self.total_limit + 1e-9:
                out.append(("BUDGET_EXCEEDED",
                            f"This wallet has been approved to pay {spent:g} in the last {hours:g} h; "
                            f"{amount:g} more would exceed its budget of {self.total_limit:g}."))
        if self.per_payee_limit is not None:
            spent = sum(e["amount"] for e in win if e["recipient"] == r)
            if spent + amount > self.per_payee_limit + 1e-9:
                out.append(("PAYEE_BUDGET_EXCEEDED",
                            f"{spent:g} has been approved to this payee in the last {hours:g} h; {amount:g} more "
                            f"would exceed the per-payee budget of {self.per_payee_limit:g}."))
        if self.max_payments_per_hour is not None:
            n = sum(1 for e in rows if e["t"] >= now - 3600)
            if n >= self.max_payments_per_hour:
                out.append(("RATE_SPIKE", f"This wallet already made {n} approved payments in the last hour "
                                          f"(limit {self.max_payments_per_hour})."))
        if self.amount_spike_factor is not None:
            past = [e["amount"] for e in rows if e["recipient"] == r][-20:]
            if len(past) >= self.spike_min_history:
                med = statistics.median(past)
                if med > 0 and amount > self.amount_spike_factor * med:
                    out.append(("AMOUNT_SPIKE", f"{amount:g} is {amount / med:.1f}x this wallet's usual payment to "
                                                f"this payee (median {med:g} over its last {len(past)})."))
        return out

    def record(self, *, chain_id: int, sender: str, recipient: str, amount: float, token: str = "USDC",
               payment_id: Optional[str] = None) -> None:
        """Count a payment against the budgets. Called automatically on approval with ``reserve_on_approve``."""
        if payment_id is not None and (not isinstance(payment_id, str) or not payment_id.strip()):
            raise ValueError("payment_id must be a non-empty string")
        self.ledger.append({"t": self._clock(), "chain_id": chain_id, "sender": sender.lower(),
                            "recipient": recipient.lower(), "token": token, "amount": float(amount),
                            "id": payment_id})

    def release(self, payment_id: str) -> int:
        """Remove an approved payment that was never sent (by the ``payment_id`` given when it was checked)."""
        return self.ledger.remove(payment_id)
