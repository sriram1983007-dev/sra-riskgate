"""SQLite storage for SRA-RiskGate Cloud: organisations, API keys, the shared spend ledger, the receipt vault,
usage and the threat feed.

One process, one database file. Writes that must be atomic (a budget check plus its ledger entry, a receipt and its
place in the chain) run under a per-organisation lock inside one transaction. Run a single instance; see README.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

from sra_riskgate.spend import SpendLedger

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, created REAL NOT NULL,
  receipt_key BLOB NOT NULL, policy TEXT NOT NULL DEFAULT '{"version": 1}'
);
CREATE TABLE IF NOT EXISTS api_keys (
  hash TEXT PRIMARY KEY, prefix TEXT NOT NULL, org_id TEXT NOT NULL REFERENCES orgs(id), label TEXT,
  created REAL NOT NULL, revoked REAL
);
CREATE TABLE IF NOT EXISTS ledger (
  org_id TEXT NOT NULL, t REAL NOT NULL, chain_id INTEGER, sender TEXT NOT NULL, recipient TEXT NOT NULL,
  token TEXT, amount REAL NOT NULL, pid TEXT
);
CREATE INDEX IF NOT EXISTS ledger_org_sender_t ON ledger(org_id, sender, t);
CREATE TABLE IF NOT EXISTS receipts (
  org_id TEXT NOT NULL, seq INTEGER NOT NULL, t REAL NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY (org_id, seq)
);
CREATE TABLE IF NOT EXISTS usage (
  org_id TEXT NOT NULL, month TEXT NOT NULL, checks INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (org_id, month)
);
CREATE TABLE IF NOT EXISTS feed_reports (
  address TEXT NOT NULL, org_id TEXT NOT NULL, imitates TEXT, chain_id INTEGER, tx TEXT, t REAL NOT NULL,
  PRIMARY KEY (address, org_id)
);
CREATE TABLE IF NOT EXISTS feed_review (
  address TEXT PRIMARY KEY, status TEXT NOT NULL CHECK (status IN ('approved', 'rejected')), note TEXT,
  t REAL NOT NULL
);
"""

DEFAULT_PLANS = {"free": 1_000, "team": 100_000, "scale": 2_000_000}
KEY_PREFIX = "sra_live_"


def plans() -> Dict[str, int]:
    """Monthly check limits per plan, from SRA_CLOUD_PLANS (JSON) or the defaults."""
    raw = os.environ.get("SRA_CLOUD_PLANS")
    if not raw:
        return dict(DEFAULT_PLANS)
    data = json.loads(raw)
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, int) and v > 0
                                             for k, v in data.items()):
        raise ValueError("SRA_CLOUD_PLANS must be a JSON object of plan name to a positive monthly check limit")
    return data


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def month(t: Optional[float] = None) -> str:
    return time.strftime("%Y-%m", time.gmtime(time.time() if t is None else t))


class Store:
    """All database access. Thread-safe: each call opens its own connection."""

    def __init__(self, path: str):
        self.path = path
        self._locks: Dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextlib.contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        try:
            yield c
        finally:
            c.close()

    @contextlib.contextmanager
    def org_lock(self, org_id: str) -> Iterator[None]:
        with self._locks_guard:
            lock = self._locks.setdefault(org_id, threading.Lock())
        with lock:
            yield

    # ------------------------------------------------------------ orgs and keys

    def create_org(self, name: str, plan: str = "free") -> Dict[str, str]:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name is required")
        if plan not in plans():
            raise ValueError(f"unknown plan {plan!r}; plans: {', '.join(plans())}")
        org_id = "org_" + secrets.token_hex(8)
        receipt_key = secrets.token_bytes(32)
        with self.conn() as c:
            c.execute("INSERT INTO orgs (id, name, plan, created, receipt_key) VALUES (?,?,?,?,?)",
                      (org_id, name.strip(), plan, time.time(), receipt_key))
        key = self.new_key(org_id, label="first key")
        return {"org_id": org_id, "api_key": key, "receipt_key_hex": receipt_key.hex()}

    def new_key(self, org_id: str, label: Optional[str] = None) -> str:
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        with self.conn() as c:
            if c.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone() is None:
                raise ValueError(f"no organisation {org_id}")
            c.execute("INSERT INTO api_keys (hash, prefix, org_id, label, created) VALUES (?,?,?,?,?)",
                      (hash_key(key), key[:16], org_id, label, time.time()))
        return key

    def revoke_key(self, prefix: str) -> int:
        with self.conn() as c:
            return c.execute("UPDATE api_keys SET revoked=? WHERE prefix=? AND revoked IS NULL",
                             (time.time(), prefix)).rowcount

    def org_for_key(self, key: str) -> Optional[sqlite3.Row]:
        if not isinstance(key, str) or not key.startswith(KEY_PREFIX):
            return None
        with self.conn() as c:
            return c.execute("SELECT o.* FROM api_keys k JOIN orgs o ON o.id=k.org_id "
                             "WHERE k.hash=? AND k.revoked IS NULL", (hash_key(key),)).fetchone()

    def org(self, org_id: str) -> Optional[sqlite3.Row]:
        with self.conn() as c:
            return c.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()

    def orgs(self) -> List[sqlite3.Row]:
        with self.conn() as c:
            return c.execute("SELECT id, name, plan, created FROM orgs ORDER BY created").fetchall()

    def set_plan(self, org_id: str, plan: str) -> None:
        if plan not in plans():
            raise ValueError(f"unknown plan {plan!r}; plans: {', '.join(plans())}")
        with self.conn() as c:
            if c.execute("UPDATE orgs SET plan=? WHERE id=?", (plan, org_id)).rowcount != 1:
                raise ValueError(f"no organisation {org_id}")

    def set_policy(self, org_id: str, policy: dict) -> None:
        with self.conn() as c:
            c.execute("UPDATE orgs SET policy=? WHERE id=?", (json.dumps(policy, sort_keys=True), org_id))

    # ------------------------------------------------------------ usage

    def use_check(self, org_id: str, limit: int, now: Optional[float] = None) -> Optional[int]:
        """Count one check this month. Returns the new count, or None if the limit was already reached."""
        m = month(now)
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT checks FROM usage WHERE org_id=? AND month=?", (org_id, m)).fetchone()
            n = row["checks"] if row else 0
            if n >= limit:
                c.execute("ROLLBACK")
                return None
            c.execute("INSERT INTO usage (org_id, month, checks) VALUES (?,?,1) ON CONFLICT(org_id, month) "
                      "DO UPDATE SET checks=checks+1", (org_id, m))
            c.execute("COMMIT")
            return n + 1

    def usage(self, org_id: str, now: Optional[float] = None) -> int:
        with self.conn() as c:
            row = c.execute("SELECT checks FROM usage WHERE org_id=? AND month=?", (org_id, month(now))).fetchone()
            return row["checks"] if row else 0

    # ------------------------------------------------------------ receipts

    def last_receipt(self, org_id: str) -> Optional[dict]:
        with self.conn() as c:
            row = c.execute("SELECT receipt FROM receipts WHERE org_id=? ORDER BY seq DESC LIMIT 1",
                            (org_id,)).fetchone()
            return json.loads(row["receipt"]) if row else None

    def add_receipt(self, org_id: str, receipt: dict) -> int:
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            seq = (c.execute("SELECT MAX(seq) FROM receipts WHERE org_id=?", (org_id,)).fetchone()[0] or 0) + 1
            c.execute("INSERT INTO receipts (org_id, seq, t, receipt) VALUES (?,?,?,?)",
                      (org_id, seq, time.time(), json.dumps(receipt, sort_keys=True)))
            c.execute("COMMIT")
            return seq

    def receipts(self, org_id: str, after: int = 0, limit: int = 1000) -> List[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT seq, receipt FROM receipts WHERE org_id=? AND seq>? ORDER BY seq LIMIT ?",
                             (org_id, after, limit)).fetchall()
            return [{"seq": r["seq"], "receipt": json.loads(r["receipt"])} for r in rows]

    # ------------------------------------------------------------ threat feed

    def report(self, org_id: str, address: str, imitates: Optional[str], chain_id: Optional[int],
               tx: Optional[str]) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO feed_reports (address, org_id, imitates, chain_id, tx, t) VALUES (?,?,?,?,?,?) "
                      "ON CONFLICT(address, org_id) DO UPDATE SET imitates=excluded.imitates, "
                      "chain_id=excluded.chain_id, tx=excluded.tx, t=excluded.t",
                      (address, org_id, imitates, chain_id, tx, time.time()))

    def review(self, address: str, status: str, note: Optional[str] = None) -> None:
        if status not in ("approved", "rejected"):
            raise ValueError("status must be approved or rejected")
        with self.conn() as c:
            c.execute("INSERT INTO feed_review (address, status, note, t) VALUES (?,?,?,?) ON CONFLICT(address) "
                      "DO UPDATE SET status=excluded.status, note=excluded.note, t=excluded.t",
                      (address, status, note, time.time()))

    def feed(self, min_orgs: int) -> List[dict]:
        """Addresses in the feed: approved by an operator, or reported by at least ``min_orgs`` organisations and
        not rejected by an operator. One organisation alone can never put an address in everyone's feed."""
        with self.conn() as c:
            rows = c.execute(
                "SELECT r.address, COUNT(DISTINCT r.org_id) AS orgs, MIN(r.t) AS first_seen, "
                "MAX(r.imitates) AS imitates, MAX(r.chain_id) AS chain_id, v.status "
                "FROM feed_reports r LEFT JOIN feed_review v ON v.address=r.address GROUP BY r.address "
                "UNION SELECT v.address, 0, v.t, NULL, NULL, v.status FROM feed_review v "
                "WHERE v.status='approved' AND v.address NOT IN (SELECT address FROM feed_reports)").fetchall()
        out = []
        for r in rows:
            if r["status"] == "rejected":
                continue
            if r["status"] == "approved" or r["orgs"] >= min_orgs:
                out.append({"address": r["address"], "reports": r["orgs"], "imitates": r["imitates"],
                            "chain_id": r["chain_id"], "first_seen": r["first_seen"],
                            "reviewed": r["status"] == "approved"})
        return sorted(out, key=lambda x: x["address"])

    def pending_reports(self, min_orgs: int) -> List[dict]:
        listed = {x["address"] for x in self.feed(min_orgs)}
        with self.conn() as c:
            rows = c.execute("SELECT r.address, COUNT(DISTINCT r.org_id) AS orgs, MAX(r.imitates) AS imitates "
                             "FROM feed_reports r LEFT JOIN feed_review v ON v.address=r.address "
                             "WHERE v.status IS NULL GROUP BY r.address").fetchall()
        return [dict(r) for r in rows if r["address"] not in listed]


class DBLedger(SpendLedger):
    """A ``SpendLedger`` kept in the cloud database for one organisation, so every machine shares one budget."""

    def __init__(self, store: Store, org_id: str):
        super().__init__(None)
        self.store, self.org_id = store, org_id

    def entries(self, sender: str, since: float) -> List[dict]:
        with self.store.conn() as c:
            rows = c.execute("SELECT t, chain_id, sender, recipient, token, amount, pid FROM ledger "
                             "WHERE org_id=? AND sender=? AND t>=? ORDER BY t", (self.org_id, sender.lower(), since))
            return [{"t": r["t"], "chain_id": r["chain_id"], "sender": r["sender"], "recipient": r["recipient"],
                     "token": r["token"], "amount": r["amount"], "id": r["pid"]} for r in rows]

    def append(self, entry: dict) -> None:
        with self.store.conn() as c:
            c.execute("INSERT INTO ledger (org_id, t, chain_id, sender, recipient, token, amount, pid) "
                      "VALUES (?,?,?,?,?,?,?,?)",
                      (self.org_id, entry["t"], entry.get("chain_id"), entry["sender"], entry["recipient"],
                       entry.get("token"), entry["amount"], entry.get("id")))

    def remove(self, payment_id: str) -> int:
        with self.store.conn() as c:
            return c.execute("DELETE FROM ledger WHERE org_id=? AND pid=?", (self.org_id, payment_id)).rowcount

    def compact(self, now: Optional[float] = None) -> int:
        cutoff = (now if now is not None else time.time()) - 31 * 86_400
        with self.store.conn() as c:
            return c.execute("DELETE FROM ledger WHERE org_id=? AND t<?", (self.org_id, cutoff)).rowcount


def row_policy(row: Any) -> dict:
    return json.loads(row["policy"]) if row is not None else {"version": 1}


def as_dict(row: Any) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()} if row is not None else {}
