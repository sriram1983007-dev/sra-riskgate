"""Poisoning scan (1.14.0+): which look-alike addresses are already targeting a wallet.

Address poisoning works in two steps. First the attacker makes a look-alike of one of your payees (the same first
and last characters, the part a wallet shows) appear in your history: a zero-value ``transferFrom`` of real USDC
"from" you, a fake token that emits a ``Transfer`` from you, or a dust payment to you. Then they wait for you, or
your agent, to copy the address from the history. ``check_payment`` stops the second step; this scan finds the first
one, before anyone copies anything, and gives you the addresses to block.

    sra-riskgate scan 0xYourWallet --rpc https://... [--blocks 200000] [--write-policy scan-policy.json]

    from sra_riskgate.scan import scan_wallet
    result = scan_wallet("0xYourWallet", rpc_url="https://...")
    result["findings"]          # each look-alike, the payee it imitates and the transactions that planted it
    result["blocked_addresses"] # ready for a policy's blocked_addresses
    result["suspicious_payees"] # payees you have actually paid that look like another of your payees: check both

How it decides, using only standard JSON-RPC (``eth_chainId``, ``eth_blockNumber``, ``eth_getLogs``):

1. Your **payees** are the addresses you sent a non-zero amount of a listed stablecoin to (USDC, USDT, USDB,
   USDG and any you registered with ``register_stablecoin``), plus any you pass in ``known_payees``.
2. Every other address in an ERC-20 ``Transfer`` event that has you on one side (any contract, including fake
   tokens) is checked against your payees with the same rule as ``LOOKALIKE_RECIPIENT``: strict by default
   (3 characters at each end), since every real attack the standard rule missed in 90 days of Ethereum data
   imitated only 3 at each end.
3. A match is a finding, labelled by how it was planted: ``zero_value_transfer`` (a real stablecoin moved 0 "from"
   you), ``fake_token`` (a contract that is not a listed stablecoin), ``dust_received`` (a real stablecoin sent to
   you from the look-alike).

Honest scope: the scan sees only the block range it reads (``blocks``, default 200,000: about a month on Ethereum,
under a week on Base) and only ERC-20 ``Transfer`` events, so native-coin dust and NFT spam are not covered. A
match is very unlikely to be chance (strict: about 1 in 16.7 million per payee), but it is still a pattern, not
proof of intent. The scan sends your wallet address to the RPC provider you choose; it sends nothing anywhere else.
``complete`` is False when the request budget ran out before the range was read.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional

from sra_riskgate.chains import STABLECOINS
from sra_riskgate.counterparty import LOOKALIKE_CHECKS, find_lookalike, parse_address_list, parse_lookalike_check
from sra_riskgate.sanctions import _normalise

__all__ = ["scan_wallet", "ScanError", "TRANSFER_TOPIC", "scan_policy"]

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
DEFAULT_BLOCKS = 200_000
DEFAULT_CHUNK = 10_000
DEFAULT_MAX_REQUESTS = 1000
EXPLORERS = {1: "https://etherscan.io/tx/", 8453: "https://basescan.org/tx/", 84532: "https://sepolia.basescan.org/tx/",
             42161: "https://arbiscan.io/tx/", 10: "https://optimistic.etherscan.io/tx/",
             137: "https://polygonscan.com/tx/", 43114: "https://snowtrace.io/tx/"}
_RANGE_HINTS = ("range", "limit", "too many", "exceed", "10000", "query returned more", "timeout", "response size")


class ScanError(Exception):
    """The RPC could not be read (bad URL, refused, or an error no smaller range fixes)."""


def _http_rpc(url: str, timeout: float = 30.0) -> Callable[[str, list], Any]:
    if not isinstance(url, str) or not url.startswith(("https://", "http://")):
        raise ScanError("rpc_url must be an http(s) URL")
    counter = {"id": 0}

    def call(method: str, params: list) -> Any:
        counter["id"] += 1
        body = json.dumps({"jsonrpc": "2.0", "id": counter["id"], "method": method, "params": params}).encode()
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": "sra-riskgate"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (caller's own RPC URL)
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise ScanError(f"RPC HTTP {e.code}: {e.read()[:200]!r}") from e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ScanError(f"RPC unreachable: {e}") from e
        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            raise ScanError(str(err.get("message", err)) if isinstance(err, dict) else str(err))
        if not isinstance(data, dict) or "result" not in data:
            raise ScanError("RPC answer has no result")
        return data["result"]
    return call


def _topic(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


def _addr_from_topic(t: Any) -> Optional[str]:
    if not isinstance(t, str) or len(t) != 66:
        return None
    return _normalise("0x" + t[-40:])


def _int(h: Any) -> int:
    try:
        return int(h, 16) if isinstance(h, str) and h not in ("0x", "") else 0
    except ValueError:
        return 0


def _get_logs(rpc, topics: list, start: int, end: int, chunk: int, budget: dict) -> List[dict]:
    """Read logs over [start, end] in chunks, halving a chunk the RPC refuses as too large."""
    out: List[dict] = []
    lo = start
    size = min(chunk, budget.get("size", chunk))  # start at the size the provider accepted last time
    while lo <= end:
        if budget["left"] <= 0:
            budget["stopped_at"] = lo
            return out
        hi = min(end, lo + size - 1)
        budget["left"] -= 1
        try:
            logs = rpc("eth_getLogs", [{"fromBlock": hex(lo), "toBlock": hex(hi), "topics": topics}])
        except ScanError as e:
            if size > 1 and any(h in str(e).lower() for h in _RANGE_HINTS):
                size = max(1, size // 2)
                budget["size"] = size
                continue
            raise
        if not isinstance(logs, list):
            raise ScanError("eth_getLogs did not return a list")
        out.extend(x for x in logs if isinstance(x, dict))
        lo = hi + 1
    return out


def scan_wallet(wallet: str, *, rpc_url: Optional[str] = None, rpc: Optional[Callable[[str, list], Any]] = None,
                blocks: int = DEFAULT_BLOCKS, from_block: Optional[int] = None, to_block: Optional[int] = None,
                known_payees: Optional[Iterable[str]] = None, lookalike_check: str = "strict",
                chunk: int = DEFAULT_CHUNK, max_requests: int = DEFAULT_MAX_REQUESTS) -> dict:
    """Scan ``wallet``'s ERC-20 transfer history for look-alikes of its payees. See the module docstring.

    Give ``rpc_url`` (any Ethereum JSON-RPC endpoint for the chain) or ``rpc`` (a callable ``(method, params) ->
    result``, for tests or your own client). Raises ``ScanError`` if the RPC cannot be read and ``ValueError`` on bad
    arguments; never returns a partial result silently (``complete`` says whether the whole range was read).
    """
    w = _normalise(wallet)
    if w is None:
        raise ValueError(f"wallet is not an EVM address: {wallet!r}")
    min_total = parse_lookalike_check(lookalike_check)
    extra = parse_address_list("known_payees", list(known_payees) if known_payees is not None else None) or frozenset()
    for name, v in (("blocks", blocks), ("chunk", chunk), ("max_requests", max_requests)):
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            raise ValueError(f"{name} must be a positive integer")
    if rpc is None:
        if rpc_url is None:
            raise ValueError("give rpc_url (or rpc)")
        rpc = _http_rpc(rpc_url)

    chain_id = _int(rpc("eth_chainId", []))
    latest = _int(rpc("eth_blockNumber", []))
    end = latest if to_block is None else min(int(to_block), latest)
    start = max(0, end - blocks + 1) if from_block is None else max(0, int(from_block))
    if start > end:
        raise ValueError("from_block is after to_block")
    stable = {c[0].lower(): sym for sym, chains in STABLECOINS.items() for cid, c in chains.items() if cid == chain_id}

    budget = {"left": max_requests, "stopped_at": None}
    t = _topic(w)
    out_logs = _get_logs(rpc, [TRANSFER_TOPIC, t], start, end, chunk, budget)
    in_logs = _get_logs(rpc, [TRANSFER_TOPIC, None, t], start, end, chunk, budget) if budget["left"] > 0 else []
    complete = budget["stopped_at"] is None

    # 1. payees: non-zero listed-stablecoin transfers from the wallet
    paid: Dict[str, dict] = {}
    events = []  # (counterparty, kind, log)
    for lg in out_logs:
        topics = lg.get("topics") or []
        if len(topics) < 3:
            continue
        to = _addr_from_topic(topics[2])
        contract = (lg.get("address") or "").lower()
        value = _int(lg.get("data"))
        if to is None or to == w:
            continue
        if contract in stable and value > 0:
            p = paid.setdefault(to, {"payments": 0, "first_block": _int(lg.get("blockNumber")), "tokens": set()})
            p["payments"] += 1
            p["tokens"].add(stable[contract])
        else:
            events.append((to, "zero_value_transfer" if contract in stable else "fake_token", lg))
    for lg in in_logs:
        topics = lg.get("topics") or []
        if len(topics) < 3:
            continue
        frm = _addr_from_topic(topics[1])
        contract = (lg.get("address") or "").lower()
        if frm is None or frm == w or frm == "0x" + "0" * 40:
            continue
        events.append((frm, "dust_received" if contract in stable else "fake_token", lg))

    payees = frozenset(paid) | extra

    # 2. look-alikes planted in the history
    findings: Dict[str, dict] = {}
    for addr, kind, lg in events:
        if addr in payees:
            continue
        m = find_lookalike(addr, payees, min_total)
        if m is None:
            continue
        f = findings.setdefault(addr, {"address": addr, "imitates": m[0], "shared_prefix": m[1], "shared_suffix": m[2],
                                       "kinds": set(), "transactions": []})
        f["kinds"].add(kind)
        tx = lg.get("transactionHash")
        if isinstance(tx, str) and all(x["tx"] != tx for x in f["transactions"]):
            f["transactions"].append({"tx": tx, "block": _int(lg.get("blockNumber")), "kind": kind,
                                      "contract": (lg.get("address") or "").lower(),
                                      **({"url": EXPLORERS[chain_id] + tx} if chain_id in EXPLORERS else {})})

    # 3. payees you actually paid that look like another of your payees
    suspicious = []
    plist = sorted(paid)
    for i, a in enumerate(plist):
        for b in plist[i + 1:]:
            m = find_lookalike(a, frozenset({b}), min_total)
            if m:
                pa, pb = paid[a], paid[b]
                suspicious.append({"addresses": [a, b], "shared_prefix": m[1], "shared_suffix": m[2],
                                   "payments": {a: pa["payments"], b: pb["payments"]},
                                   "first_block": {a: pa["first_block"], b: pb["first_block"]},
                                   "note": "You paid both. One may be a poisoned copy: confirm each through a channel "
                                           "you control before paying either again."})

    rows = sorted(findings.values(), key=lambda f: (-(f["shared_prefix"] + f["shared_suffix"]), f["address"]))
    for f in rows:
        f["kinds"] = sorted(f["kinds"])
        f["transactions"].sort(key=lambda x: x["block"])
    return {
        "wallet": w, "chain_id": chain_id, "from_block": start, "to_block": end,
        "complete": complete, **({} if complete else {"stopped_at_block": budget["stopped_at"]}),
        "lookalike_check": lookalike_check, "payees": len(payees), "payee_addresses": sorted(payees),
        "events_checked": len(events),
        "findings": rows, "blocked_addresses": [f["address"] for f in rows],
        "suspicious_payees": suspicious, "requests_used": max_requests - budget["left"],
    }


def scan_policy(result: dict, *, name: Optional[str] = None, include_payees: bool = False) -> dict:
    """A policy file (``version`` 1) that blocks every look-alike found, with ``lookalike_check`` set to the scan's.

    ``include_payees=True`` also writes the payees found as ``known_recipients``, which turns on the look-alike check
    against them and holds the first payment to anyone else. Validate it with ``sra-riskgate policy validate``.
    """
    pol: Dict[str, Any] = {"version": 1, "name": name or f"poisoning-scan-{result['wallet'][:10]}",
                           "blocked_addresses": list(result["blocked_addresses"]),
                           "lookalike_check": result.get("lookalike_check", "strict")}
    if include_payees:
        pol["known_recipients"] = list(result.get("payee_addresses", []))
    if pol["lookalike_check"] not in LOOKALIKE_CHECKS:
        raise ValueError("lookalike_check must be 'standard' or 'strict'")
    return pol
