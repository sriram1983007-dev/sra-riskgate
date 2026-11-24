"""SRA-RiskGate Cloud: the hosted service behind ``sra_riskgate.cloud``.

What it adds to the free, offline library, for teams whose agents run on more than one machine:

- ``POST /v1/check``: the library's ``check_payment`` on the payment fields, with the organisation's policy, a
  **shared spend ledger** (budgets hold across every machine), the **threat feed** as a blocklist, and a **signed,
  chained receipt** kept in the vault. The payment's free text never reaches the service: the client checks it
  locally first.
- ``POST /v1/ledger/release``: give back budget for an approved payment that was never sent.
- ``GET/PUT /v1/policy``: the organisation's policy, in the library's policy format (no ``ledger``, no ``screening``).
- ``GET /v1/feed``, ``POST /v1/feed/report``: look-alike addresses reported by scans. An address enters everyone's
  feed only when ``SRA_CLOUD_FEED_MIN_ORGS`` (default 2) organisations reported it or an operator approved it.
- ``GET /v1/receipts``, ``GET /v1/report``: the receipt vault and an audit report built from it.
- ``GET /v1/usage``: checks used this month against the plan.
- ``POST /v1/x402/check``: pay per check in USDC with x402, no account (when ``SRA_CLOUD_X402_PAY_TO`` is set).
- ``GET /``: a small dashboard; ``GET /healthz``.

Authentication: ``Authorization: Bearer sra_live_...`` (create organisations and keys with ``sra-cloud``).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from sra_riskgate import (ReceiptSigner, __version__ as LIB_VERSION, audit_report, audit_report_markdown,
                          check_payment, issue_receipt, load_policy)
from sra_riskgate.sanctions import _normalise
from sra_riskgate.spend import SpendGuard

from sra_riskgate_cloud import __version__
from sra_riskgate_cloud.db import DBLedger, Store, plans, row_policy

MAX_BODY = 64 * 1024
FORBIDDEN_POLICY_KEYS = {"ledger", "screening"}


class CheckIn(BaseModel):
    chain_id: int = Field(..., description="EVM chain id, e.g. 8453 for Base")
    sender: str = Field(..., description="The paying wallet")
    recipient: str = Field(..., description="The payee")
    amount: float = Field(..., description="Amount in whole token units, e.g. 25 for 25 USDC")
    token: str = Field("USDC", description="Token symbol")
    peg_deviation_pct: Optional[float] = Field(None, description="Current depeg in percent, if known")
    payment_id: Optional[str] = Field(None, max_length=200, description="Your id, to release budget later")
    known_recipients: Optional[List[str]] = Field(None, max_length=10_000,
                                                  description="Added to the policy's known payees")


class ReleaseIn(BaseModel):
    payment_id: str = Field(..., min_length=1, max_length=200)


class ReportIn(BaseModel):
    address: str
    imitates: Optional[str] = None
    chain_id: Optional[int] = None
    tx: Optional[str] = Field(None, max_length=100)


def _feed_min_orgs() -> int:
    v = int(os.environ.get("SRA_CLOUD_FEED_MIN_ORGS", "2"))
    if v < 2:
        raise ValueError("SRA_CLOUD_FEED_MIN_ORGS must be at least 2, so no single organisation controls the feed")
    return v


def _validate_policy(data: Any):
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    bad = sorted(FORBIDDEN_POLICY_KEYS & set(data))
    if bad:
        raise ValueError(f"{', '.join(bad)} cannot be set on the cloud service (the ledger is shared and kept by "
                         "the service; screening keys stay on your machines)")
    return load_policy(data)


def _guard(policy, store: Store, org_id: str) -> Optional[SpendGuard]:
    g = policy.spend_guard
    if g is None:
        return None
    return SpendGuard(DBLedger(store, org_id), total_limit=g.total_limit, per_payee_limit=g.per_payee_limit,
                      window_seconds=g.window_seconds, max_payments_per_hour=g.max_payments_per_hour,
                      amount_spike_factor=g.amount_spike_factor, spike_min_history=g.spike_min_history)


def _run_check(store: Store, org: Any, body: CheckIn, *, feed_addresses: List[str]) -> Dict[str, Any]:
    """The check, its ledger entry and its receipt, atomically for this organisation."""
    org_id = org["id"]
    policy = _validate_policy(row_policy(org))
    kw = policy.check_kwargs()
    kw.pop("spend_guard", None)
    guard = _guard(policy, store, org_id)
    known = list(kw.pop("known_recipients", []) or []) + list(body.known_recipients or [])
    blocked = list(kw.pop("blocked_addresses", []) or []) + feed_addresses
    payment = {"chain_id": body.chain_id, "sender": body.sender, "recipient": body.recipient,
               "amount": body.amount, "token": body.token}
    signer = ReceiptSigner.hmac(bytes(org["receipt_key"]), key_id=org_id)
    with store.org_lock(org_id):
        result = check_payment(**payment, peg_deviation_pct=body.peg_deviation_pct,
                               known_recipients=known or None, blocked_addresses=blocked or None,
                               spend_guard=guard, payment_id=body.payment_id, **kw)
        prev = store.last_receipt(org_id)
        receipt = issue_receipt(result, signer, payment=payment, policy=policy,
                                **({"previous": prev} if prev else {"chain_start": True}))
        seq = store.add_receipt(org_id, receipt)
    out = result.model_dump(mode="json")
    out.update({"receipt": receipt, "receipt_seq": seq, "source": "sra-riskgate-cloud"})
    return out


def create_app(store: Optional[Store] = None, *, x402_facilitator: Any = None) -> FastAPI:
    """The app. ``x402_facilitator`` replaces the HTTP facilitator client (for tests)."""
    store = store or Store(os.environ.get("SRA_CLOUD_DB", "sra-cloud.db"))
    min_orgs = _feed_min_orgs()
    plan_limits = plans()
    app = FastAPI(title="SRA-RiskGate Cloud", version=__version__,
                  description="Shared budgets, threat feed and receipt vault for agents that pay.")
    app.state.store = store

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        size = request.headers.get("content-length")
        if size is not None and (not size.isdigit() or int(size) > MAX_BODY):
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    def org_dep(authorization: Optional[str] = Header(None)) -> Any:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing API key: send Authorization: Bearer sra_live_...")
        org = store.org_for_key(authorization[7:].strip())
        if org is None:
            raise HTTPException(401, "invalid or revoked API key")
        return org

    def feed_addresses() -> List[str]:
        return [x["address"] for x in store.feed(min_orgs)]

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "service": f"sra-riskgate-cloud {__version__}", "library": f"sra-riskgate {LIB_VERSION}"}

    @app.post("/v1/check")
    def check(body: CheckIn, org=Depends(org_dep)):
        limit = plan_limits.get(org["plan"], 0)
        used = store.use_check(org["id"], limit)
        if used is None:
            raise HTTPException(429, f"monthly check limit reached for plan {org['plan']} ({limit}); "
                                     "the client treats this as hold")
        try:
            out = _run_check(store, org, body, feed_addresses=feed_addresses())
        except ValueError as e:  # a stored policy that no longer validates
            raise HTTPException(409, f"organisation policy is invalid: {e}") from e
        out["usage"] = {"checks_this_month": used, "limit": limit, "plan": org["plan"]}
        return out

    @app.post("/v1/ledger/release")
    def release(body: ReleaseIn, org=Depends(org_dep)):
        with store.org_lock(org["id"]):
            n = DBLedger(store, org["id"]).remove(body.payment_id)
        return {"released": n}

    @app.get("/v1/policy")
    def get_policy(org=Depends(org_dep)):
        p = row_policy(org)
        return {"policy": p, "sha256": load_policy(p).sha256}

    @app.put("/v1/policy")
    def put_policy(policy: Dict[str, Any], org=Depends(org_dep)):
        try:
            p = _validate_policy(policy)
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
        store.set_policy(org["id"], policy)
        return {"policy": policy, "sha256": p.sha256}

    @app.get("/v1/feed")
    def get_feed(org=Depends(org_dep)):
        items = store.feed(min_orgs)
        return {"addresses": [x["address"] for x in items], "entries": items, "min_orgs": min_orgs,
                "updated": time.time()}

    @app.post("/v1/feed/report")
    def report(body: ReportIn, org=Depends(org_dep)):
        a, i = _normalise(body.address), _normalise(body.imitates) if body.imitates else None
        if a is None or (body.imitates and i is None):
            raise HTTPException(422, "address and imitates must be EVM addresses")
        store.report(org["id"], a, i, body.chain_id, body.tx)
        listed = a in {x["address"] for x in store.feed(min_orgs)}
        return {"reported": a, "in_feed": listed}

    @app.get("/v1/receipts")
    def receipts(after: int = 0, limit: int = 1000, org=Depends(org_dep)):
        return {"receipts": store.receipts(org["id"], after=max(0, after), limit=max(1, min(limit, 5000)))}

    @app.get("/v1/report")
    def report_view(format: str = "json", org=Depends(org_dep)):
        rows = [r["receipt"] for r in store.receipts(org["id"], limit=1_000_000)]
        rep = audit_report(rows, key=bytes(org["receipt_key"]), title=f"{org['name']}: agent payment decisions")
        if format == "md":
            return PlainTextResponse(audit_report_markdown(rep), media_type="text/markdown")
        return rep

    @app.get("/v1/usage")
    def usage(org=Depends(org_dep)):
        return {"org": org["name"], "plan": org["plan"], "checks_this_month": store.usage(org["id"]),
                "limit": plan_limits.get(org["plan"], 0)}

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        from sra_riskgate_cloud.dashboard import PAGE
        return PAGE

    _mount_x402(app, store, feed_addresses, x402_facilitator)
    return app


def _mount_x402(app: FastAPI, store: Store, feed_addresses, facilitator: Any = None) -> None:
    """Pay-per-check with x402 on POST /v1/x402/check, if SRA_CLOUD_X402_PAY_TO is set.

    Uses the official x402 SDK middleware (verification and settlement through the facilitator). Paid checks are
    stateless: no shared ledger, since there is no account; the result carries a receipt signed with the service's
    own key (SRA_CLOUD_X402_RECEIPT_KEY, hex), and the threat feed applies.
    """
    pay_to = os.environ.get("SRA_CLOUD_X402_PAY_TO")
    if not pay_to:
        return
    if _normalise(pay_to) is None:
        raise ValueError("SRA_CLOUD_X402_PAY_TO must be an EVM address")
    key_hex = os.environ.get("SRA_CLOUD_X402_RECEIPT_KEY")
    if not key_hex:
        raise ValueError("SRA_CLOUD_X402_RECEIPT_KEY (hex) is required with SRA_CLOUD_X402_PAY_TO")
    receipt_key = bytes.fromhex(key_hex)
    try:
        from x402 import x402ResourceServer
        from x402.http import FacilitatorConfig, HTTPFacilitatorClient
        from x402.http.middleware.fastapi import payment_middleware
        from x402.mechanisms.evm.exact import register_exact_evm_server
    except ImportError as e:  # pragma: no cover
        raise ImportError("pay-per-check needs the x402 SDK: pip install 'sra-riskgate-cloud[x402]' (x402[fastapi,evm])") from e
    network = os.environ.get("SRA_CLOUD_X402_NETWORK", "eip155:8453")
    price = os.environ.get("SRA_CLOUD_X402_PRICE", "$0.002")
    cfg = {"url": os.environ["SRA_CLOUD_FACILITATOR_URL"]} if os.environ.get("SRA_CLOUD_FACILITATOR_URL") else {}
    facilitator = facilitator or HTTPFacilitatorClient(FacilitatorConfig(**cfg))
    server = register_exact_evm_server(x402ResourceServer(facilitator), network)
    routes = {"POST /v1/x402/check": {"accepts": {"scheme": "exact", "payTo": pay_to, "price": price,
                                                  "network": network},
                                      "description": "One SRA-RiskGate payment check"}}
    mw = payment_middleware(routes, server)

    @app.middleware("http")
    async def x402_mw(request, call_next):
        return await mw(request, call_next)

    signer = ReceiptSigner.hmac(receipt_key, key_id="sra-cloud-x402")

    @app.post("/v1/x402/check")
    def x402_check(body: CheckIn):
        payment = {"chain_id": body.chain_id, "sender": body.sender, "recipient": body.recipient,
                   "amount": body.amount, "token": body.token}
        result = check_payment(**payment, peg_deviation_pct=body.peg_deviation_pct,
                               known_recipients=body.known_recipients or None,
                               blocked_addresses=feed_addresses() or None, lookalike_check="strict")
        out = result.model_dump(mode="json")
        out.update({"receipt": issue_receipt(result, signer, payment=payment), "source": "sra-riskgate-cloud x402"})
        return out
