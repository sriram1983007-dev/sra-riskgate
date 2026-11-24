"""``sra-cloud``: run and administer SRA-RiskGate Cloud.

    sra-cloud serve [--host 0.0.0.0] [--port 8080]
    sra-cloud create-org "Acme Agents" [--plan team]     # prints the org id, its first API key and its receipt key
    sra-cloud new-key ORG_ID [--label ci]
    sra-cloud revoke-key sra_live_XXXXXXX                  # the first 16 characters shown by list-keys / at creation
    sra-cloud set-plan ORG_ID team
    sra-cloud orgs
    sra-cloud feed [--pending]
    sra-cloud feed-approve 0xADDRESS [--note "..."]  /  sra-cloud feed-reject 0xADDRESS [--note "..."]

The database is SRA_CLOUD_DB (default ./sra-cloud.db).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from sra_riskgate.sanctions import _normalise

from sra_riskgate_cloud.db import Store


def _store() -> Store:
    return Store(os.environ.get("SRA_CLOUD_DB", "sra-cloud.db"))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sra-cloud", description="Run and administer SRA-RiskGate Cloud.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int,
                                                                                             default=8080)
    c = sub.add_parser("create-org"); c.add_argument("name"); c.add_argument("--plan", default="free")
    k = sub.add_parser("new-key"); k.add_argument("org_id"); k.add_argument("--label")
    r = sub.add_parser("revoke-key"); r.add_argument("prefix")
    sp = sub.add_parser("set-plan"); sp.add_argument("org_id"); sp.add_argument("plan")
    sub.add_parser("orgs")
    f = sub.add_parser("feed"); f.add_argument("--pending", action="store_true")
    for name in ("feed-approve", "feed-reject"):
        x = sub.add_parser(name); x.add_argument("address"); x.add_argument("--note")
    a = p.parse_args(argv)
    try:
        if a.cmd == "serve":
            import uvicorn
            from sra_riskgate_cloud.app import create_app
            uvicorn.run(create_app(_store()), host=a.host, port=a.port, proxy_headers=True)
            return 0
        st = _store()
        if a.cmd == "create-org":
            out = st.create_org(a.name, a.plan)
            print(json.dumps(out, indent=2))
            print("Save the API key and receipt key now: they are not shown again.", file=sys.stderr)
        elif a.cmd == "new-key":
            print(st.new_key(a.org_id, a.label))
        elif a.cmd == "revoke-key":
            n = st.revoke_key(a.prefix[:16])
            print(f"revoked {n} key(s)")
            return 0 if n else 1
        elif a.cmd == "set-plan":
            st.set_plan(a.org_id, a.plan)
            print(f"{a.org_id}: {a.plan}")
        elif a.cmd == "orgs":
            for o in st.orgs():
                print(f"{o['id']}  {o['plan']:<6}  {o['name']}")
        elif a.cmd == "feed":
            from sra_riskgate_cloud.app import _feed_min_orgs
            rows = st.pending_reports(_feed_min_orgs()) if a.pending else st.feed(_feed_min_orgs())
            print(json.dumps(rows, indent=2))
        else:
            addr = _normalise(a.address)
            if addr is None:
                raise ValueError("not an EVM address")
            st.review(addr, "approved" if a.cmd == "feed-approve" else "rejected", a.note)
            print(f"{addr}: {'approved' if a.cmd == 'feed-approve' else 'rejected'}")
        return 0
    except ValueError as e:
        print(f"sra-cloud: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
