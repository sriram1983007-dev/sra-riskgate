"""A one-page dashboard. The API key stays in the browser tab (sessionStorage) and is sent only to this service."""

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SRA-RiskGate Cloud</title>
<style>
 :root { --ink:#1a2a44; --mid:#556578; --rule:#d4dce8; --panel:#f4f6f9; --accent:#1a5cc8; }
 body { font: 15px/1.5 system-ui, sans-serif; color: var(--ink); margin: 0; background: #fff; }
 main { max-width: 960px; margin: 0 auto; padding: 32px 20px; }
 h1 { font-size: 22px; margin: 0 0 4px; } p.sub { color: var(--mid); margin: 0 0 24px; }
 .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }
 .tile { background: var(--panel); border-radius: 8px; padding: 14px 16px; }
 .tile b { display: block; font-size: 24px; } .tile span { color: var(--mid); font-size: 13px; }
 table { width: 100%; border-collapse: collapse; font-size: 13px; }
 th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rule); }
 code { font-size: 12px; } input { width: 340px; max-width: 100%; padding: 8px; border: 1px solid var(--rule);
 border-radius: 6px; } button { padding: 8px 14px; border: 0; border-radius: 6px; background: var(--accent);
 color: #fff; cursor: pointer; } .err { color: #b42318; } .approve { color: #067647 } .hold { color: #b54708 }
 .reject { color: #b42318 }
</style></head><body><main>
<h1>SRA-RiskGate Cloud</h1><p class="sub">Shared budgets, threat feed and signed decisions for your agents.</p>
<form id="f"><input id="k" type="password" placeholder="sra_live_..." autocomplete="off">
<button>Open</button></form><p id="msg"></p>
<section id="out" hidden>
 <div class="row"><div class="tile"><b id="plan"></b><span>plan</span></div>
 <div class="tile"><b id="used"></b><span>checks this month</span></div>
 <div class="tile"><b id="verified"></b><span>receipts verified</span></div>
 <div class="tile"><b id="feed"></b><span>addresses in threat feed</span></div></div>
 <h2>Recent decisions</h2>
 <table><thead><tr><th>#</th><th>When</th><th>Decision</th><th>Payee</th><th>Amount</th><th>Flags</th></tr></thead>
 <tbody id="rows"></tbody></table>
</section>
<script>
const $ = (id) => document.getElementById(id);
let key = null; try { key = sessionStorage.getItem("sra_key"); } catch (e) {}
async function api(path) {
  const r = await fetch(path, { headers: { Authorization: "Bearer " + key } });
  if (!r.ok) throw new Error((await r.json()).detail || r.status);
  return r.json();
}
function text(el, v) { el.textContent = v; return el; }
async function load() {
  $("msg").textContent = "";
  try {
    const [u, rep, feed, rec] = await Promise.all([api("/v1/usage"), api("/v1/report"), api("/v1/feed"),
                                                   api("/v1/receipts?limit=5000")]);
    text($("plan"), u.plan); text($("used"), u.checks_this_month + " / " + u.limit);
    text($("verified"), rep.verified + " / " + rep.receipts); text($("feed"), feed.addresses.length);
    const body = $("rows"); body.replaceChildren();
    rec.receipts.slice(-50).reverse().forEach((x) => {
      const r = x.receipt, p = r.payment || {}, tr = document.createElement("tr");
      [x.seq, r.issued_at, r.decision, p.recipient || "", (p.amount ?? "") + " " + (p.token || ""),
       (r.flags || []).join(", ")].forEach((v, i) => { const td = text(document.createElement("td"), v);
        if (i === 2) td.className = v; tr.appendChild(td); });
      body.appendChild(tr);
    });
    $("out").hidden = false;
  } catch (e) { $("out").hidden = true; $("msg").className = "err"; text($("msg"), "Could not load: " + e.message); }
}
$("f").addEventListener("submit", (ev) => { ev.preventDefault(); key = $("k").value.trim();
  try { sessionStorage.setItem("sra_key", key); } catch (e) {} load(); });
if (key) load();
</script></main></body></html>
"""
