#!/usr/bin/env python3
"""
warp_web.py - local web interface for Duck Scanner (warp_scan.py)

    pip install cryptography
    python warp_web.py              # opens http://127.0.0.1:8765

Needs warp_scan.py in the same folder. Listens on 127.0.0.1 only
(your WARP private keys never leave this machine).
"""
import argparse
import json
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import warp_scan as w

LOCK = threading.Lock()
S = {"state": "idle", "stage": "", "done": 0, "total": 0, "alive": 0,
     "logs": [], "result": None, "files": {}, "error": "", "cancel": None}


def log(msg):
    with LOCK:
        S["logs"].append(f"{time.strftime('%H:%M:%S')}  {msg}")
        del S["logs"][:-300]


def progress(stage, done, total, alive):
    with LOCK:
        S.update(stage=stage, done=done, total=total, alive=alive)


def job(cfg, cancel):
    try:
        res = w.run_scan(cfg, log=log, progress=progress, cancel=cancel)
        with LOCK:
            S.update(state="done", files=res["files"], result={
                "endpoints": res["endpoints"], "found": res["found"],
                "wanted": res["wanted"], "registered": res["registered"],
                "files": {k: len(v) for k, v in res["files"].items()}})
        log("[+] done")
    except w.Cancelled:
        with LOCK:
            S["state"] = "cancelled"
        log("[i] cancelled")
    except Exception as e:  # noqa: BLE001
        with LOCK:
            S.update(state="error", error=str(e))
        log(f"[!] {e}")


def parse_cfg(d):
    def num(k, lo, hi, cast=int):
        v = cast(d.get(k))
        if not lo <= v <= hi:
            raise ValueError(f"{k} must be between {lo} and {hi}")
        return v

    cfg = w.Config(
        use_proxy=bool(d.get("use_proxy")),
        proxy_type=d.get("proxy_type", "socks5"),
        proxy_host=str(d.get("proxy_host", "127.0.0.1")).strip() or "127.0.0.1",
        proxy_port=num("proxy_port", 1, 65535),
        stack=d.get("stack", "v4"),
        single=num("single", 0, 500), wow=num("wow", 0, 500),
        amnezia=num("amnezia", 0, 500), masque=num("masque", 0, 500),
        mom=num("mom", 0, 500), gool=num("gool", 0, 500),
        masque_transport=d.get("masque_transport", "h3"),
        baseline=bool(d.get("baseline", True)),
        masque_fragment=bool(d.get("masque_fragment", True)),
        jc=num("jc", 0, 128), jmin=num("jmin", 0, 1280), jmax=num("jmax", 0, 1280),
        xray_path=str(d.get("xray_path", "")).strip().strip('"'),
        xray_verify=num("xray_verify", 0, 100),
        candidates=num("candidates", 50, 60000), probes=num("probes", 0, 10),
        timeout=num("timeout", 0.3, 10, float), workers=num("workers", 4, 600))
    if cfg.proxy_type not in ("socks5", "http") or cfg.stack not in ("v4", "v6", "dual") \
            or cfg.masque_transport not in ("h3", "h2"):
        raise ValueError("bad option")
    if cfg.jmin > cfg.jmax:
        raise ValueError("jmin must be <= jmax")
    return cfg


class H(BaseHTTPRequestHandler):
    server_version = "warp-web"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "[::1]")

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "{}")
        path = self.path.split("?")[0]
        if path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if path == "/api/status":
            with LOCK:
                d = {k: S[k] for k in ("state", "stage", "done", "total", "alive",
                                       "logs", "result", "error")}
            return self._send(200, json.dumps(d))
        if path.startswith("/api/file/"):
            name = path[len("/api/file/"):]
            with LOCK:
                files = dict(S["files"])
            if name.endswith(".zip") and files:
                prefix = name[:-4]
                data = w.make_zip(files, None if prefix == "warp_configs" else prefix)
                return self._send(200, data, "application/zip", {
                    "Content-Disposition": f'attachment; filename="{prefix}.zip"'})
            if name in files:
                ctype = "application/json" if name.endswith(".json") else "text/plain"
                extra = ({"Content-Disposition": f'attachment; filename="{name.split("/")[-1]}"'}
                         if "dl=1" in self.path else None)
                return self._send(200, files[name], ctype + "; charset=utf-8", extra)
        return self._send(404, "{}")

    def do_POST(self):
        if not self._host_ok() or self.headers.get("Origin") not in (
                None, f"http://{self.headers.get('Host')}"):
            return self._send(403, "{}")
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, '{"error":"bad json"}')
        if self.path == "/api/start":
            try:
                cfg = parse_cfg(body)
                if cfg.single + cfg.wow + cfg.amnezia + cfg.masque + cfg.mom + cfg.gool <= 0:
                    raise ValueError("Turn on at least one config type.")
            except (ValueError, TypeError) as e:
                return self._send(400, json.dumps({"error": str(e)}))
            with LOCK:
                if S["state"] == "running":
                    return self._send(409, '{"error":"already running"}')
                cancel = threading.Event()
                S.update(state="running", stage="starting", done=0, total=0,
                         alive=0, logs=[], result=None, files={}, error="",
                         cancel=cancel)
            threading.Thread(target=job, args=(cfg, cancel), daemon=True).start()
            return self._send(200, "{}")
        if self.path == "/api/stop":
            with LOCK:
                if S["cancel"] is not None:
                    S["cancel"].set()
            return self._send(200, "{}")
        return self._send(404, "{}")


ICON = "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"

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Duck Scanner</title>
<link rel="icon" href="data:image/png;base64,__ICON__">
<style>
:root{--bg:#f4f6fb;--card:#fff;--ink:#14181f;--mute:#667085;--line:#e4e8f0;--acc:#f6821f;--acc2:#ff9d4d;
--ok:#16a34a;--bad:#dc2626;--inp:#f8fafc;--shadow:0 1px 2px rgba(16,24,40,.06),0 8px 24px rgba(16,24,40,.06)}
:root[data-theme=dark]{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--mute:#8b98a9;--line:#262d38;--inp:#0f141b;
--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.3)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:center;gap:14px;padding:18px 28px;max-width:1180px;margin:0 auto}
.logo{width:42px;height:42px;border-radius:11px;box-shadow:0 4px 12px rgba(246,130,31,.35)}
h1{font-size:19px;margin:0}header p{margin:0;color:var(--mute);font-size:13px}
.sp{flex:1}
button{font:inherit;cursor:pointer}
.ghost{background:var(--card);border:1px solid var(--line);color:var(--ink);border-radius:10px;padding:7px 12px}
main{display:grid;grid-template-columns:minmax(0,430px) minmax(0,1fr);gap:20px;max-width:1180px;margin:0 auto;padding:0 28px 40px}
main>section{min-width:0}
@media(max-width:900px){main{grid-template-columns:minmax(0,1fr);padding:0 16px 32px}header{padding:16px}}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 18px 16px;box-shadow:var(--shadow);margin-bottom:16px}
.card h2{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--mute);margin:0 0 12px;display:flex;align-items:center;gap:8px}
.row{display:flex;gap:10px;align-items:center;margin:8px 0}
.row label{flex:1}.row label.sw{flex:none}.row small,.hint{color:var(--mute);font-size:12.5px}
.hint{margin:8px 0 0}
input[type=number],input[type=text],select{background:var(--inp);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:8px 10px;font:inherit;min-width:0}
input[type=number]{width:84px;text-align:right}
input:focus,select:focus{outline:2px solid var(--acc);outline-offset:0;border-color:transparent}
.seg{display:flex;background:var(--inp);border:1px solid var(--line);border-radius:12px;padding:3px;gap:3px}
.seg button{flex:1;border:0;background:none;color:var(--mute);padding:8px 6px;border-radius:9px;font-weight:600}
.seg button.on{background:var(--card);color:var(--ink);box-shadow:0 1px 3px rgba(0,0,0,.15)}
.seg.off{opacity:.45;pointer-events:none}
.sw{position:relative;width:42px;height:24px}
.sw input{opacity:0;width:0;height:0;position:absolute}.sw span{position:absolute;inset:0;background:var(--line);border-radius:99px;transition:.2s;cursor:pointer}
.sw span:before{content:"";position:absolute;left:3px;top:3px;width:18px;height:18px;background:#fff;border-radius:50%;transition:.2s}
.sw input:checked+span{background:var(--acc)}.sw input:checked+span:before{transform:translateX(18px)}
.sw input:focus-visible+span{outline:2px solid var(--acc);outline-offset:2px}
.type{display:flex;gap:12px;align-items:center;padding:9px 0;border-top:1px solid var(--line)}
.type:first-of-type{border-top:0}
.type .nm{flex:1;min-width:0}.type .nm b{display:block;font-weight:600}.type .nm small{color:var(--mute);font-size:12px}
.type.off .nm,.type.off input[type=number]{opacity:.45}
.badge.g{background:rgba(22,163,74,.14);color:var(--ok)}.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;background:rgba(246,130,31,.15);color:var(--acc);text-transform:none;letter-spacing:0}
.total{display:flex;justify-content:space-between;margin-top:10px;padding-top:10px;border-top:1px dashed var(--line);font-weight:600}
details summary{cursor:pointer;color:var(--mute);font-weight:600;font-size:13px;margin-bottom:6px}
.actions{display:flex;gap:10px}
.btn{flex:1;border:0;border-radius:12px;padding:12px 16px;font-weight:700;color:#fff;background:linear-gradient(135deg,var(--acc),var(--acc2));box-shadow:0 6px 16px rgba(246,130,31,.35)}
.btn:disabled{opacity:.5;box-shadow:none;cursor:not-allowed}
.btn.stop{flex:none;background:var(--card);color:var(--bad);border:1px solid var(--line);box-shadow:none}
.bar{height:10px;background:var(--inp);border-radius:99px;overflow:hidden;margin:14px 0 6px;border:1px solid var(--line)}
.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--acc),var(--acc2));transition:width .3s}
.stat{display:flex;justify-content:space-between;color:var(--mute);font-size:13px}
pre#log:empty{display:none}
pre#log{margin:12px 0 0;background:#0b0f14;color:#b8c4d4;border-radius:12px;padding:12px;height:150px;overflow:auto;font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap}
.err{background:rgba(220,38,38,.1);color:var(--bad);border-radius:10px;padding:10px 12px;margin-top:12px;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px}
.tile{background:var(--inp);border:1px solid var(--line);border-radius:12px;padding:10px 12px}
.tile b{display:block;font-size:20px}.tile span{color:var(--mute);font-size:12px}
.file{display:flex;align-items:center;gap:10px;padding:10px 0;border-top:1px solid var(--line)}
.file:first-of-type{border-top:0}.file div{flex:1;min-width:0}.file b{display:block}.file small{color:var(--mute)}
.file button{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:9px;padding:6px 11px;font-weight:600}
.file button.p{background:var(--acc);border-color:var(--acc);color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mute);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;border-bottom:1px solid var(--line);font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.t{font-family:inherit;font-weight:700;font-size:11px;padding:2px 8px;border-radius:99px}
.t.single{background:rgba(59,130,246,.15);color:#3b82f6}.t.wow{background:rgba(168,85,247,.15);color:#a855f7}.t.amnezia{background:rgba(246,130,31,.15);color:var(--acc)}
.t.masque{background:rgba(20,184,166,.15);color:#14b8a6}.t.gool{background:rgba(234,179,8,.18);color:#ca8a04}.t.mom{background:rgba(236,72,153,.15);color:#ec4899}
.scroll{max-height:320px;overflow:auto}
.warn{background:rgba(234,179,8,.12);border:1px solid rgba(234,179,8,.4);border-radius:12px;padding:10px 12px;margin:0 0 12px;font-size:13px}.warn code{word-break:break-word;font-size:12px}
code{background:var(--inp);padding:1px 5px;border-radius:6px}
ol{margin:0;padding-left:20px;color:var(--mute)}ol b{color:var(--ink)}
.hide{display:none!important}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(20px);background:#111827;color:#fff;padding:10px 16px;border-radius:12px;opacity:0;transition:.25s;pointer-events:none}
.toast.show{opacity:1;transform:translateX(-50%)}
</style>
</head>
<body>
<header>
  <img class="logo" alt="" src="data:image/png;base64,__ICON__">
  <div><h1>Duck Scanner</h1><p>Find clean Cloudflare WARP endpoints and build configs for your apps</p></div>
  <div class="sp"></div>
  <button class="ghost" id="theme">Theme</button>
</header>
<main>
<section>
  <div class="card">
    <h2>Registration proxy</h2>
    <div class="row"><label for="use_proxy">Use a proxy to create the WARP accounts</label>
      <label class="sw"><input type="checkbox" id="use_proxy" checked><span></span></label></div>
    <div id="proxybox">
      <div class="row">
        <select id="proxy_type"><option value="socks5">SOCKS5</option><option value="http">HTTP</option></select>
        <input type="text" id="proxy_host" value="127.0.0.1" style="flex:1">
        <input type="number" id="proxy_port" value="10808" style="width:96px">
      </div>
      <p class="hint">Used only to create the accounts. The scan itself always goes direct. Default is v2rayN's SOCKS port.</p>
    </div>
  </div>

  <div class="card">
    <h2>IP version</h2>
    <div class="seg" id="stack">
      <button data-v="v4" class="on">IPv4</button><button data-v="v6">IPv6</button><button data-v="dual">Dual stack</button>
    </div>
    <p class="hint">Which endpoint addresses to scan and use. IPv6 needs working IPv6 on this PC.</p>
  </div>

  <div class="card">
    <h2>Config types</h2>
    <div class="type" data-t="single"><label class="sw"><input type="checkbox" id="en_single" checked><span></span></label>
      <div class="nm"><b>Single WARP</b><small>WireGuard · Hiddify, Xray, WireGuard app</small></div><input type="number" id="single" min="0" value="25"></div>
    <div class="type" data-t="wow"><label class="sw"><input type="checkbox" id="en_wow" checked><span></span></label>
      <div class="nm"><b>WARP on WARP</b><small>Two accounts · Hiddify</small></div><input type="number" id="wow" min="0" value="5"></div>
    <div class="type" data-t="amnezia"><label class="sw"><input type="checkbox" id="en_amnezia" checked><span></span></label>
      <div class="nm"><b>Amnezia</b><small>AmneziaWG .conf files</small></div><input type="number" id="amnezia" min="0" value="20"></div>
    <div class="type" data-t="masque"><label class="sw"><input type="checkbox" id="en_masque" checked><span></span></label>
      <div class="nm"><b>MASQUE</b><small>What the 1.1.1.1 app uses · OneXray, Xray</small></div><input type="number" id="masque" min="0" value="10"></div>
    <div class="type" data-t="mom"><label class="sw"><input type="checkbox" id="en_mom"><span></span></label>
      <div class="nm"><b>MASQUE on MASQUE</b> <span class="badge">experimental</span><small>Two MASQUE accounts · OneXray, Xray</small></div><input type="number" id="mom" min="0" value="5"></div>
    <div class="type" data-t="gool"><label class="sw"><input type="checkbox" id="en_gool"><span></span></label>
      <div class="nm"><b>WARP over MASQUE (gool)</b><small>WireGuard carried inside MASQUE · OneXray, Xray</small></div><input type="number" id="gool" min="0" value="5"></div>
    <div class="total"><span>Endpoints to find</span><span id="sum">50</span></div>
    <details style="margin-top:12px"><summary>Amnezia settings</summary>
      <div class="row"><label>Jc (junk packets)</label><input type="number" id="jc" value="4"></div>
      <div class="row"><label>Jmin</label><input type="number" id="jmin" value="40"></div>
      <div class="row"><label>Jmax</label><input type="number" id="jmax" value="70"></div>
    </details>
  </div>

  <div class="card">
    <h2>MASQUE transport</h2>
    <div class="seg" id="transport">
      <button data-v="h3" class="on">HTTP/3</button><button data-v="h2">HTTP/2</button>
    </div>
    <div class="row" style="margin-top:12px"><label for="masque_fragment">Fragment the TLS hello on HTTP/2 <small>(helps on filtered networks)</small></label>
      <label class="sw"><input type="checkbox" id="masque_fragment" checked><span></span></label></div>
    <div class="row" style="margin-top:6px"><label for="baseline">Also list the standard endpoint on every port <small>(recommended)</small></label>
      <label class="sw"><input type="checkbox" id="baseline" checked><span></span></label></div>
    <p class="hint"><b>HTTP/3</b> (QUIC, UDP) is what the 1.1.1.1 app tries first. It falls back to <b>HTTP/2</b> (TCP) when HTTP/3 is blocked, so pick HTTP/2 here for networks that block UDP. Needs Xray-core 26.9.30 or newer.</p>
  </div>

  <div class="card">
    <h2>Test with Xray <span class="badge">optional</span></h2>
    <div class="row"><input type="text" id="xray_path" placeholder="Path to xray.exe (blank = skip the test)" style="flex:1"></div>
    <div class="row"><label>Endpoints to test</label><input type="number" id="xray_verify" min="0" value="12"></div>
    <p class="hint">Runs your own Xray on each Xray config and opens a real connection through it. Only endpoints that work are kept, and failures show Xray's exact error. v2rayN keeps its copy in <code>bin\xray\xray.exe</code>. Leave the path blank to skip.</p>
  </div>

  <div class="card">
    <details><summary>Advanced scan settings</summary>
      <div class="row"><label>Endpoints to try</label><input type="number" id="candidates" value="4000" step="500"></div>
      <div class="row"><label>Verify rounds</label><input type="number" id="probes" value="3"></div>
      <div class="row"><label>Timeout (s)</label><input type="number" id="timeout" value="1.5" step="0.5"></div>
      <div class="row"><label>Parallel probes</label><input type="number" id="workers" value="200" step="50"></div>
    </details>
  </div>
</section>

<section>
  <div class="card">
    <h2>Scan</h2>
    <div class="actions">
      <button class="btn" id="start">Start scan</button>
      <button class="btn stop hide" id="stop">Stop</button>
    </div>
    <div class="bar"><i id="fill"></i></div>
    <div class="stat"><span id="stage">Ready</span><span id="count"></span></div>
    <div class="err hide" id="err"></div>
    <pre id="log"></pre>
  </div>

  <div class="card hide" id="results">
    <h2>Results</h2>
    <div class="tiles">
      <div class="tile"><b id="t_found">0</b><span>endpoints found</span></div>
      <div class="tile"><b id="t_best">-</b><span>best latency</span></div>
      <div class="tile"><b id="t_acc">0</b><span>WARP accounts</span></div>
    </div>
    <div class="warn hide" id="xnote"></div>
    <div id="files"></div>
    <details style="margin-top:12px"><summary>Endpoints</summary>
      <div class="scroll"><table><thead><tr><th>Tag</th><th>Type</th><th>Endpoint</th><th>ms</th><th>OK</th><th>Xray</th></tr></thead><tbody id="rows"></tbody></table></div>
    </details>
  </div>

  <div class="card">
    <h2>Which file goes where</h2>
    <ol><li><b>OneXray</b> (iPhone, Mac, Windows, Android): Connect → expert mode → Raw JSON → import. This is the MASQUE one.</li>
    <li><b>Hiddify</b>: copy the JSON, then + → Add from clipboard. Single WARP and WARP-on-WARP only; Hiddify has no MASQUE and can't read Xray files.</li>
    <li><b>Xray</b>: <code>xray run -c warp_xray_auto.json</code>, then SOCKS5 127.0.0.1:10808.</li>
    <li><b>AmneziaWG</b> / <b>WireGuard</b>: import the .conf files.</li></ol>
  </div>
</section>
</main>
<div class="toast" id="toast"></div>
<script>
const $ = id => document.getElementById(id);
const TYPES = ["single","wow","amnezia","masque","mom","gool"];
const NUM = ["proxy_port","jc","jmin","jmax","candidates","probes","timeout","workers","xray_verify"];
const OTHER = ["use_proxy","proxy_type","proxy_host","masque_fragment","baseline","xray_path"];
let stack = "v4", transport = "h3", timer = null, shown = "";
const ROWS = {
  "onexray/onexray_raw.json":["OneXray (iPhone and PC)","Raw JSON · Connect → expert mode → Raw JSON → import",true],
  "onexray/onexray_raw_alt_sni.json":["OneXray · alternative TLS name","Only if the first one won't connect",false]};
const APPS = {
  hiddify:["Hiddify","Single WARP + WARP-on-WARP · Copy, then + → Add from clipboard"],
  xray:["Xray (plain)","Complete config · run with xray.exe · picks the fastest endpoint"],
  xray_endpoints:["Xray · one file per endpoint","The same config, one endpoint per file"],
  amnezia:["AmneziaWG","Import each .conf in the AmneziaWG app"],
  wireguard:["WireGuard","Official app · import the .zip"]};

function toast(m){const t=$("toast");t.textContent=m;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),1800)}
function setSeg(id,v){document.querySelectorAll("#"+id+" button").forEach(b=>b.classList.toggle("on",b.dataset.v===v))}
function refresh(){
  let s=0;
  TYPES.forEach(k=>{const on=$("en_"+k).checked;document.querySelector(`.type[data-t=${k}]`).classList.toggle("off",!on);if(on)s+=(+$(k).value||0)});
  $("sum").textContent=s;
  $("transport").classList.toggle("off",!($("en_masque").checked||$("en_mom").checked||$("en_gool").checked));
  $("proxybox").classList.toggle("hide",!$("use_proxy").checked);
}
function collect(){
  const d={stack,masque_transport:transport};
  TYPES.forEach(k=>{d[k]=$("en_"+k).checked?(+$(k).value||0):0;d["en_"+k]=$("en_"+k).checked;d["n_"+k]=+$(k).value||0});
  NUM.forEach(i=>d[i]=Number($(i).value));
  OTHER.forEach(i=>{const e=$(i);d[i]=e.type==="checkbox"?e.checked:e.value});
  return d;
}
function save(){try{localStorage.setItem("warp_cfg5",JSON.stringify(collect()))}catch(e){}}
function load(){
  try{const d=JSON.parse(localStorage.getItem("warp_cfg5")||"{}");
    TYPES.forEach(k=>{if("en_"+k in d)$("en_"+k).checked=d["en_"+k];if("n_"+k in d)$(k).value=d["n_"+k]});
    NUM.forEach(i=>{if(i in d)$(i).value=d[i]});
    OTHER.forEach(i=>{if(!(i in d))return;const e=$(i);if(e.type==="checkbox")e.checked=d[i];else e.value=d[i]});
    if(d.stack){stack=d.stack;setSeg("stack",stack)}
    if(d.masque_transport){transport=d.masque_transport;setSeg("transport",transport)}}catch(e){}
  refresh();
}
async function api(path,body){
  const r=await fetch(path,body===undefined?{}:{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  return {ok:r.ok,data:await r.json().catch(()=>({}))};
}
async function start(){
  const r=await api("/api/start",collect());
  if(!r.ok){showErr(r.data.error||"Could not start");return}
  showErr("");$("results").classList.add("hide");poll();
}
function showErr(m){const e=$("err");e.textContent=m;e.classList.toggle("hide",!m)}
async function poll(){
  clearTimeout(timer);
  const {data:s}=await api("/api/status");
  const run=s.state==="running";
  $("start").disabled=run;$("stop").classList.toggle("hide",!run);
  $("stage").textContent=run?(s.stage||"starting"):({idle:"Ready",done:"Finished",cancelled:"Cancelled",error:"Failed"}[s.state]||"");
  $("count").textContent=run&&s.total?`${s.done}/${s.total} · ${s.alive} alive`:"";
  $("fill").style.width=(s.state==="done"?100:(s.total?Math.round(100*s.done/s.total):0))+"%";
  const txt=s.logs.join("\n");if(txt!==shown){shown=txt;const l=$("log");l.textContent=txt;l.scrollTop=l.scrollHeight}
  if(s.state==="error")showErr(s.error);
  if(s.state==="done"&&s.result)render(s.result);
  if(run)timer=setTimeout(poll,600);
}
function fileRow(title,hint,btns){
  const d=document.createElement("div");d.className="file";
  const t=document.createElement("div");const b=document.createElement("b");b.textContent=title;
  const s=document.createElement("small");s.textContent=hint;t.append(b,s);d.append(t,...btns);return d;
}
function btn(label,fn,primary){const b=document.createElement("button");b.textContent=label;if(primary)b.className="p";b.onclick=fn;return b}
function copyFile(n){return async()=>{const t=await (await fetch("/api/file/"+n)).text();
  try{await navigator.clipboard.writeText(t);toast("Copied "+n.split("/").pop())}catch(e){toast("Copy blocked - use Download")}}}
function render(r){
  $("results").classList.remove("hide");
  $("t_found").textContent=r.found+(r.found<r.wanted?" / "+r.wanted:"");
  const rtts=r.endpoints.map(e=>e.rtt);$("t_best").textContent=rtts.length?Math.min(...rtts)+" ms":"-";
  $("t_acc").textContent=r.registered;
  const box=$("files");box.innerHTML="";
  const groups={};Object.keys(r.files).forEach(n=>{const p=n.split("/");(groups[p.length>1?p[0]:"_"]=groups[p.length>1?p[0]:"_"]||[]).push(n)});
  Object.keys(ROWS).forEach(n=>{if(!r.files[n])return;const [t,h,p]=ROWS[n];
    box.append(fileRow(t,h,[btn("Copy",copyFile(n),p),btn("Download",()=>location.href="/api/file/"+n+"?dl=1")]))});
  ["hiddify","xray","xray_endpoints","amnezia","wireguard"].forEach(g=>{
    const f=groups[g];if(!f)return;const [title,hint]=APPS[g];
    if(f.length===1){const isJson=f[0].endsWith(".json");
      box.append(fileRow(title,hint,[btn("Copy",copyFile(f[0]),false),btn("Download",()=>location.href="/api/file/"+f[0]+"?dl=1")]))}
    else box.append(fileRow(title,f.length+" files · "+hint,[btn("Download .zip",()=>location.href="/api/file/"+g+".zip")]))});
  box.append(fileRow("Everything","All folders + README",[btn("Download .zip",()=>location.href="/api/file/warp_configs.zip")]));
  const L={single:"WARP",wow:"WoW",amnezia:"Amnezia",masque:"MASQUE",mom:"MoM",gool:"GOOL"};
  $("rows").innerHTML=r.endpoints.map(e=>`<tr><td>${e.tag||"-"}</td><td><span class="t ${e.type}">${L[e.type]}${e.proto?" · "+e.proto.toUpperCase():""}</span></td><td>${e.ip.includes(":")?"["+e.ip+"]":e.ip}:${e.port}</td><td>${e.rtt}</td><td>${Math.round(e.success*100)}%</td><td title="${(e.note||"").replace(/"/g,"'")}">${e.xray==="ok"?"✓":e.xray==="fail"?"✗":"–"}</td></tr>`).join("");
  const tested=r.endpoints.filter(e=>e.xray),okc=tested.filter(e=>e.xray==="ok").length,x=$("xnote");
  if(tested.length&&!okc){const m=(tested.find(e=>e.note)||{}).note||"";
    x.innerHTML="<b>None of the "+tested.length+" tested endpoints connected.</b> Xray said:<br><code></code><br>Usual causes: Xray-core older than 26.9.30 (update it), a blocked network, or try HTTP/3.";
    x.querySelector("code").textContent=m;x.classList.remove("hide")}
  else if(tested.length){x.textContent="Xray test: "+okc+" of "+tested.length+" endpoints connected. Only those are in the Xray files.";x.classList.remove("hide")}
  else x.classList.add("hide");
}
document.querySelectorAll("#stack button").forEach(b=>b.onclick=()=>{stack=b.dataset.v;setSeg("stack",stack);save()});
document.querySelectorAll("#transport button").forEach(b=>b.onclick=()=>{transport=b.dataset.v;setSeg("transport",transport);save()});
[...TYPES.map(k=>"en_"+k),...TYPES,...NUM,...OTHER].forEach(i=>$(i).addEventListener("input",()=>{save();refresh()}));
$("start").onclick=start;$("stop").onclick=()=>api("/api/stop",{});
$("theme").onclick=()=>{const r=document.documentElement;const d=r.dataset.theme==="dark"?"light":"dark";r.dataset.theme=d;try{localStorage.setItem("warp_theme",d)}catch(e){}};
(function(){let t=null;try{t=localStorage.getItem("warp_theme")}catch(e){}
  document.documentElement.dataset.theme=t||(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light")})();
load();poll();
</script>
</body>
</html>
""".replace("__ICON__", ICON)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    srv = None
    for port in range(a.port, a.port + 10):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), H)
            break
        except OSError:
            continue
    if srv is None:
        sys.exit("Could not open a local port (8765-8774 are all busy).")
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    print(f"Duck Scanner is running at {url}")
    print("Keep this window open while you use it. Close it (or press Ctrl+C) to quit.")
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
