#!/usr/bin/env python3
"""
warp_scan.py (Duck Scanner) - scan Cloudflare WARP endpoints with a real WireGuard handshake
and build configs for several apps (Hiddify, Xray/v2rayN, AmneziaWG, WireGuard).

    pip install cryptography
    python warp_scan.py --single 25 --wow 5 --amnezia 20 --masque 10
    python warp_web.py            # same thing, with a web interface
"""
import argparse
import base64
import collections
import copy
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import random
import shutil
import subprocess
import tempfile
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_der_public_key)


class Cancelled(Exception):
    pass


# --------------------------------------------------------------------------
# Cloudflare WARP constants
# --------------------------------------------------------------------------
PEER_PUBLIC_KEY = base64.b64decode("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")

V4_RANGES = ["162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24",
             "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24",
             "188.114.99.0/24"]

WARP_PORTS = [
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074,
    1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
    4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742,
    8854, 8886]

# --------------------------------------------------------------------------
# WireGuard handshake initiation (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)
# --------------------------------------------------------------------------
CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"


def _hash(data: bytes) -> bytes:
    return hashlib.blake2s(data).digest()


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def _kdf1(c: bytes, data: bytes) -> bytes:
    return _hmac(_hmac(c, data), b"\x01")


def _kdf2(c: bytes, data: bytes):
    prk = _hmac(c, data)
    t1 = _hmac(prk, b"\x01")
    t2 = _hmac(prk, t1 + b"\x02")
    return t1, t2


def _raw_pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _dh(priv: X25519PrivateKey, pub: bytes) -> bytes:
    return priv.exchange(X25519PublicKey.from_public_bytes(pub))


def _tai64n() -> bytes:
    t = time.time()
    sec = int(t)
    nano = int((t - sec) * 1e9)
    return struct.pack(">QI", 0x400000000000000a + sec, nano)


def build_initiation(static_priv_raw: bytes, peer_pub: bytes = PEER_PUBLIC_KEY):
    """Return (148-byte initiation packet, sender_index)."""
    s_priv = X25519PrivateKey.from_private_bytes(static_priv_raw)
    s_pub = _raw_pub(s_priv)
    e_priv = X25519PrivateKey.generate()
    e_pub = _raw_pub(e_priv)
    sender = os.urandom(4)

    c = _hash(CONSTRUCTION)
    h = _hash(c + IDENTIFIER)
    h = _hash(h + peer_pub)

    c = _kdf1(c, e_pub)
    h = _hash(h + e_pub)

    c, k = _kdf2(c, _dh(e_priv, peer_pub))
    enc_static = ChaCha20Poly1305(k).encrypt(b"\x00" * 12, s_pub, h)
    h = _hash(h + enc_static)

    c, k = _kdf2(c, _dh(s_priv, peer_pub))
    enc_ts = ChaCha20Poly1305(k).encrypt(b"\x00" * 12, _tai64n(), h)

    body = b"\x01\x00\x00\x00" + sender + e_pub + enc_static + enc_ts
    mac1_key = _hash(LABEL_MAC1 + peer_pub)
    mac1 = hashlib.blake2s(body, digest_size=16, key=mac1_key).digest()
    return body + mac1 + b"\x00" * 16, sender


def probe(ip: str, port: int, static_priv_raw: bytes, timeout: float):
    """Send one handshake initiation. Return RTT in ms, or None."""
    pkt, sender = build_initiation(static_priv_raw)
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        t0 = time.perf_counter()
        s.send(pkt)
        data = s.recv(512)
        rtt = (time.perf_counter() - t0) * 1000
        # handshake response: type 2, 92 bytes, receiver index == our sender
        if len(data) == 92 and data[0] == 2 and data[8:12] == sender:
            return rtt
    except OSError:
        pass
    finally:
        s.close()
    return None


# --------------------------------------------------------------------------
# HTTPS (optionally through a SOCKS5 / HTTP proxy) and WARP registration
# --------------------------------------------------------------------------
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(x: str) -> bytes:
    return base64.b64decode(x + "=" * (-len(x) % 4))


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("proxy closed connection")
        buf += chunk
    return buf


def _socks5_connect(proxy_host, proxy_port, host, port, timeout):
    """Minimal SOCKS5 CONNECT (no auth, hostname resolved by the proxy)."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if _recv_exact(s, 2) != b"\x05\x00":
            raise OSError("SOCKS5 proxy refused no-auth")
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h
                  + struct.pack(">H", port))
        ver, rep, _, atyp = _recv_exact(s, 4)
        if rep != 0:
            raise OSError(f"SOCKS5 connect failed (code {rep})")
        skip = {1: 4, 4: 16}.get(atyp)
        if skip is None:
            skip = _recv_exact(s, 1)[0]
        _recv_exact(s, skip + 2)
        return s
    except Exception:
        s.close()
        raise


def _https(method, host, path, body, headers, proxy, timeout=20):
    """HTTPS request, optionally through socks5://h:p or http://h:p."""
    ctx = ssl.create_default_context()
    if proxy and proxy.scheme in ("socks5", "socks5h", "socks"):
        raw = _socks5_connect(proxy.hostname, proxy.port, host, 443, timeout)
        conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
        conn.sock = ctx.wrap_socket(raw, server_hostname=host)
    elif proxy:  # http proxy -> CONNECT tunnel
        conn = http.client.HTTPSConnection(proxy.hostname, proxy.port,
                                           timeout=timeout, context=ctx)
        conn.set_tunnel(host, 443)
    else:
        conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
    try:
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


API_HOST = "api.cloudflareclient.com"
API_WG = ("/v0a1922", {"User-Agent": "okhttp/3.12.1",
                       "CF-Client-Version": "a-6.3-1922"})
API_MASQUE = ("/v0a4471", {"User-Agent": "WARP for Android",
                           "CF-Client-Version": "a-6.35-4471"})


def _parse_account(j) -> dict:
    cfg = j["config"]
    return {"id": j.get("id"), "token": j.get("token"),
            "v4": cfg["interface"]["addresses"]["v4"],
            "v6": cfg["interface"]["addresses"].get("v6"),
            "reserved": list(_b64d(cfg["client_id"])[:3]) if cfg.get("client_id") else [0, 0, 0],
            "peer_public_key": cfg["peers"][0]["public_key"]}


def register_warp(pub_b64: str, proxy=None, log=print, api=API_WG, android=False):
    """Register a free WARP device. Returns account dict or None."""
    prefix, hdr = api
    data = {"install_id": "", "fcm_token": "", "key": pub_b64,
            "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "type": "Android", "model": "PC", "locale": "en_US"}
    if android:          # what usque sends: random serial + explicit key/tunnel type
        data.update({"serial_number": os.urandom(8).hex(),
                     "key_type": "curve25519", "tunnel_type": "wireguard"})
    body = json.dumps(data).encode()
    headers = {"Content-Type": "application/json", **hdr}
    try:
        status, raw = _https("POST", API_HOST, f"{prefix}/reg", body, headers, proxy)
        if not 200 <= status < 300:
            log(f"[!] WARP registration returned HTTP {status}")
            return None
        return _parse_account(json.loads(raw))
    except Exception as e:  # noqa: BLE001
        log(f"[!] WARP registration failed ({e})")
        return None


def enroll_masque(acct: dict, ec_pub_b64: str, proxy=None, log=print) -> bool:
    """Attach a P-256 MASQUE key to a registered device (what `usque enroll` does)."""
    prefix, hdr = API_MASQUE
    body = json.dumps({"key": ec_pub_b64, "key_type": "secp256r1",
                       "tunnel_type": "masque", "name": "warp-scanner"}).encode()
    headers = {"Content-Type": "application/json; charset=UTF-8",
               "Authorization": f"Bearer {acct['token']}", **hdr}
    try:
        status, raw = _https("PATCH", API_HOST, f"{prefix}/reg/{acct['id']}",
                             body, headers, proxy)
        if not 200 <= status < 300:
            log(f"[!] MASQUE enrollment returned HTTP {status}")
            return False
        try:
            j = json.loads(raw)
            acct.update(_parse_account(j))
            acct["edge_public_key"] = j["config"]["peers"][0].get("public_key")
            if j.get("warp_enabled") is False:       # Xray: access denied otherwise
                _https("PATCH", API_HOST, f"{prefix}/reg/{acct['id']}",
                       json.dumps({"warp_enabled": True}).encode(), headers, proxy)
        except Exception:  # noqa: BLE001  (response shape differs: keep what we have)
            pass
        return True
    except Exception as e:  # noqa: BLE001
        log(f"[!] MASQUE enrollment failed ({e})")
        return False


def _new_key() -> dict:
    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return {"private_key": _b64(raw), "public_key": _b64(_raw_pub(priv)),
            "account": None}


def create_masque_account(proxy, log=print):
    """New device + P-256 key enrolled for MASQUE. Separate from the WireGuard
    accounts, because enrolling switches that device away from WireGuard."""
    key = ec.generate_private_key(ec.SECP256R1())
    priv = _b64(key.private_bytes(Encoding.DER, PrivateFormat.TraditionalOpenSSL,
                                  NoEncryption()))          # SEC1, like Xray's docs
    pub = _b64(key.public_key().public_bytes(Encoding.DER,
                                             PublicFormat.SubjectPublicKeyInfo))
    wg = _new_key()
    acct = (register_warp(wg["public_key"], proxy, log, API_MASQUE, android=True)
            or register_warp(wg["public_key"], proxy, log, API_WG))
    if not acct or not enroll_masque(acct, pub, proxy, log):
        return None
    return {"ec_private_key": priv, "ec_public_key": pub, "account": acct}


def default_identity_path() -> str:
    if getattr(sys, "frozen", False):          # packaged .exe: per-user data dir
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Duck-Scanner")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "warp_identity.json")
    return "warp_identity.json"


def load_identities(path, need_wg, need_masque, proxy, log=print):
    """-> (wireguard identities, masque identities); creates what is missing."""
    data = {}
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
    wg = data.get("accounts")
    if wg is None and data.get("private_key"):             # v1 file format
        wg = [{"private_key": data["private_key"], "public_key": data["public_key"],
               "account": data.get("account")}]
    wg = [a for a in (wg or []) if a.get("account")]
    ms = [m for m in (data.get("masque") or []) if m.get("account")]
    first = True
    while len(wg) < need_wg:
        if not first:
            time.sleep(1.0)                                # be gentle with the API
        first = False
        log("[i] registering a WireGuard WARP account ...")
        a = _new_key()
        a["account"] = register_warp(a["public_key"], proxy, log)
        if not a["account"]:
            break
        wg.append(a)
    while len(ms) < need_masque:
        if not first:
            time.sleep(1.0)
        first = False
        log("[i] registering a MASQUE WARP account ...")
        m = create_masque_account(proxy, log)
        if not m:
            break
        ms.append(m)
    with open(path, "w") as f:
        json.dump({"accounts": wg, "masque": ms}, f)
    return wg[:need_wg], ms[:need_masque]


# --------------------------------------------------------------------------
# WireGuard endpoint scan
# --------------------------------------------------------------------------
def _v4_hosts():
    out = []
    for cidr in V4_RANGES:
        out += [str(h) for h in ipaddress.ip_network(cidr).hosts()]
    return out


def _v6_hosts():
    """WARP v6 endpoints embed the v4 address: 2606:4700:d0::a29f:c001."""
    out = []
    for h in _v4_hosts():
        a, b, c, d = (int(x) for x in h.split("."))
        for k in (0, 1):
            out.append(f"2606:4700:d{k}::{a:02x}{b:02x}:{c:02x}{d:02x}")
    return out


def _sample(pools, ports, n, rng):
    total = sum(len(p) for p in pools) * len(ports)
    n = min(n, total)
    seen, i = set(), 0
    while len(seen) < n:
        pool = pools[i % len(pools)]
        i += 1
        seen.add((rng.choice(pool), rng.choice(ports)))
    return list(seen)


def candidates(n, ports, rng, stack="v4"):
    pools = []
    if stack in ("v4", "dual"):
        pools.append(_v4_hosts())
    if stack in ("v6", "dual"):
        pools.append(_v6_hosts())
    return _sample(pools, ports, n, rng)


def run_probes(targets, fn, workers, label, progress, cancel):
    """Run fn(target) for every target in parallel. fn returns a value or None."""
    results = {}

    def one(t):
        if cancel is not None and cancel.is_set():
            return None
        try:
            return fn(t)
        except Exception:  # noqa: BLE001
            return None

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [(t, ex.submit(one, t)) for t in targets]
        for t, f in futs:
            results[t] = f.result()
            done += 1
            if done % 50 == 0 or done == len(futs):
                alive = sum(v is not None for v in results.values())
                progress(label, done, len(futs), alive)
    if cancel is not None and cancel.is_set():
        raise Cancelled()
    return results


def _rtt(v):
    return v[0] if isinstance(v, tuple) else v


def verify_and_rank(first, fn, cfg, need, label, progress, cancel):
    """Re-probe the fastest survivors; rank by success ratio, then latency."""
    alive = sorted((t for t, r in first.items() if r is not None),
                   key=lambda t: _rtt(first[t]))
    if not alive:
        return []
    pool = alive[: max(need * 4, 100)]
    stats = {t: [_rtt(first[t])] for t in pool}
    for i in range(cfg.probes):
        res = run_probes(pool, fn, cfg.workers, f"{label}: verify {i + 1}/{cfg.probes}",
                         progress, cancel)
        for t, r in res.items():
            stats[t].append(None if r is None else _rtt(r))
        time.sleep(0.3)
    ranked = []
    for t, rs in stats.items():
        ok = [r for r in rs if r is not None]
        if ok:
            ranked.append((len(ok) / len(rs), sum(ok) / len(ok), t))
    ranked.sort(key=lambda x: (-x[0], x[1]))
    picked, used, rest = [], set(), []
    for ratio, rtt, (ip, port) in ranked:
        (rest if ip in used else picked).append(
            {"ip": ip, "port": port, "rtt": round(rtt, 1), "success": round(ratio, 2)})
        used.add(ip)
    return picked + rest


def scan_endpoints(cfg, need, priv_raw, progress, cancel):
    rng = random.Random(cfg.seed)
    ports = cfg.ports or WARP_PORTS
    fn = lambda t: probe(t[0], t[1], priv_raw, cfg.timeout)  # noqa: E731
    first = run_probes(candidates(cfg.candidates, ports, rng, cfg.stack), fn,
                       cfg.workers, "WireGuard sweep", progress, cancel)
    return verify_and_rank(first, fn, cfg, need, "WireGuard", progress, cancel)[:need]


# --------------------------------------------------------------------------
# MASQUE endpoint scan (HTTP/2 over TCP, HTTP/3 over QUIC)
# --------------------------------------------------------------------------
MASQUE_SNI = "consumer-masque.cloudflareclient.com"
MASQUE_PORTS = [443, 500, 1701, 4443, 4500, 8443, 8095]
MASQUE_DEFAULT_EDGE = {"v4": "162.159.198.2", "v6": "2606:4700:103::2"}


def masque_candidates(n, stack, rng):
    pools = []
    if stack in ("v4", "dual"):
        pools.append([f"162.159.198.{i}" for i in range(1, 255)])
    if stack in ("v6", "dual"):
        pools.append([f"2606:4700:103::{i:x}" for i in range(1, 256)])
    out = set(_sample(pools, MASQUE_PORTS, n, rng))
    out.add((MASQUE_DEFAULT_EDGE["v6" if stack == "v6" else "v4"], 443))
    return list(out)


def _spki_b64(cert_der: bytes) -> str:
    cert = x509.load_der_x509_certificate(cert_der)
    return _b64(cert.public_key().public_bytes(Encoding.DER,
                                               PublicFormat.SubjectPublicKeyInfo))


def probe_h2(ip, port, timeout):
    """TCP + TLS1.3 (ALPN h2) handshake. -> (rtt_ms, edge key b64) or None."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2"])
    t0 = time.perf_counter()
    with socket.create_connection((ip, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=MASQUE_SNI) as ss:
            rtt = (time.perf_counter() - t0) * 1000
            return rtt, _spki_b64(ss.getpeercert(binary_form=True))


def probe_h3(ip, port, timeout):
    """QUIC reachability: an unknown-version Initial must draw a Version
    Negotiation packet. -> rtt_ms or None."""
    dcid, scid = os.urandom(8), os.urandom(8)
    pkt = (bytes([0xC0 | (os.urandom(1)[0] & 0x0F)]) + b"\x1a\x2a\x3a\x4a"
           + bytes([8]) + dcid + bytes([8]) + scid)
    pkt += b"\x00" * (1200 - len(pkt))
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        t0 = time.perf_counter()
        s.send(pkt)
        d = s.recv(2048)
        rtt = (time.perf_counter() - t0) * 1000
        if len(d) >= 7 and d[0] & 0x80 and d[1:5] == b"\x00\x00\x00\x00" \
                and d[5] == 8 and d[6:14] == scid:
            return rtt
    except OSError:
        pass
    finally:
        s.close()
    return None


def _norm_spki(s):
    """Accept PEM or base64 SubjectPublicKeyInfo; return base64 if it is P-256."""
    try:
        s = "".join(l for l in str(s).splitlines() if "-----" not in l).strip()
        k = load_der_public_key(_b64d(s))
        if isinstance(k, ec.EllipticCurvePublicKey) and k.curve.name == "secp256r1":
            return _b64(k.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
    except Exception:  # noqa: BLE001
        pass
    return None


def scan_masque(cfg, need, progress, cancel, log=print, fallback_pin=None):
    """-> (endpoints [{ip,port,rtt,success,proto}], edge pin or None)"""
    rng = random.Random(cfg.seed)
    cands = masque_candidates(min(cfg.candidates, 1500), cfg.stack, rng)
    want_h2 = cfg.masque_transport == "h2"
    want_h3 = cfg.masque_transport == "h3"
    h2 = lambda t: probe_h2(t[0], t[1], cfg.timeout)            # noqa: E731
    h3 = lambda t: probe_h3(t[0], t[1], cfg.timeout)            # noqa: E731

    first2 = run_probes(cands, h2, cfg.workers, "MASQUE HTTP/2 sweep", progress, cancel)
    pins = collections.Counter(v[1] for v in first2.values() if v)
    pin = pins.most_common(1)[0][0] if pins else _norm_spki(fallback_pin or "")
    good2 = {t: v for t, v in first2.items() if v and v[1] == pin}
    if pins:
        log(f"[i] MASQUE edge key read from {sum(pins.values())} endpoint(s)")
    elif pin:
        log("[i] no HTTP/2 endpoint answered - using the key from registration")
    else:
        log("[!] could not read the MASQUE edge key (TCP/443 blocked?)")

    ranked2, ranked3 = [], []
    if want_h2 and good2:
        ranked2 = verify_and_rank(good2, h2, cfg, need, "MASQUE HTTP/2", progress, cancel)
    if want_h3:
        ips_ok = {t[0] for t in good2}
        c3 = [t for t in cands if not ips_ok or t[0] in ips_ok]
        first3 = run_probes(c3, h3, cfg.workers, "MASQUE HTTP/3 sweep", progress, cancel)
        ranked3 = verify_and_rank(first3, h3, cfg, need, "MASQUE HTTP/3", progress, cancel)
    for e in ranked2:
        e["proto"] = "h2"
    for e in ranked3:
        e["proto"] = "h3"
    out = ranked2 if cfg.masque_transport == "h2" else ranked3
    return out[:need], pin


def assign(endpoints, quotas, order):
    """Round-robin the ranked endpoints over the config types."""
    quota = dict(quotas)
    order = [k for k in order if quota.get(k, 0) > 0]
    out, i = [], 0
    for ep in endpoints:
        if not order or not any(quota[k] > 0 for k in order):
            break
        for _ in range(len(order)):
            k = order[i % len(order)]
            i += 1
            if quota[k] > 0:
                quota[k] -= 1
                out.append(dict(ep, type=k))
                break
    return out


# --------------------------------------------------------------------------
# Config + output builders (one folder per client app)
# --------------------------------------------------------------------------
@dataclass
class Config:
    # registration proxy (used ONLY for creating the WARP accounts)
    use_proxy: bool = True
    proxy_type: str = "socks5"          # socks5 | http
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 10808
    stack: str = "v4"                   # v4 | v6 | dual
    # how many of each config (0 = off)
    single: int = 25
    wow: int = 5
    amnezia: int = 20
    masque: int = 0
    mom: int = 0                        # MASQUE on MASQUE
    gool: int = 0                       # WireGuard inside MASQUE
    masque_transport: str = "h3"        # h3 (QUIC, what the 1.1.1.1 app tries first) | h2 (TCP)
    baseline: bool = True               # also list the standard MASQUE endpoint on every port
    masque_fragment: bool = True        # TLS-hello fragment on HTTP/2 (Xray)
    xray_path: str = ""                 # xray(.exe) used to test the Xray configs
    xray_verify: int = 12               # how many endpoints to test
    jc: int = 4
    jmin: int = 40
    jmax: int = 70
    # scan tuning
    candidates: int = 4000
    probes: int = 3
    timeout: float = 1.5
    workers: int = 200
    ports: list = field(default_factory=list)
    seed: int = None
    identity: str = field(default_factory=default_identity_path)


def _addrs(acct):
    return [f"{acct['v4']}/32"] + ([f"{acct['v6']}/128"] if acct.get("v6") else [])


def _fmt_ep(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _hiddify_wg(tag, ip, port, ident, mtu=1280, detour=None):
    a = ident["account"]
    o = {"type": "wireguard", "tag": tag, "server": ip, "server_port": port,
         "local_address": _addrs(a), "private_key": ident["private_key"],
         "peer_public_key": a["peer_public_key"], "reserved": a["reserved"],
         "mtu": mtu}
    if detour:
        o["detour"] = detour
    return o


def _xray_wg(tag, ip, port, ident, mtu=1280):
    a = ident["account"]
    return {"protocol": "wireguard", "tag": tag, "settings": {
        "secretKey": ident["private_key"], "address": _addrs(a),
        "peers": [{"publicKey": a["peer_public_key"],
                   "allowedIPs": ["0.0.0.0/0", "::/0"],
                   "endpoint": _fmt_ep(ip, port)}],
        "reserved": a["reserved"], "mtu": mtu}}


def _xray_masque(tag, ip, port, proto, m, pin, fragment, dialer=None):
    ss = {"method": "masque",
          "masqueSettings": {"warp": {"privateKey": m["ec_private_key"],
                                      "publicKey": pin,
                                      "address": _addrs(m["account"])}},
          "security": "tls",
          "tlsSettings": {"serverName": MASQUE_SNI, "alpn": [proto]}}
    if proto == "h2" and fragment:
        ss["finalmask"] = {"tcp": [{"type": "fragment", "settings": {
            "packets": "tlshello", "lengths": ["10-20"], "delays": ["10-20"]}}]}
    if dialer:
        ss["sockopt"] = {"dialerProxy": dialer}
    return {"protocol": "masque", "tag": tag,
            "settings": {"address": ip, "port": port,
                         "remoteDNS": ["1.1.1.1", "2606:4700:4700::1111"]},
            "streamSettings": ss}


def _wg_conf(ident, endpoint, amnezia=None):
    a = ident["account"]
    lines = ["[Interface]", f"PrivateKey = {ident['private_key']}",
             f"Address = {', '.join(_addrs(a))}",
             "DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001",
             "MTU = 1280"]
    if amnezia:
        lines += [f"Jc = {amnezia['jc']}", f"Jmin = {amnezia['jmin']}",
                  f"Jmax = {amnezia['jmax']}", "S1 = 0", "S2 = 0",
                  "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4"]
    lines += ["", "[Peer]", f"PublicKey = {a['peer_public_key']}",
              "AllowedIPs = 0.0.0.0/0, ::/0", f"Endpoint = {endpoint}", ""]
    return "\n".join(lines)



# --------------------------------------------------------------------------
# Test the Xray configs with a real xray binary (finds out WHY something fails)
# --------------------------------------------------------------------------
def find_xray(user_path=""):
    """Only used when the user gave a path (the test is opt-in)."""
    p = (user_path or "").strip().strip('"')
    if not p:
        return None
    for c in (p, os.path.join(p, "xray.exe"), os.path.join(p, "xray")):
        if os.path.isfile(c):
            return c
    return None


def xray_version(xray):
    try:
        out = subprocess.run([xray, "version"], capture_output=True, text=True,
                             timeout=10, **_nowin()).stdout
        return out.splitlines()[0].strip() if out else ""
    except Exception:  # noqa: BLE001
        return ""


def _nowin():
    return {"creationflags": 0x08000000} if os.name == "nt" else {}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _trace_via_socks(port, host="www.cloudflare.com", tport=443, timeout=10,
                     verify=True):
    """GET /cdn-cgi/trace through the local SOCKS5 proxy -> dict of key=value."""
    raw = _socks5_connect("127.0.0.1", port, host, tport, timeout)
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        s.settimeout(timeout)
        s.sendall(f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\n"
                  "Connection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    body = data.split(b"\r\n\r\n", 1)[-1].decode(errors="replace")
    return dict(l.split("=", 1) for l in body.splitlines() if "=" in l)


def _diag(lines):
    """The most useful line(s) of an xray log, without timestamps/banner."""
    import re
    keys = ("fail", "error", "denied", "refused", "invalid", "unknown", "not support")
    hits = [re.sub(r"^\d{4}/\d\d/\d\d [\d:.]+ ", "", l) for l in lines
            if any(k in l.lower() for k in keys)]
    hits = [re.sub(r"\[\d+\] ", "", h) for h in hits]
    return " | ".join(dict.fromkeys(hits[-2:]))[-500:]


def xray_test_one(xray, outbounds, tag, timeout=12, **trace_kw):
    """Run xray with one exit and fetch cdn-cgi/trace through it.
    -> (ok, message, latency_ms)"""
    port = _free_port()
    cfg = _xray_full(outbounds, tag)
    cfg["inbounds"] = [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                        "protocol": "socks", "settings": {"udp": True}}]
    cfg["routing"]["rules"][0]["inboundTag"] = ["socks-in"]
    cfg["log"] = {"loglevel": "info"}
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    lines = collections.deque(maxlen=60)
    proc = subprocess.Popen([xray, "run", "-c", path], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace",
                            **_nowin())
    threading.Thread(target=lambda: [lines.append(l.strip()) for l in proc.stdout
                                     if l.strip()], daemon=True).start()
    try:
        t0 = time.time()
        while time.time() - t0 < 6:                     # wait for the listener
            if proc.poll() is not None:
                time.sleep(0.2)
                return False, _diag(lines) or "xray exited", None
            try:
                socket.create_connection(("127.0.0.1", port), 0.3).close()
                break
            except OSError:
                time.sleep(0.2)
        t1 = time.perf_counter()
        try:
            tr = _trace_via_socks(port, timeout=timeout, **trace_kw)
        except Exception as e:  # noqa: BLE001
            for _ in range(8):                      # let the log line arrive
                if _diag(lines):
                    break
                time.sleep(0.2)
            return False, (_diag(lines) or f"no answer through the tunnel ({e})"), None
        ms = (time.perf_counter() - t1) * 1000
        if tr.get("warp") in ("on", "plus"):
            return True, f"warp={tr['warp']} exit {tr.get('ip', '?')} {tr.get('loc', '')}", ms
        return False, f"connected but traffic is not on WARP (warp={tr.get('warp')})", ms
    finally:
        proc.terminate()
        try:
            proc.wait(3)
        except Exception:  # noqa: BLE001
            proc.kill()
        try:
            os.remove(path)
        except OSError:
            pass


def verify_with_xray(xitems, cfg, log, progress, cancel):
    """Test up to cfg.xray_verify exits. Sets e['xray'] / e['note'] on each."""
    if not (cfg.xray_path or "").strip() or cfg.xray_verify <= 0:
        return []                                   # opt-in: no path, no test
    xray = find_xray(cfg.xray_path)
    if not xray:
        log(f"[!] Xray not found at '{cfg.xray_path}' - skipped the connection test.")
        return []
    log(f"[i] testing with {xray_version(xray) or xray} ...")
    todo = xitems[: max(0, cfg.xray_verify)]
    ok_tags, done = [], 0
    deadline = time.time() + 150                   # never hold the scan hostage
    ex = ThreadPoolExecutor(max_workers=4)
    try:
        futs = [(it, ex.submit(xray_test_one, xray, it[1], it[0])) for it in todo]
        for (tag, outs, e), f in futs:
            try:
                ok, msg, ms = f.result(timeout=max(1, deadline - time.time()))
            except Exception:  # noqa: BLE001
                log("[!] Xray test took too long - using the endpoints as scanned.")
                break
            e["xray"] = "ok" if ok else "fail"
            e["note"] = msg
            if ok:
                ok_tags.append(tag)
                e["rtt"] = round(ms, 1)
            else:
                log(f"[!] {tag}: {msg}")
            done += 1
            progress("Testing with Xray", done, len(todo), len(ok_tags))
            if cancel is not None and cancel.is_set():
                raise Cancelled()
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    log(f"[i] Xray test: {len(ok_tags)}/{len(todo)} endpoints work")
    if todo and not ok_tags:
        log("[!] None of the tested endpoints connected - the lines above are "
            "Xray's own reasons. Usual causes: Xray-core older than 26.9.30, "
            "a blocked network, or a wrong account.")
    return ok_tags

README = """Duck Scanner - what to import where
====================================

onexray/onexray_raw.json            <- start here for MASQUE
    OneXray (iPhone, Mac, Windows, Android): Connect -> expert mode -> Raw JSON
    -> import (or paste). Needs OneXray 26.10.5 or newer (Xray-core 26.9.30+).
    It lists the standard MASQUE endpoint on every port plus your scanned ones
    and picks the fastest one that connects.
onexray/onexray_raw_alt_sni.json
    Same thing with a different TLS name - only if the first one won't connect.

xray/warp_xray_auto.json
    The same endpoints as a plain Xray config:  xray run -c warp_xray_auto.json
    Local proxy: SOCKS5 127.0.0.1:10808, HTTP :10809.
    (v2rayN's custom-config import did not work for us; use plain Xray or OneXray.)

hiddify/warp_hiddify.json
    Hiddify: copy ALL of it, then "+" -> "Add from clipboard".
    Single WARP and WARP-on-WARP only (WireGuard, UDP). Hiddify has no MASQUE,
    and it cannot read Xray files.

amnezia/*.conf        AmneziaWG app: import a .conf file.
wireguard/*.conf      Official WireGuard app: import a .conf (a .zip works too).

MASQUE transport: HTTP/3 (QUIC, UDP) is what the 1.1.1.1 app tries first; it falls
back to HTTP/2 (TCP) when HTTP/3 is blocked. Pick HTTP/2 here for networks that
block UDP.

Types:  WARP-*    plain WireGuard (UDP)
        MASQUE-*  WARP over MASQUE
        MoM-*     MASQUE dialed through another MASQUE tunnel (experimental)
        GOOL-*    WireGuard WARP carried inside a MASQUE tunnel

Keep these files private: they contain your WARP private keys.
"""

XRAY_LISTEN = ("127.0.0.1", 10808, 10809)


def _xray_full(outbounds, tag=None):
    """Complete, runnable Xray config. tag=None -> balance over all exits."""
    inbounds = [
        {"tag": "socks-in", "listen": XRAY_LISTEN[0], "port": XRAY_LISTEN[1],
         "protocol": "socks", "settings": {"udp": True},
         "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
        {"tag": "http-in", "listen": XRAY_LISTEN[0], "port": XRAY_LISTEN[2],
         "protocol": "http"}]
    cfg = {"log": {"loglevel": "warning"}, "inbounds": inbounds,
           "outbounds": outbounds + [{"protocol": "freedom", "tag": "direct"}]}
    ins = ["socks-in", "http-in"]
    if tag:
        cfg["routing"] = {"rules": [{"type": "field", "inboundTag": ins,
                                     "outboundTag": tag}]}
        return cfg
    prefixes = [p for p in ("WARP-", "MASQUE-", "MoM-", "GOOL-")
                if any(o["tag"].startswith(p) for o in outbounds)]
    cfg["observatory"] = {"subjectSelector": prefixes, "enableConcurrency": True,
                          "probeUrl": "https://www.gstatic.com/generate_204",
                          "probeInterval": "1m"}
    cfg["routing"] = {"domainStrategy": "AsIs",
                      "balancers": [{"tag": "warp-auto", "selector": prefixes,
                                     "strategy": {"type": "leastPing"}}],
                      "rules": [{"type": "field", "inboundTag": ins,
                                 "balancerTag": "warp-auto"}]}
    return cfg


MASQUE_EXITS = ("MASQUE-", "MoM-", "GOOL-")


def _onexray_raw(name, items, sni=None):
    """Complete OneXray 'Raw JSON' config (the app adds its own tunIn inbound)."""
    outs = copy.deepcopy([o for _, os_, _ in items for o in os_])
    if sni:
        for o in outs:
            if o.get("protocol") == "masque":
                o["streamSettings"]["tlsSettings"]["serverName"] = sni
    tags = [t for t, _, _ in items]
    prefixes = [p for p in MASQUE_EXITS if any(t.startswith(p) for t in tags)]
    outs += [{"tag": "direct", "protocol": "freedom"},
             {"tag": "block", "protocol": "blackhole"},
             {"tag": "user-dns", "protocol": "dns",
              "settings": {"rules": [{"action": "hijack", "qType": "1,28"},
                                     {"action": "direct"}]},
              "streamSettings": {"sockopt": {"dialerProxy": tags[0]}}}]
    return {
        "name": name,
        "dns": {"tag": "user-dns-query", "servers": ["1.1.1.1"]},
        "outbounds": outs,
        "observatory": {"subjectSelector": prefixes, "enableConcurrency": True,
                        "probeUrl": "https://www.gstatic.com/generate_204",
                        "probeInterval": "2m"},
        "routing": {"domainStrategy": "IPIfNonMatch",
                    "balancers": [{"tag": "warp-auto", "selector": prefixes,
                                   "strategy": {"type": "leastPing"}}],
                    "rules": [
                        {"ruleTag": "Resolve tunnel DNS", "inboundTag": ["tunIn"],
                         "port": "53", "outboundTag": "user-dns"},
                        {"ruleTag": "DNS through VPN", "inboundTag": ["user-dns-query"],
                         "balancerTag": "warp-auto"},
                        {"ruleTag": "Local network", "outboundTag": "direct",
                         "ip": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]},
                        {"ruleTag": "Everything else through WARP",
                         "inboundTag": ["tunIn"], "balancerTag": "warp-auto"}]}}


def build_outputs(assigned, wg, ms, pin, cfg, log=print, progress=lambda *a: None, cancel=None):
    files = {}
    if not assigned:
        return files
    n = collections.Counter()
    hid, xitems = [], []           # xitems: (exit tag, [xray outbounds])
    outer_wg = "2606:4700:d0::a29f:c001" if cfg.stack == "v6" else "162.159.192.1"
    edge = MASQUE_DEFAULT_EDGE["v6" if cfg.stack == "v6" else "v4"]
    am = {"jc": cfg.jc, "jmin": cfg.jmin, "jmax": cfg.jmax}
    frag = cfg.masque_fragment
    for e in assigned:
        k = e["type"]
        n[k] += 1
        i = f"{n[k]:02d}"
        e["tag"] = None
        if k == "single" and wg:
            e["tag"] = f"WARP-{i}"
            hid.append(_hiddify_wg(e["tag"], e["ip"], e["port"], wg[0]))
            xitems.append((e["tag"], [_xray_wg(e["tag"], e["ip"], e["port"], wg[0])], e))
            files[f"wireguard/{e['tag']}.conf"] = _wg_conf(
                wg[0], _fmt_ep(e["ip"], e["port"]))
        elif k == "wow":
            if len(wg) < 2:
                log("[!] WARP-on-WARP needs 2 accounts - skipped one.")
                continue
            e["tag"] = f"WoW-{i}"
            hid.append(_hiddify_wg(f"WoW-{i}-in", e["ip"], e["port"], wg[0]))
            hid.append(_hiddify_wg(e["tag"], outer_wg, 2408, wg[1], mtu=1200,
                                   detour=f"WoW-{i}-in"))
        elif k == "amnezia" and wg:
            e["tag"] = f"AWG-{i}"
            files[f"amnezia/{e['tag']}.conf"] = _wg_conf(
                wg[0], _fmt_ep(e["ip"], e["port"]), am)
        elif k == "masque":
            if not ms or not pin:
                continue
            e["tag"] = f"MASQUE-{e['proto'].upper()}-{i}"
            xitems.append((e["tag"], [_xray_masque(
                e["tag"], e["ip"], e["port"], e["proto"], ms[0], pin, frag)], e))
        elif k == "mom":
            if len(ms) < 2 or not pin:
                log("[!] MASQUE on MASQUE needs 2 MASQUE accounts - skipped one.")
                continue
            e["tag"] = f"MoM-{i}"
            inner = _xray_masque(f"inner-{e['tag']}", e["ip"], e["port"],
                                 e["proto"], ms[0], pin, frag)
            outer = _xray_masque(e["tag"], edge, 443, cfg.masque_transport, ms[1], pin, frag,
                                 dialer=inner["tag"])
            xitems.append((e["tag"], [inner, outer], e))
        elif k == "gool":
            if not ms or not wg or not pin:
                log("[!] GOOL needs a MASQUE and a WireGuard account - skipped one.")
                continue
            e["tag"] = f"GOOL-{i}"
            inner = _xray_masque(f"inner-{e['tag']}", e["ip"], e["port"],
                                 e["proto"], ms[0], pin, frag)
            outer = _xray_wg(e["tag"], outer_wg, 2408, wg[0], mtu=1200)
            outer["streamSettings"] = {"sockopt": {"dialerProxy": inner["tag"]}}
            xitems.append((e["tag"], [inner, outer], e))
    if hid:
        files["hiddify/warp_hiddify.json"] = json.dumps({"outbounds": hid}, indent=2)
    if xitems:
        good = verify_with_xray(xitems, cfg, log, progress, cancel)
        if good:                      # keep only what really connected
            xitems = [it for it in xitems if it[0] in good]
    base_items = []                   # the standard endpoint on every port
    if cfg.baseline and ms and pin and (cfg.masque + cfg.mom + cfg.gool) > 0:
        have = {(o["settings"]["address"], o["settings"]["port"],
                 o["streamSettings"]["tlsSettings"]["alpn"][0])
                for t, os_, _ in xitems if t.startswith("MASQUE-")
                for o in os_ if o["protocol"] == "masque" and o["tag"] == t}
        for port in MASQUE_PORTS:
            if (edge, port, cfg.masque_transport) not in have:
                tag = f"MASQUE-STD-{port}"
                base_items.append((tag, [_xray_masque(tag, edge, port, cfg.masque_transport,
                                                      ms[0], pin, frag)], None))
    allx = base_items + xitems
    if allx:
        allouts = [o for _, outs, _ in allx for o in outs]
        files["xray/warp_xray_auto.json"] = json.dumps(_xray_full(allouts), indent=2)
        for tag, outs, _ in xitems:
            files[f"xray_endpoints/{tag}.json"] = json.dumps(
                _xray_full(outs, tag), indent=2)
        ox = [it for it in allx if it[0].startswith(MASQUE_EXITS)]
        if ox:
            files["onexray/onexray_raw.json"] = json.dumps(
                _onexray_raw("Duck Scanner - WARP MASQUE", ox), indent=2)
            files["onexray/onexray_raw_alt_sni.json"] = json.dumps(
                _onexray_raw("Duck Scanner - WARP MASQUE (alt TLS name)", ox,
                             sni="www.cloudflare.com"), indent=2)
    if files:
        files["README.txt"] = README
    return files


def make_zip(files, prefix=None) -> bytes:
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in files.items():
            if prefix is None or name.startswith(prefix + "/"):
                z.writestr(name[len(prefix) + 1:] if prefix else name, text)
    return buf.getvalue()


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def run_scan(cfg: Config, log=print, progress=lambda *a: None, cancel=None):
    need_wg = cfg.single + cfg.wow + cfg.amnezia
    need_ms = cfg.masque + cfg.mom + cfg.gool
    if need_wg + need_ms <= 0:
        raise ValueError("Turn on at least one config type.")
    proxy = None
    if cfg.use_proxy:
        scheme = "socks5" if cfg.proxy_type == "socks5" else "http"
        proxy = urllib.parse.urlparse(f"{scheme}://{cfg.proxy_host}:{cfg.proxy_port}")
        log(f"[i] registration proxy: {scheme}://{cfg.proxy_host}:{cfg.proxy_port} "
            "(scanning itself goes direct)")
    wg_accts_needed = (2 if cfg.wow > 0 else 1) if (need_wg or cfg.gool) else 0
    ms_accts_needed = (2 if cfg.mom > 0 else 1) if need_ms else 0
    wg, ms = load_identities(cfg.identity, wg_accts_needed, ms_accts_needed, proxy, log)
    log(f"[i] accounts ready: WireGuard {len(wg)}/{wg_accts_needed}, "
        f"MASQUE {len(ms)}/{ms_accts_needed}")

    assigned, found, pin = [], 0, None
    if need_wg:
        key = wg[0] if wg else _new_key()
        log(f"[i] scanning WireGuard endpoints (stack={cfg.stack}) ...")
        eps = scan_endpoints(cfg, need_wg, base64.b64decode(key["private_key"]),
                             progress, cancel)
        found += len(eps)
        if not eps:
            log("[!] no WireGuard endpoint answered")
        assigned += assign(eps, {"single": cfg.single, "wow": cfg.wow,
                                 "amnezia": cfg.amnezia},
                           ("single", "wow", "amnezia"))
    if need_ms:
        log(f"[i] scanning MASQUE endpoints ({cfg.masque_transport}) ...")
        fb = ms[0]["account"].get("edge_public_key") if ms else None
        eps, pin = scan_masque(cfg, need_ms, progress, cancel, log, fb)
        found += len(eps)
        if not eps:
            log("[!] no MASQUE endpoint answered")
        assigned += assign(eps, {"masque": cfg.masque, "mom": cfg.mom, "gool": cfg.gool},
                           ("masque", "mom", "gool"))
    if not assigned:
        raise RuntimeError(
            "No endpoint answered. Check that this PC can reach Cloudflare "
            "(UDP for WireGuard/HTTP3, TCP 443 for HTTP/2) or raise the timeout.")
    wanted = need_wg + need_ms
    if found < wanted:
        log(f"[!] only {found} of {wanted} endpoints found - "
            "raise 'Endpoints to try' for more.")
    files = build_outputs(assigned, wg, ms, pin, cfg, log, progress, cancel)
    return {"endpoints": assigned, "files": files, "found": found,
            "wanted": wanted, "registered": len(wg) + len(ms)}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--proxy-type", choices=["socks5", "http"], default="socks5")
    ap.add_argument("--proxy-host", default="127.0.0.1")
    ap.add_argument("--proxy-port", type=int, default=10808)
    ap.add_argument("--stack", choices=["v4", "v6", "dual"], default="v4")
    ap.add_argument("--single", type=int, default=25)
    ap.add_argument("--wow", type=int, default=5)
    ap.add_argument("--amnezia", type=int, default=20)
    ap.add_argument("--masque", type=int, default=0)
    ap.add_argument("--mom", type=int, default=0, help="MASQUE on MASQUE")
    ap.add_argument("--gool", type=int, default=0, help="WireGuard inside MASQUE")
    ap.add_argument("--masque-transport", choices=["h3", "h2"], default="h3",
                    help="h3 = QUIC/UDP (default, like the 1.1.1.1 app), h2 = TCP")
    ap.add_argument("--no-baseline", action="store_true",
                    help="do not add the standard endpoint on every port")
    ap.add_argument("--no-fragment", action="store_true")
    ap.add_argument("--xray", default="", help="path to xray(.exe) to test the Xray configs")
    ap.add_argument("--xray-verify", type=int, default=12)
    ap.add_argument("--jc", type=int, default=4)
    ap.add_argument("--jmin", type=int, default=40)
    ap.add_argument("--jmax", type=int, default=70)
    ap.add_argument("--candidates", type=int, default=4000)
    ap.add_argument("--probes", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--workers", type=int, default=200)
    ap.add_argument("--identity", default=default_identity_path())
    ap.add_argument("--outdir", default="warp_out")
    ap.add_argument("--zip", action=argparse.BooleanOptionalAction, default=True)
    a = ap.parse_args()
    cfg = Config(use_proxy=not a.no_proxy, proxy_type=a.proxy_type,
                 proxy_host=a.proxy_host, proxy_port=a.proxy_port, stack=a.stack,
                 single=a.single, wow=a.wow, amnezia=a.amnezia, masque=a.masque,
                 mom=a.mom, gool=a.gool, masque_transport=a.masque_transport,
                 masque_fragment=not a.no_fragment, baseline=not a.no_baseline, xray_path=a.xray, xray_verify=a.xray_verify, jc=a.jc, jmin=a.jmin,
                 jmax=a.jmax, candidates=a.candidates, probes=a.probes,
                 timeout=a.timeout, workers=a.workers, identity=a.identity)

    def prog(label, done, total, alive):
        print(f"\r[{label}] {done}/{total} alive={alive}      ", end="",
              file=sys.stderr)

    try:
        res = run_scan(cfg, log=lambda m: print("\n" + m, file=sys.stderr),
                       progress=prog)
    except Exception as e:  # noqa: BLE001
        print(f"\n[!] {e}", file=sys.stderr)
        sys.exit(1)
    print(file=sys.stderr)
    for name, text in res["files"].items():
        path = os.path.join(a.outdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    print(f"[+] wrote {len(res['files'])} files to {a.outdir}/", file=sys.stderr)
    if a.zip:
        with open(os.path.join(a.outdir, "warp_configs.zip"), "wb") as f:
            f.write(make_zip(res["files"]))
        print("[+] wrote warp_configs.zip", file=sys.stderr)


if __name__ == "__main__":
    main()
