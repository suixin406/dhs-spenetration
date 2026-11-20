#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""http_concurrent.py — 高并发请求框架（带解密钩子 / 重试 / 限速 / 结果落盘）

用法:
  # 1) 批量探测状态码与长度
  python http_concurrent.py get --urls urls.txt --threads 50 --out loot/scan.txt

  # 2) 带参批量打接口（每行一个 query，插到 {q} 位置）
  python http_concurrent.py post --url https://api/x --params params.txt \
      --tpl 'email={q}&code=123456' --threads 30 --show

  # 3) 用 AES 密钥解响应（--aes-key 自动尝试解密再判定）
  python http_concurrent.py get --urls urls.txt --aes-key '=^%7@84%0^!8892-' --show

  # 4) 需要先登录拿 token
  python http_concurrent.py get --urls urls.txt --header 'accessToken:eyJ...'
"""
import argparse
import base64
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from scope_guard import require_allowed

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

try:
    import requests
    import urllib3
except Exception:
    requests = None
    urllib3 = None

UA = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
      "Accept": "application/json, text/plain, */*"}

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _aes_ecb(ct: bytes, key: bytes) -> bytes:
        d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        b = d.update(ct) + d.finalize()
        if b:
            n = b[-1]
            if 1 <= n <= 16 and b[-n:] == bytes([n]) * n:
                b = b[:-n]
        return b
    HAVE_AES = True
except Exception:
    HAVE_AES = False


def maybe_decrypt(text: str, key: bytes) -> str:
    if not HAVE_AES or not key:
        return text
    t = text.strip().strip('"').replace("\\/", "/")
    try:
        return _aes_ecb(base64.b64decode(t), key).decode("utf-8", "ignore")
    except Exception:
        return text


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("get", "post"):
        p = sub.add_parser(name)
        p.add_argument("--url", default="", help="固定 URL（get 时与 --urls 二选一）")
        p.add_argument("--urls", default="", help="URL 列表文件")
        p.add_argument("--params", default="", help="参数列表文件（每行一个 {q} 值）")
        p.add_argument("--tpl", default="q={q}", help="表单模板，用 {q} 占位")
        p.add_argument("--threads", type=int, default=40)
        p.add_argument("--timeout", type=float, default=15)
        p.add_argument("--header", default="", help="额外头 k:v;k2:v2")
        p.add_argument("--aes-key", default="", help="响应 AES-ECB 密钥")
        p.add_argument("--show", action="store_true", help="打印响应片段")
        p.add_argument("--out", default="", help="结果文件")
        p.add_argument("--retry", type=int, default=1)
        p.add_argument("--insecure", action="store_true", help="关闭 TLS 证书校验")
        p.add_argument("--scope-config", help="AUTHORIZED-TARGETS.json 路径")

    a = ap.parse_args()
    if requests is None:
        ap.error("需要 requests：python -m pip install -r requirements.txt")
    if a.threads < 1 or a.threads > 512:
        ap.error("--threads must be between 1 and 512")
    if a.retry < 0 or a.retry > 20:
        ap.error("--retry must be between 0 and 20")
    if a.insecure and urllib3 is not None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    hdrs = dict(UA)
    if a.header:
        for kv in a.header.split(";"):
            if ":" in kv:
                k, v = kv.split(":", 1)
                hdrs[k.strip()] = v.strip()
    key = a.aes_key.encode() if a.aes_key else b""

    urls = []
    if a.url:
        urls = [a.url]
    if a.urls:
        urls = [l.strip() for l in open(a.urls, encoding="utf-8", errors="ignore") if l.strip()]
    if not urls:
        sys.exit("需要 --url 或 --urls")
    for url in urls:
        try:
            require_allowed(url, "active", a.scope_config)
        except (ValueError, PermissionError) as exc:
            ap.error("scope denied for %s: %s" % (url, exc))

    params = [""]
    if a.params:
        params = [l.strip() for l in open(a.params, encoding="utf-8", errors="ignore") if l.strip()]

    jobs = []
    if a.cmd == "get":
        jobs = [(u, None) for u in urls]
    else:
        for u in urls:
            for pv in params:
                body = a.tpl.replace("{q}", pv)
                d = {}
                for kv in body.split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        d[k] = v
                jobs.append((u, d))

    lock = threading.Lock()
    if a.out:
        parent = os.path.dirname(os.path.abspath(a.out))
        os.makedirs(parent, exist_ok=True)
    out = open(a.out, "w", encoding="utf-8") if a.out else None
    n = 0
    t0 = time.time()

    def one(job):
        nonlocal n
        u, d = job
        last = ""
        for attempt in range(a.retry + 1):
            try:
                if a.cmd == "get":
                    r = requests.get(u, headers=hdrs, timeout=a.timeout, verify=not a.insecure)
                else:
                    r = requests.post(u, data=d, headers=hdrs, timeout=a.timeout, verify=not a.insecure)
                body = maybe_decrypt(r.text, key)
                last = "%s len=%-7d %s" % (r.status_code, len(r.content), body[:160].replace("\n", " "))
                with lock:
                    n += 1
                    if a.out:
                        out.write("%s\n%s\n" % (u, last))
                    if a.show:
                        print("%-52s %s" % (u[:52], last))
                    if n % 100 == 0:
                        el = time.time() - t0
                        print("[%d] %.0f/s" % (n, n / el if el else 0), file=sys.stderr)
                return last
            except Exception as e:
                last = "ERR attempt=%d/%d %s" % (attempt + 1, a.retry + 1, str(e)[:60])
        return last

    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        list(ex.map(one, jobs))

    el = time.time() - t0
    if out:
        out.close()
    print("\n=== 完成 ===")
    print("  任务 %d  耗时 %.1fs  吞吐 %.1f/s" % (len(jobs), el, len(jobs) / el if el else 0))
    if a.out:
        print("  结果:", a.out)


if __name__ == "__main__":
    main()
