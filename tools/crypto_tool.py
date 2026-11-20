#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""crypto_tool.py — API 加解密与签名复现

用法:
  # 解密（ECB，给定 key）
  python crypto_tool.py dec --key '=^%7@84%0^!8892-' --b64 '<cipher>'
  # 解密（CBC）
  python crypto_tool.py dec --key <hex_or_str> --iv <iv> --mode cbc --b64 '<cipher>'
  # 从文件批量解
  python crypto_tool.py dec --key <k> --file loot/raw.txt
  # 爆破 key（用一个已知明文特征判断）
  python crypto_tool.py brute --b64 '<cipher>' --wordlist keys.txt --expect '{"code"'
  # 签名
  python crypto_tool.py sign --algo md5 --params 'a=1&b=2' --salt <salt>
  python crypto_tool.py sign --algo hmac-sha256 --data 'x' --secret <s>
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE = True
except Exception:
    HAVE = False


def norm_key(k: str) -> bytes:
    """支持 32/48/64 位 hex，或直接 utf-8 字符串"""
    k = k.strip()
    if len(k) in (32, 48, 64):
        try:
            return binascii.unhexlify(k)
        except Exception:
            pass
    return k.encode()


def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    n = b[-1]
    return b[:-n] if 1 <= n <= 16 and b[-n:] == bytes([n]) * n else b


def pkcs7_pad(b: bytes, bs: int = 16) -> bytes:
    n = bs - len(b) % bs
    return b + bytes([n]) * n


def aes_dec(data: bytes, key: bytes, iv: bytes = None, mode: str = "ecb") -> bytes:
    if not HAVE:
        sys.exit("需要 cryptography：pip install cryptography")
    algo = algorithms.AES(key)
    m = modes.ECB() if mode.lower() == "ecb" else modes.CBC(iv or b"\x00" * 16)
    d = Cipher(algo, m).decryptor()
    return d.update(data) + d.finalize()


def aes_enc(data: bytes, key: bytes, iv: bytes = None, mode: str = "ecb") -> bytes:
    if not HAVE:
        sys.exit("需要 cryptography：pip install cryptography")
    algo = algorithms.AES(key)
    m = modes.ECB() if mode.lower() == "ecb" else modes.CBC(iv or b"\x00" * 16)
    e = Cipher(algo, m).encryptor()
    return e.update(pkcs7_pad(data)) + e.finalize()


def try_decode(cipher_text: str) -> bytes:
    """自动识别 base64 / hex"""
    t = cipher_text.strip().strip('"').strip("'").replace("\\/", "/")
    try:
        return base64.b64decode(t, validate=False)
    except Exception:
        pass
    try:
        return binascii.unhexlify(t)
    except Exception:
        pass
    return t.encode("latin-1")


def pretty(b: bytes) -> str:
    t = pkcs7_unpad(b).decode("utf-8", "ignore")
    try:
        return json.dumps(json.loads(t), ensure_ascii=False, indent=2)
    except Exception:
        return t


def cmd_dec(a):
    key = norm_key(a.key)
    iv = norm_key(a.iv) if a.iv else None
    if a.file:
        src = open(a.file, encoding="utf-8", errors="ignore").read().splitlines()
    else:
        src = [a.b64]
    for i, line in enumerate(src, 1):
        line = line.strip()
        if not line:
            continue
        try:
            out = pretty(aes_dec(try_decode(line), key, iv, a.mode))
            print("--- [%d] ---" % i)
            print(out[:2000])
        except Exception as e:
            print("--- [%d] FAIL: %s" % (i, str(e)[:80]))


def cmd_enc(a):
    key = norm_key(a.key)
    iv = norm_key(a.iv) if a.iv else None
    ct = aes_enc(a.plain.encode(), key, iv, a.mode)
    print("raw    :", ct)
    print("b64    :", base64.b64encode(ct).decode())
    print("hex    :", binascii.hexlify(ct).decode())


def cmd_brute(a):
    ct = try_decode(a.b64)
    try:
        words = [l.strip() for l in open(a.wordlist, encoding="utf-8", errors="ignore") if l.strip()]
    except Exception as e:
        sys.exit("读不到字典: %s" % e)
    print("[+] 字典 %d 条，密文 %d 字节" % (len(words), len(ct)))
    for w in words:
        for cand in (w, hashlib.md5(w.encode()).hexdigest()[:16],
                     hashlib.md5(w.encode()).hexdigest()[:32]):
            try:
                pt = pkcs7_unpad(aes_dec(ct, norm_key(cand), None, "ecb")).decode("utf-8", "ignore")
            except Exception:
                continue
            if a.expect in pt:
                print("\n*** HIT key=%r (派生自 %r)" % (cand, w))
                print(pretty(pt.encode())[:1500])
                return
    print("[-] 未命中")


def cmd_sign(a):
    p = dict()
    for kv in (a.params or "").split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            p[k] = v
    if a.algo == "md5":
        s = "&".join("%s=%s" % (k, p[k]) for k in sorted(p))
        print("sign_str:", s)
        print("sign    :", hashlib.md5((s + a.salt).encode()).hexdigest())
    elif a.algo == "md5-cat":
        print("sign    :", hashlib.md5(((a.data or "") + a.salt).encode()).hexdigest())
    elif a.algo == "sha1":
        s = "&".join("%s=%s" % (k, p[k]) for k in sorted(p))
        print("sign    :", hashlib.sha1((s + a.salt).encode()).hexdigest())
    elif a.algo == "hmac-sha256":
        print("sign    :", hmac.new(a.secret.encode(), (a.data or "").encode(), hashlib.sha256).hexdigest())
    elif a.algo == "hmac-sha1":
        print("sign    :", hmac.new(a.secret.encode(), (a.data or "").encode(), hashlib.sha1).hexdigest())
    else:
        sys.exit("未知 algo: %s" % a.algo)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("dec")
    d.add_argument("--key", required=True)
    d.add_argument("--iv")
    d.add_argument("--mode", default="ecb")
    d.add_argument("--b64", default="")
    d.add_argument("--file")
    d.set_defaults(func=cmd_dec)

    e = sub.add_parser("enc")
    e.add_argument("--key", required=True)
    e.add_argument("--iv")
    e.add_argument("--mode", default="ecb")
    e.add_argument("--plain", required=True)
    e.set_defaults(func=cmd_enc)

    b = sub.add_parser("brute")
    b.add_argument("--b64", required=True)
    b.add_argument("--wordlist", required=True)
    b.add_argument("--expect", default='{"')
    b.set_defaults(func=cmd_brute)

    s = sub.add_parser("sign")
    s.add_argument("--algo", default="md5",
                   choices=["md5", "md5-cat", "sha1", "hmac-sha256", "hmac-sha1"])
    s.add_argument("--params", default="")
    s.add_argument("--data", default="")
    s.add_argument("--salt", default="")
    s.add_argument("--secret", default="")
    s.set_defaults(func=cmd_sign)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
