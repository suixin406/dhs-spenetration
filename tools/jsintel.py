#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jsintel.py — 从前端 bundle 提取 API / 密钥 / 字段名 / 懒加载分块

用法:
  python jsintel.py <url_or_file> [-o outdir] [--keywords kw1,kw2]

示例:
  python jsintel.py https://target/assets/index.abc.js -o loot/intel
  python jsintel.py ./index.js
"""
import argparse
import json
import os
import re
import ssl
import sys
from urllib.request import Request, urlopen

from scope_guard import require_allowed

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

UA = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"}

# ---------- 提取规则 ----------
PAT = {
    "api_paths": r"""['"](/[A-Za-z0-9_\-/\.]{2,80})['"]""",
    "abs_url": r"""https?://[A-Za-z0-9\.\-:%_/?#=&~+]+""",
    "base_url_keys": r"""(?:baseURL|BASE_URL|API_HOST|SERVER_URL|API_URL|baseUrl)\s*[:=]\s*['"]([^'"]{3,160})['"]""",
    "route_paths": r"""(?:path|route)\s*:\s*['"]([^'"]{1,80})['"]""",
    "chunks": r"""['"]([A-Za-z0-9_\-\.]+\.js)['"]""",
    "aes_key_ctx": r"""['"]([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:,.<>/?|~`]{16})['"]""",
    "crypto_hits": r"""(CryptoJS\.AES|AES\.(?:en|de)crypt|mode\.(?:ECB|CBC|CTR)|Pkcs7|JSEncrypt|setPublicKey|sm4|SM4)""",
    "sign_hints": r"""(?:sign|signature|x-sign|_sign|nonce|timestamp)\s*[:=]""",
    "field_defs": r"""(?:username|passwd|password|passWord|confirm_passwd|email|mobile|phone|code|verify|captcha|accessToken|token)\s*[:=]""",
}

INTERESTING = (
    "token", "auth", "sign", "secret", "key", "api", "base", "host", "url",
    "pass", "pwd", "admin", "debug", "test", "demo",
)


def read_source(src, insecure=False, max_bytes=20 * 1024 * 1024):
    if os.path.isfile(src):
        with open(src, encoding="utf-8", errors="ignore") as source:
            return source.read(max_bytes + 1)
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    request = Request(src, headers=UA)
    with urlopen(request, timeout=40, context=context) as response:
        raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("source exceeds --max-mb")
    return raw.decode("utf-8", "ignore")


def uniq(xs):
    out, seen = [], set()
    for x in xs:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", help="bundle URL 或本地文件")
    ap.add_argument("-o", "--out", default="loot/intel", help="输出目录")
    ap.add_argument("--keywords", default="", help="额外关键词，逗号分隔")
    ap.add_argument("--insecure", action="store_true", help="关闭 TLS 证书校验")
    ap.add_argument("--max-mb", type=int, default=20, help="最大下载/读取体积")
    ap.add_argument("--scope-config", help="AUTHORIZED-TARGETS.json 路径")
    a = ap.parse_args()

    if a.max_mb < 1 or a.max_mb > 1024:
        ap.error("--max-mb must be between 1 and 1024")
    if not os.path.isfile(a.src):
        try:
            require_allowed(a.src, "active", a.scope_config)
        except (ValueError, PermissionError) as exc:
            ap.error("scope denied: %s" % exc)
    js = read_source(a.src, a.insecure, a.max_mb * 1024 * 1024)
    if len(js.encode("utf-8")) > a.max_mb * 1024 * 1024:
        ap.error("source exceeds --max-mb")
    os.makedirs(a.out, exist_ok=True)
    print("[+] source bytes: %d" % len(js), file=sys.stderr)

    res = {}
    for name, pat in PAT.items():
        hits = re.findall(pat, js)
        if name == "abs_url":
            res[name] = uniq(hits)
        elif name == "aes_key_ctx":
            res[name] = uniq([h for h in hits if len(h) == 16])
        elif name == "crypto_hits":
            res[name] = uniq(hits)
        else:
            res[name] = uniq(hits)

    # API 路径过滤：只留像接口的
    api = [p for p in res.get("api_paths", [])
           if re.search(r"/(api|v\d|admin|user|order|pay|auth|upload|sms|code|config|login|register|reset)", p, re.I)]
    res["api_like"] = api

    # 关键词加分项
    kws = [k.strip() for k in a.keywords.split(",") if k.strip()]
    kw_hits = {}
    for k in kws:
        kw_hits[k] = uniq(re.findall(r"['\"]([^'\"]{0,60}%s[^'\"]{0,60})['\"]" % re.escape(k), js, re.I))[:30]
    res["custom_keywords"] = kw_hits

    # 落盘
    def dump(name, data):
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as f:
            if isinstance(data, list):
                f.write("\n".join(str(x) for x in data))
            else:
                json.dump(data, f, ensure_ascii=False, indent=2)

    dump("api_paths.txt", res.get("api_like", []))
    dump("all_paths.txt", res.get("api_paths", []))
    dump("urls.txt", res.get("abs_url", []))
    dump("chunks.txt", res.get("chunks", []))
    dump("aes16.txt", res.get("aes_key_ctx", []))
    dump("summary.json", {k: v for k, v in res.items() if k not in ("api_paths", "abs_url", "aes_key_ctx")})

    # 控制台摘要
    print("\n=== 摘要 ===")
    print("  API 路径        : %d  (-> api_paths.txt)" % len(res.get("api_like", [])))
    print("  全部路径        : %d" % len(res.get("api_paths", [])))
    print("  绝对 URL        : %d" % len(res.get("abs_url", [])))
    print("  baseURL 候选    : %d" % len(res.get("base_url_keys", [])))
    print("  懒加载 chunk    : %d" % len(res.get("chunks", [])))
    print("  16 字节常量     : %d  (AES 密钥候选)" % len(res.get("aes_key_ctx", [])))
    print("  加密函数命中    : %s" % ", ".join(res.get("crypto_hits", [])[:8]))
    print("  签名字段提示    : %d" % len(res.get("sign_hints", [])))
    print("  表单字段提示    : %s" % ", ".join(res.get("field_defs", [])[:12]))

    for k in ("base_url_keys", "aes_key_ctx"):
        if res.get(k):
            print("\n  [%s]" % k)
            for x in res[k][:10]:
                print("    ", x)

    if api:
        print("\n  [前 25 条 API]")
        for p in api[:25]:
            print("    ", p)


if __name__ == "__main__":
    main()
