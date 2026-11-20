#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apk_extract.py — APK 解包与接口/密钥提取（纯 Python，不依赖 jadx/apktool）

用法:
  python apk_extract.py app.apk -o loot/app
  python apk_extract.py https://x/app.apk -o loot/app     # 直接下

产出:
  loot/app/dex_strings.txt   全量字符串
  loot/app/endpoints.txt     API / URL
  loot/app/keys.txt          疑似密钥（16/24/32 字节常量、AK/SK）
  loot/app/fields.txt        表单字段/参数名
  loot/app/manifest.txt      AndroidManifest 里的 scheme/permission（可用时）
"""
import argparse
import os
import re
import sys
import zipfile

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except Exception:
    requests = None

URL_RE = re.compile(rb"https?://[A-Za-z0-9\.\-_~:/?#\[\]@!$&'()*+,;=%]{6,200}")
PATH_RE = re.compile(rb"/(?:api|v\d|user|order|pay|auth|admin|upload|sms|code|login|register|reset|config)[A-Za-z0-9_\-/\.]{0,60}")
KEY_RE = re.compile(rb"[\"']([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:,.<>/?|~`]{16}|[A-Za-z0-9+/]{24}|[A-Za-z0-9+/]{32})[\"']")
AK_RE = re.compile(rb"(?:AKID|LTAI|AKIA|access[_-]?key|secret[_-]?key|appkey|app_secret)[\"'=:\s]{0,4}([A-Za-z0-9]{12,40})", re.I)
FIELD_RE = re.compile(rb"[\"'](username|passwd|password|passWord|confirm_passwd|email|mobile|phone|code|verify|captcha|accessToken|token|sign|timestamp|nonce)[\"']")
SIGN_RE = re.compile(rb"(?:md5|sha1|sha256|HmacSHA256|MessageDigest|Cipher|getInstance|AES|RSA|sm4)", re.I)


def fetch(src, dest):
    if os.path.isfile(src):
        return src
    if requests is None:
        sys.exit("需要 requests 才能下载")
    print("[+] 下载 %s" % src, file=sys.stderr)
    r = requests.get(src, stream=True, timeout=120, verify=False,
                     headers={"User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    with open(dest, "wb") as f:
        for chunk in r.iter_content(65536):
            f.write(chunk)
    return dest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", help="APK 路径或 URL")
    ap.add_argument("-o", "--out", default="loot/app")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    apk = fetch(a.src, os.path.join(a.out, "app.apk"))
    z = zipfile.ZipFile(apk)
    names = z.namelist()
    print("[+] 条目 %d" % len(names))

    blobs = []
    for n in names:
        if re.search(r"(classes\d*\.dex|\.so$|AndroidManifest\.xml|assets/.*\.(json|js|xml|txt|properties))$", n):
            try:
                blobs.append((n, z.read(n)))
            except Exception:
                pass
    print("[+] 读取 %d 个关键条目" % len(blobs))
    total = b"\n".join(b for _, b in blobs)

    def dump(name, items):
        p = os.path.join(a.out, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(set(x for x in items if x))))
        print("    %-16s %d -> %s" % (name, len(set(items)), p))

    urls = [m.group(0).decode("latin-1", "ignore") for m in URL_RE.finditer(total)]
    paths = [m.group(0).decode("latin-1", "ignore") for m in PATH_RE.finditer(total)]
    keys = [m.group(1).decode("latin-1", "ignore") for m in KEY_RE.finditer(total)]
    aks = [m.group(1).decode("latin-1", "ignore") for m in AK_RE.finditer(total)]
    fields = [m.group(1).decode("latin-1", "ignore") for m in FIELD_RE.finditer(total)]
    signs = sorted(set(m.group(0).decode("latin-1", "ignore").lower() for m in SIGN_RE.finditer(total)))

    print("\n=== 提取结果 ===")
    dump("dex_strings.txt", re.findall(rb"[ -~]{6,80}", total) and
         [s.decode("latin-1", "ignore") for s in re.findall(rb"[ -~]{8,120}", total)][:200000])
    dump("endpoints.txt", urls)
    dump("api_paths.txt", paths)
    dump("keys.txt", keys + aks)
    dump("fields.txt", fields)

    with open(os.path.join(a.out, "sign_algo_hints.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(signs))

    print("\n=== 摘要 ===")
    print("  URL          :", len(set(urls)))
    print("  API 路径     :", len(set(paths)))
    print("  密钥候选     :", len(set(keys)), "+ AK/SK", len(set(aks)))
    print("  表单字段     :", ", ".join(sorted(set(fields))[:15]))
    print("  加密算法提示 :", ", ".join(signs[:10]))
    if urls:
        print("\n  [前 15 条 URL]")
        for u in sorted(set(urls))[:15]:
            print("    ", u)


if __name__ == "__main__":
    main()
