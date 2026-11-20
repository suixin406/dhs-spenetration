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
import ssl
import sys
import zipfile
from urllib.request import Request, urlopen

from scope_guard import require_allowed

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

URL_RE = re.compile(rb"https?://[A-Za-z0-9\.\-_~:/?#\[\]@!$&'()*+,;=%]{6,200}")
PATH_RE = re.compile(rb"/(?:api|v\d|user|order|pay|auth|admin|upload|sms|code|login|register|reset|config)[A-Za-z0-9_\-/\.]{0,60}")
KEY_RE = re.compile(rb"[\"']([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:,.<>/?|~`]{16}|[A-Za-z0-9+/]{24}|[A-Za-z0-9+/]{32})[\"']")
AK_RE = re.compile(rb"(?:AKID|LTAI|AKIA|access[_-]?key|secret[_-]?key|appkey|app_secret)[\"'=:\s]{0,4}([A-Za-z0-9]{12,40})", re.I)
FIELD_RE = re.compile(rb"[\"'](username|passwd|password|passWord|confirm_passwd|email|mobile|phone|code|verify|captcha|accessToken|token|sign|timestamp|nonce)[\"']")
SIGN_RE = re.compile(rb"(?:md5|sha1|sha256|HmacSHA256|MessageDigest|Cipher|getInstance|AES|RSA|sm4)", re.I)


def fetch(src, dest, insecure=False, max_bytes=300 * 1024 * 1024):
    if os.path.isfile(src):
        return src
    print("[+] 下载 %s" % src, file=sys.stderr)
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    request = Request(src, headers={"User-Agent": "Mozilla/5.0"})
    total = 0
    with urlopen(request, timeout=120, context=context) as response, open(dest, "wb") as output:
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("APK exceeds --max-download-mb")
            output.write(chunk)
    return dest


def printable_strings(blob):
    ascii_strings = [m.decode("utf-8", "ignore") for m in re.findall(rb"[ -~]{4,200}", blob)]
    utf16_strings = []
    for match in re.findall(rb"(?:[ -~]\x00){4,200}", blob):
        utf16_strings.append(match.decode("utf-16le", "ignore"))
    return sorted(set(ascii_strings + utf16_strings))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", help="APK 路径或 URL")
    ap.add_argument("-o", "--out", default="loot/app")
    ap.add_argument("--insecure", action="store_true", help="关闭 TLS 证书校验")
    ap.add_argument("--max-download-mb", type=int, default=300)
    ap.add_argument("--max-entry-mb", type=int, default=128)
    ap.add_argument("--max-total-mb", type=int, default=512)
    ap.add_argument("--scope-config", help="AUTHORIZED-TARGETS.json 路径")
    a = ap.parse_args()
    for name in ("max_download_mb", "max_entry_mb", "max_total_mb"):
        if getattr(a, name) < 1:
            ap.error("--%s must be positive" % name.replace("_", "-"))
    os.makedirs(a.out, exist_ok=True)

    if not os.path.isfile(a.src):
        try:
            require_allowed(a.src, "active", a.scope_config)
        except (ValueError, PermissionError) as exc:
            ap.error("scope denied: %s" % exc)

    apk = fetch(a.src, os.path.join(a.out, "app.apk"), a.insecure, a.max_download_mb * 1024 * 1024)
    blobs = []
    manifest = b""
    with zipfile.ZipFile(apk) as archive:
        infos = archive.infolist()
        print("[+] 条目 %d" % len(infos))
        selected_total = 0
        for info in infos:
            n = info.filename
            if not re.search(r"(classes\d*\.dex|\.so$|AndroidManifest\.xml|assets/.*\.(json|js|xml|txt|properties))$", n):
                continue
            if info.file_size > a.max_entry_mb * 1024 * 1024:
                print("[!] 跳过超大条目 %s (%d bytes)" % (n, info.file_size), file=sys.stderr)
                continue
            selected_total += info.file_size
            if selected_total > a.max_total_mb * 1024 * 1024:
                raise ValueError("selected APK entries exceed --max-total-mb")
            try:
                data = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                print("[!] 读取失败 %s: %s" % (n, exc), file=sys.stderr)
                continue
            blobs.append((n, data))
            if n == "AndroidManifest.xml":
                manifest = data
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
    dump("manifest.txt", printable_strings(manifest))

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
