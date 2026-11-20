#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_gh_auth_and_diag.py — 重新授权、落盘 token、诊断能力

产出:
  _gh_token.txt    token（本地，已被 .gitignore 排除）
诊断项:
  - token 前缀（gho_/ghp_/github_pat_）
  - /user 返回的 x-oauth-scopes
  - 能否 list 仓库
  - 能否建仓（预期：gho_ 不行）
  - 是否 GitHub App token
"""
import base64
import json
import os
import sys
import time

try:
    import requests
except Exception:
    sys.exit("需要 requests")

CLIENT_ID = "Iv1.b507a08c87ecfe98"
DEVICE_URL = "https://github.com/login/device/code"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API = "https://api.github.com"
H0 = {"Accept": "application/json", "User-Agent": "dsh-pentest-preset"}
HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(HERE, "_gh_token.txt")

SCOPE = "repo read:org workflow"


def device_flow():
    r = requests.post(DEVICE_URL, headers=H0, timeout=30,
                      data={"client_id": CLIENT_ID, "scope": SCOPE})
    d = r.json()
    if "device_code" not in d:
        sys.exit("申请设备码失败: %s" % json.dumps(d)[:300])
    dev, ucode = d["device_code"], d["user_code"]
    vuri = d.get("verification_uri", "https://github.com/login/device")
    interval, expires = int(d.get("interval", 5)), int(d.get("expires_in", 900))
    print("=" * 62)
    print("  打开：%s" % vuri)
    print("  代码：%s" % ucode)
    print("  有效：%d 分钟" % (expires // 60))
    print("=" * 62, flush=True)
    deadline = time.time() + expires
    while time.time() < deadline:
        time.sleep(interval)
        tr = requests.post(TOKEN_URL, headers=H0, timeout=30, data={
            "client_id": CLIENT_ID, "device_code": dev,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
        try:
            td = tr.json()
        except Exception:
            continue
        e = td.get("error")
        if e == "authorization_pending":
            print(".", end="", flush=True); continue
        if e == "slow_down":
            interval += int(td.get("interval", 5)); continue
        if e in ("expired_token", "access_denied"):
            sys.exit("\n授权失败: %s" % e)
        if td.get("access_token"):
            print()
            return td["access_token"]
    sys.exit("\n超时")


def main():
    tok = None
    if os.path.exists(TOKEN_FILE):
        tok = open(TOKEN_FILE).read().strip()
        print("[+] 复用已存 token（%s...）长度 %d" % (tok[:7], len(tok)))
    else:
        tok = device_flow()
        open(TOKEN_FILE, "w").write(tok)
        print("[+] token 已落盘 %s" % TOKEN_FILE)

    H = {"Authorization": "Bearer " + tok,
         "Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28",
         "User-Agent": "dsh-pentest-preset"}

    print("\n=== 诊断 ===")
    print("  token 前缀 : %s" % tok[:7])

    r = requests.get(API + "/user", headers=H, timeout=30)
    print("  /user      : %d" % r.status_code)
    if r.status_code == 200:
        print("  登录身份   : %s" % r.json().get("login"))
    sc = r.headers.get("x-oauth-scopes")
    acc = r.headers.get("x-accepted-oauth-scopes")
    print("  oauth scopes: %s" % (sc if sc else "(无 -> 说明是 GitHub App token)"))
    if acc:
        print("  accepted     : %s" % acc)

    # App 判定
    ir = requests.get(API + "/installation/repositories", headers=H, timeout=30)
    print("  /installation/repositories: %d %s" %
          (ir.status_code, "(是 GitHub App)" if ir.status_code == 200 else "(非 App 或不可用)"))

    # 能否建仓
    cr = requests.post(API + "/user/repos", headers=H, timeout=30, json={
        "name": "_dsh_probe_test", "private": True, "auto_init": False})
    print("  POST /user/repos: %d" % cr.status_code)
    if cr.status_code in (200, 201):
        print("  >>> 可以建仓！")
        url = cr.json()["url"]
        d = requests.delete(url, headers=H, timeout=30)
        print("  探测仓库已删除: %d" % d.status_code)
    else:
        print("  >>> 不能建仓: %s" % cr.text[:160])

    # 列仓库
    lr = requests.get(API + "/user/repos", headers=H, timeout=30, params={"per_page": 5})
    print("  GET /user/repos: %d" % lr.status_code)
    if lr.status_code == 200:
        for x in lr.json()[:5]:
            print("     -", x["full_name"], "| push:", x.get("permissions", {}).get("push"))


if __name__ == "__main__":
    main()
