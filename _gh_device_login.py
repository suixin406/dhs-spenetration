#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_gh_device_login.py — GitHub 设备授权流 + 自动上传

流程：
  1) 向 GitHub 申请设备码 -> 打印 user_code 与 URL
  2) 轮询等待用户授权
  3) 拿到 token 后调用 _push_github.py 上传

用法：
  python _gh_device_login.py [--repo NAME] [--private] [--scope repo]
"""
import argparse
import json
import os
import subprocess
import sys
import time

try:
    import requests
except Exception:
    sys.exit("需要 requests")

# GitHub CLI 的公开 OAuth App client_id（gh auth login 用的同一个）
CLIENT_ID = "Iv1.b507a08c87ecfe98"
DEVICE_URL = "https://github.com/login/device/code"
TOKEN_URL = "https://github.com/login/oauth/access_token"
H = {"Accept": "application/json", "User-Agent": "dsh-pentest-preset"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="dsh-pentest-preset")
    ap.add_argument("--private", action="store_true")
    ap.add_argument("--scope", default="repo")
    a = ap.parse_args()

    # 1) 申请设备码
    r = requests.post(DEVICE_URL, headers=H, timeout=30,
                      data={"client_id": CLIENT_ID, "scope": a.scope})
    if r.status_code != 200:
        sys.exit("申请设备码失败: %d %s" % (r.status_code, r.text[:200]))
    d = r.json()
    if "device_code" not in d:
        sys.exit("返回异常: %s" % json.dumps(d)[:300])

    dev = d["device_code"]
    ucode = d.get("user_code")
    vuri = d.get("verification_uri", "https://github.com/login/device")
    interval = int(d.get("interval", 5))
    expires = int(d.get("expires_in", 900))

    print("=" * 62)
    print("  请在浏览器打开：  %s" % vuri)
    print("  输入一次性代码：  %s" % ucode)
    print("  有效期：%d 分钟" % (expires // 60))
    print("=" * 62)
    print("WAITING_FOR_AUTH", flush=True)

    # 2) 轮询
    deadline = time.time() + expires
    tok = None
    while time.time() < deadline:
        time.sleep(interval)
        tr = requests.post(TOKEN_URL, headers=H, timeout=30, data={
            "client_id": CLIENT_ID,
            "device_code": dev,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        })
        try:
            td = tr.json()
        except Exception:
            continue
        err = td.get("error")
        if err == "authorization_pending":
            print(".", end="", flush=True)
            continue
        if err == "slow_down":
            interval += int(td.get("interval", 5))
            continue
        if err in ("expired_token", "access_denied"):
            sys.exit("\n授权失败: %s" % err)
        if td.get("access_token"):
            tok = td["access_token"]
            break

    if not tok:
        sys.exit("\n超时，未拿到 token")

    print("\n[+] 授权成功，token 长度 %d" % len(tok))
    os.environ["GH_TOKEN"] = tok

    # 3) 上传
    here = os.path.dirname(os.path.abspath(__file__))
    cmd = [sys.executable, os.path.join(here, "_push_github.py"), "--repo", a.repo]
    if a.private:
        cmd.append("--private")
    print("[+] 开始上传 ...")
    p = subprocess.run(cmd, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    sys.exit(p.returncode)


if __name__ == "__main__":
    main()
