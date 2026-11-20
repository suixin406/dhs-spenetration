#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_push_github.py — 用 GitHub REST API 直传（不需要 git），兼容空仓库

用法:
  python _push_github.py --repo dsh-pentest-preset [--owner suixin406] [--wait]

  --wait  仓库不存在时轮询等待（最多 15 分钟），一出现就推
"""
import argparse
import base64
import json
import os
import sys
import time

try:
    import requests
except Exception:
    sys.exit("需要 requests")

API = "https://api.github.com"
HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(HERE, "_gh_token.txt")

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "targets", "loot", "recon", "exploit", "screens", "logs"}
SKIP_FILES = {".DS_Store", "Thumbs.db", "cordis.patch.yml.bak", "_gh_token.txt"}
SKIP_EXT = {".pyc", ".log", ".zip", ".bak"}


def collect():
    out = []
    for dirpath, dirnames, filenames in os.walk(HERE):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in SKIP_FILES:
                continue
            if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, HERE).replace("\\", "/")
            out.append((rel, full))
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="dsh-pentest-preset")
    ap.add_argument("--owner", default="")
    ap.add_argument("--branch", default="")
    ap.add_argument("--wait", action="store_true")
    ap.add_argument("--wait-min", type=int, default=15)
    a = ap.parse_args()

    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not tok and os.path.exists(TOKEN_FILE):
        tok = open(TOKEN_FILE).read().strip()
    if not tok:
        sys.exit("缺 token：设 GH_TOKEN 或先跑 _gh_auth_and_diag.py")

    H = {"Authorization": "Bearer " + tok,
         "Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28",
         "User-Agent": "dsh-pentest-preset-push"}

    owner = a.owner
    if not owner:
        r = requests.get(API + "/user", headers=H, timeout=30)
        if r.status_code != 200:
            sys.exit("token 无效: %d %s" % (r.status_code, r.text[:200]))
        owner = r.json()["login"]
    print("[+] owner: %s   repo: %s" % (owner, a.repo))

    # 等仓库出现
    repo_url = "%s/repos/%s/%s" % (API, owner, a.repo)
    deadline = time.time() + a.wait_min * 60
    while True:
        r = requests.get(repo_url, headers=H, timeout=30)
        if r.status_code == 200:
            break
        if not a.wait or time.time() > deadline:
            sys.exit("仓库不存在（%d）。请先到 https://github.com/new 建一个空的 %s"
                     % (r.status_code, a.repo))
        print("  ... 等待仓库创建（%ds）" % int(deadline - time.time()), flush=True)
        time.sleep(10)

    repo = r.json()
    print("[+] 仓库就绪: %s | default_branch=%s | perms=%s"
          % (repo["html_url"], repo.get("default_branch"), repo.get("permissions", {}).get("push")))
    branch = a.branch or repo.get("default_branch") or "main"

    files = collect()
    print("[+] 待上传 %d 个文件" % len(files))

    ok = fail = 0
    first = True
    for rel, full in files:
        try:
            raw = open(full, "rb").read()
        except Exception as e:
            print("  ! 读失败 %s: %s" % (rel, e)); fail += 1; continue
        content = base64.b64encode(raw).decode()
        url = "%s/repos/%s/%s/contents/%s" % (API, owner, a.repo, rel)

        sha = None
        gr = requests.get(url, headers=H, timeout=30, params={"ref": branch})
        if gr.status_code == 200:
            sha = gr.json().get("sha")

        payload = {"message": "add %s" % rel, "content": content}
        if sha:
            payload["sha"] = sha
        # 空仓库首次提交不能带 branch（该 branch 还不存在）
        if not first or sha:
            payload["branch"] = branch

        pr = requests.put(url, headers=H, timeout=90, json=payload)
        if pr.status_code in (200, 201):
            ok += 1
            first = False
            if ok % 15 == 0:
                print("  ... %d/%d" % (ok, len(files)))
        else:
            # 空仓库的兜底重试：去掉 branch
            if "branch" in payload:
                payload.pop("branch")
                pr = requests.put(url, headers=H, timeout=90, json=payload)
                if pr.status_code in (200, 201):
                    ok += 1
                    first = False
                    continue
            fail += 1
            print("  ! %s -> %d %s" % (rel, pr.status_code, pr.text[:140]))
        time.sleep(0.12)

    print("\n=== 完成 ===")
    print("  成功 %d  失败 %d" % (ok, fail))
    print("  仓库: %s" % repo["html_url"])


if __name__ == "__main__":
    main()
