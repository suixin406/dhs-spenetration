#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sync-persona.py — 把 PROMPT.md 同步进 cordis.patch.yml 的内联 prefix

为什么用内联而不用 !!js 运行时读取：
  实测 `!!js` 表达式在 baseUrl 不在作用域时会抛 ReferenceError，
  导致整块 persona 加载失败（模型失去全部指令）。内联写法已验证可用。

用法：
  python tools/sync-persona.py            # 同步
  python tools/sync-persona.py --check    # 只检查是否一致
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPT = os.path.join(ROOT, "PROMPT.md")
PATCH = os.path.join(ROOT, "cordis.patch.yml")
KEY = "prefix: |"


def persona_lines():
    with open(PROMPT, encoding="utf-8") as source:
        txt = source.read().replace("\r\n", "\n")
    lines = txt.split("\n")
    # 去掉开头的 markdown 标题行（与原始内联版本保持一致）
    while lines and (not lines[0].strip() or lines[0].lstrip().startswith("#")):
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def main():
    check = "--check" in sys.argv

    with open(PATCH, encoding="utf-8") as source:
        raw = source.read().replace("\r\n", "\n")
    lines = raw.split("\n")

    start = None
    for i, l in enumerate(lines):
        if l.strip().startswith("prefix:"):
            start = i
            break
    if start is None:
        sys.exit("找不到 prefix: 行")

    indent = len(lines[start]) - len(lines[start].lstrip())
    # 单行形式（!!js "..." 或 prefix: xxx）直接替换该行；
    # 块形式（prefix: |）替换到缩进结束
    is_block = lines[start].strip() in (KEY, "prefix: >", "prefix: |-")
    if is_block:
        end = start + 1
        while end < len(lines):
            l = lines[end]
            if l.strip() == "":
                end += 1
                continue
            if len(l) - len(l.lstrip()) <= indent:
                break
            end += 1
    else:
        end = start + 1

    pl = persona_lines()
    prefix_indent = " " * indent
    block = [prefix_indent + KEY]
    for l in pl:
        block.append(prefix_indent + "  " + l if l.strip() else "")
    # 尾部空行
    block.append("")

    new_lines = lines[:start] + block + lines[end:]
    new = "\n".join(new_lines)

    if check:
        same = new == raw
        print("in-sync" if same else "OUT-OF-SYNC (需要运行 sync-persona.py)")
        sys.exit(0 if same else 1)

    with open(PATCH, "w", encoding="utf-8", newline="\n") as destination:
        destination.write(new)
    print("synced: %d persona lines -> %s (%d bytes)" % (len(pl), PATCH, len(new.encode())))


if __name__ == "__main__":
    main()
