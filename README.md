# dsh-pentest-preset

面向 **DeepSeek Harness (DSH)** 的渗透与逆向一体化 Agent 预设。

**56 个阶段技能 + 48 篇实战知识库 + 6 个命令行工具 + 自动决断引擎。**

不是提示词合集，是一套能自己决策下一步打哪里的执行体：给一个 URL/IP/域名/APK，它按信号自动分流到对应手法，打到出结果为止。

---

## 组成

### 1. 56 个技能（skills/）

**方法论层（16 个 `pentest-*`）** —— 回答「怎么测」

| 技能 | 覆盖 |
|---|---|
| `pentest-recon` | 资产铺图、泛解析止损、云 CDN CNAME 指纹、源站定位 |
| `pentest-fingerprint` | `Server` 头 → 精确版本 → 分流 |
| `pentest-middleware` | nginx/Tengine/Apache/IIS/Tomcat 版本 CVE + 配置类（alias 穿越、merge_slashes、PATH_INFO、走私降级） |
| `pentest-cve-live` | CVE 实时查询三层：CISA KEV 在野利用 → NVD 版本区间 → nuclei 模板 |
| `pentest-crypto` | AES/DES/SM4/RSA 识别、ECB/CBC 判定、密钥定位、签名复现 |
| `pentest-auth` | 默认口令、注册、JWT、越权、**token 位置四枚举**、固定设备 token 识别 |
| `pentest-otp` | 验证码/短信码/邮件码：三态 oracle、窗口测量、限流探测、并发爆破 |
| `pentest-injection` | SQLi 全类型、命令注入、SSTI、XXE、**SQL 报错逐列 walk** |
| `pentest-upload` | 任意后缀、路径穿越、对象存储不可执行判定 |
| `pentest-ssrf` | 内网、云元数据、盲 SSRF 外带 |
| `pentest-deser` | Java/PHP/.NET/Python/Node 反序列化 |
| `pentest-framework-cve` | Spring/Shiro/Struts2/Log4j2/Fastjson/ThinkPHP/Laravel/国产面板 |
| `pentest-mobile` | APK/IPA 解包、strings 取接口与密钥、证书固定绕过、动态抓包 |
| `pentest-privesc` | Linux/Windows 提权、容器逃逸 |
| `pentest-lateral` | 凭证复用、隧道、数据库跳板 |
| `pentest-reverse` | 静态/动态逆向、脱壳、协议还原 |

**操作工具链层（40 个）** —— 回答「怎么打/怎么落地」

```
侦察  passive-recon fofa-recon recon-pipeline asset-correlation active-scan
      netspy-recon browser-automation kimi-webbridge deepseek-web-intel
      mobile-code-recon web-fingerprint
验证  asset-deep-scan nuclei-scan unauth-exploit dir-bruteforce oob-verify api-data-exfil
隧道  chisel-tunnel frp-tunnel suo5-tunnel c2-infra vps-reverse-shell shell-handler
横向  host-post-exploit lateral-movement ad-attack cloud-k8s network-device
      credential-attack fscan-intranet gogo-intranet supply-chain
编排  campaign-planning specialist-paths opsec-hygiene score-coverage
      cn-proxy-pool redteam-setup ai-agent-attack webshell-toolkit
```

### 2. 知识库（知识库/，49 篇）

实战方法论与测试清单，与技能配合使用：

- **`打穿短表.md`** —— 90 条手法索引，四列：`认什么 / 打哪 / 出什么算成 / 假点`
- 专题：`idor-test` `authbypass-test` `injection-test` `ssrf-test` `file-upload-test`
  `logic-test` `race-condition-test` `cache-poisoning-test` `http-smuggling-test`
  `deserialization-test` `oauth-jwt-test` `websocket-test` `graphql-test`
  `path-traversal-lfi-test` `prototype-pollution-test` `xss-test` `xxe-test`
  `subdomain-takeover-test` `type-juggling-test` `waf-bypass` `recon-methodology`
  `js-reverse-guide` `info-leak-test` `api-gateway-test` …

**用法**：进站先读 `打穿短表.md`，对得上再打开对应模块；**不要每站通读整库**。

### 3. 工具（tools/，6 个，无额外依赖）

| 工具 | 用途 |
|---|---|
| `jsintel.py` | 从前端 bundle 提取 API 路径、baseURL、AES 密钥候选、表单字段、懒加载分块 |
| `crypto_tool.py` | AES/DES 加解密、密钥爆破、签名复现（md5/sha1/hmac） |
| `otp_brute.py` | 验证码并发爆破，带 oracle 判定、限流探测、进度与吞吐统计 |
| `apk_extract.py` | APK 解包提取 URL/API/密钥/字段（纯 Python，不依赖 jadx） |
| `http_concurrent.py` | 高并发请求框架，带 AES 解密钩子、重试、限速、结果落盘 |
| `jwt_tool.py` | JWT 解码、alg=none 测试、payload 篡改、HS256 密钥爆破 |

```bash
python tools/jsintel.py https://target/assets/index.abc.js -o loot/intel
python tools/crypto_tool.py dec --key '=^%7@84%0^!8892-' --b64 '<cipher>'
python tools/otp_brute.py --url https://api/x/reset --param 'email=a@b.com&code={code}' --probe-only
python tools/jwt_tool.py decode eyJ...
```

### 4. 自动决断引擎（PROMPT.md）

53 行决断表，按五层组织：**侦察 → 识别 → 破门 → 落地 → 编排**。
每拿到一个信号（新目标 / 指纹 / 登录框 / 加密响应 / 验证码 / shell / 内网），立刻查表选下一发，不等确认。

**七条硬纪律**（实战踩坑沉淀）：
1. 进站先读 `打穿短表.md`
2. 参数名不准盲猜，先扒前端 bundle / APK
3. token 位置必须四枚举（header / query / body / cookie）
4. 固定 token 要识别（注册接口返回同一个 token = 设备票，不是账号）
5. 泛解析止损（随机子域能解析就放弃子域字典）
6. 配置类漏洞优先于 CVE（版本要精确匹配，配置错永远在）
7. CVE 以实时为准（KEV → NVD → nuclei，静态表只作索引）

---

## 安装

### 方式一：本地路径安装（推荐）

```bash
git clone https://github.com/<you>/dsh-pentest-preset.git
```

然后在 DSH 里：

```js
plugin_manager({
  action: "install_bundle",
  target: "<clone 下来的绝对路径>"
})
```

安装后在 **设置 → Agent 预设** 里选择「渗透与逆向」。

### 方式二：手动挂载

把本目录加入你的 profile 依赖，并在 `cordis.patch.yml` 里：

```yaml
- id: agent-preset-registry
  name: "@deepseek-ai/dsh-agent-preset-registry"
  config:
    selectedDefault: pentest
```

---

## 目录结构

```
dsh-pentest-preset/
├── package.json            # dsh.bundle.patch -> cordis.patch.yml
├── cordis.patch.yml        # 预设注册（persona 运行时读 PROMPT.md）
├── PROMPT.md               # 人设 + 决断引擎 + 七条纪律
├── skills/                 # 56 个技能，每个 <name>/SKILL.md
│   ├── pentest-*/          # 16 个方法论技能
│   └── <40 个操作技能>/
├── 知识库/                  # 49 篇实战方法论
│   ├── README.md
│   ├── 打穿短表.md
│   └── ...-test.md
└── tools/                  # 6 个命令行工具
```

---

## 产出规范

每个目标单独一个目录，禁止混放：

```
targets/<host>/
  recon/      原始探测输出
  exploit/    利用脚本与回显
  loot/       数据/凭证/文件
  logs/       时间线
  screens/    截图
  notes.md    结论
  meta.json   状态、凭证、shell
```

---

## 来源与致谢

- 知识库：`知识库/` 目录来自实战沉淀的 SRC 方法论合集
- 40 个操作技能：来自 [CallMeGuLab/dsh-purge-safe](https://github.com/CallMeGuLab/dsh-purge-safe)（MIT），本仓库做了目录适配
- CVE 保鲜设计思路：借鉴其「模板层 / 公告层 / 情报层 / 经验层」四层分离
- 方法论技能（`pentest-*`）与决断引擎：本仓库原创，来自两个真实目标的完整对抗记录

---

## 许可

MIT
