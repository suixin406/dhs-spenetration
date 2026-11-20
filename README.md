# dsh-pentest-preset

面向 **DeepSeek Harness（DSH）** 的授权安全测试与逆向 Agent 预设。

当前版本包含 **74 个技能、48 篇知识正文、6 个命令行工具**，并提供机器可执行的授权范围门禁、自动决断提示词、测试与打包检查。

> 适用范围：自建实验室、CTF/靶场、代码与样本分析，以及拥有书面授权的安全评估。网络操作以 `AUTHORIZED-TARGETS.json` 为准。

## 能力组成

### 34 个 `pentest-*` 方法论技能

覆盖侦察、指纹、中间件与 CVE、认证、越权、OTP、注入、上传、SSRF、反序列化、前端情报、源站定位、CORS、XSS、LFI、GraphQL、WebSocket、请求走私、竞态、业务逻辑、数据库、提权、横向、移动端和逆向等路径。

### 40 个操作与编排技能

覆盖被动/主动侦察、资产关联、Nuclei、目录发现、OOB 验证、内网扫描、隧道、Shell 处理、AD、云与 Kubernetes、网络设备、供应链、凭证验证、活动编排和证据覆盖。

其中 34 个操作 Skill 能与可选的 `dsh-purge-safe` 演练台运行时协同使用 `redteam_*` 资产库与证据链；没有该运行时时会退化为本地文件记录，不影响核心 Skill 和命令行工具。

### 48 篇知识正文

位于 `知识库/`。入口是 `知识库/打穿短表.md`，专题正文按信号加载，不建议每次通读全库。完整目录见 `知识库/README.md`。

### 6 个命令行工具

| 工具 | 用途 |
|---|---|
| `jsintel.py` | 从前端 bundle 提取 API、baseURL、字段、密钥候选和分块 |
| `crypto_tool.py` | AES ECB/CBC、编码识别、密钥字典和签名复现 |
| `otp_brute.py` | 受控范围内的验证码窗口、限流和并发验证 |
| `apk_extract.py` | APK 中的 URL、API、字段、密钥候选和 Manifest 字符串 |
| `http_concurrent.py` | 有界并发 HTTP 请求、重试、结果落盘和 AES 响应钩子 |
| `jwt_tool.py` | JWT 解码、篡改、alg=none 变体及 HS256/384/512 验证 |

另有两个维护/门禁工具：`scope_guard.py` 和 `sync-persona.py`。

## 运行要求

- DeepSeek Harness：目标版本 `0.2.2-rc.3`
- Node.js：18 或更高版本
- Python：3.10 或更高版本
- Python 依赖：仅并发 HTTP 和密码学功能需要 `requests`、`cryptography`

```bash
python -m pip install -r requirements.txt
```

本地文件版 `jsintel.py`、`apk_extract.py` 和 `scope_guard.py` 只使用 Python 标准库。

## 安装

```bash
git clone https://github.com/suixin406/dhs-spenetration.git
cd dhs-spenetration
python -m pip install -r requirements.txt
```

先建立实际授权范围：

```bash
cp AUTHORIZED-TARGETS.template.json AUTHORIZED-TARGETS.json
# 编辑 AUTHORIZED-TARGETS.json：目标、端口、动作级别、时间窗口、授权依据
```

Windows PowerShell：

```powershell
Copy-Item AUTHORIZED-TARGETS.template.json AUTHORIZED-TARGETS.json
```

然后在 DSH 中安装当前目录：

```js
plugin_manager({
  action: "install_bundle",
  target: "<仓库绝对路径>"
})
```

安装后在“设置 → Agent 预设”选择“渗透与逆向”。

### 可选：完整 `redteam_*` 演练台

需要资产库、证据链、记分和 `redteam_preflight` 时，另行安装兼容的 `dsh-purge-safe >= 2.0.0 < 3`。它会修改宿主运行逻辑，因此本包只把它声明为可选 peer，不会静默安装。

```bash
dsh plugin --profile web add https://codeload.github.com/CallMeGuLab/dsh-purge-safe/tar.gz/refs/heads/main
```

完整退出并重启对应 DSH host，再按该插件说明启用演练台。未安装时，预设会把证据写到 `targets/<host>/`，不会调用不存在的 `redteam_*` 工具。

## 范围门禁

配置采用默认拒绝。每个目标条目声明：

- `hosts`：精确域名、`*.example.test`、IP 或 CIDR；
- `ports`：端口、端口范围或 `*`；
- `actions`：`passive`、`active`、`exploit`、`destructive`；
- `validFrom` / `validUntil`：UTC/带时区时间窗口；
- `authorizationReference`：SOW、工单或靶场分配记录。

```bash
python tools/scope_guard.py https://target.example:443 --action active --json
```

破坏性动作即使在配置中允许，也需要本次显式确认：

```bash
python tools/scope_guard.py https://target.example:443 \
  --action destructive --confirm-destructive --json
```

退出码：`0` 允许，`2` 拒绝，`3` 配置或目标无效。

## 工具示例

TLS 证书默认校验；只有实验室自签证书才显式使用 `--insecure`。

```bash
python tools/jsintel.py ./index.js -o loot/intel
python tools/crypto_tool.py dec --key '=^%7@84%0^!8892-' --encoding base64 --b64 '<cipher>'
python tools/apk_extract.py app.apk -o loot/app
python tools/jwt_tool.py decode eyJ...
python tools/http_concurrent.py get --urls urls.txt --threads 20 --out loot/scan.txt
python tools/otp_brute.py --url https://lab/reset --param 'code={code}' --probe-only
```

## 证据目录

每个目标独立存放，避免不同范围和凭据混放：

```text
targets/<host>/
  recon/
  exploit/
  loot/
  logs/
  screens/
  notes.md
  meta.json
```

`targets/` 已被 `.gitignore` 排除。报告和截图仍应脱敏，令牌、Cookie、密钥和个人信息不进入公开提交。

## 开发与验证

```bash
npm run sync:persona        # PROMPT.md -> cordis.patch.yml
npm run check               # 元数据、计数、链接、范围模板、提示词同步、可移植性
python -m unittest discover -s tests -v
npm pack --dry-run
```

CI 在 Python 3.10/3.12 与 Node.js 20 上执行相同验证。发布前应保证工作区干净，并用正常的 Git commit/push 保持原子提交。

## 项目结构

```text
├── package.json
├── cordis.patch.yml
├── PROMPT.md
├── AUTHORIZED-TARGETS.template.json
├── skills/                 # 74 个技能
├── 知识库/                 # README + 48 篇正文
├── tools/                  # CLI、门禁与维护工具
├── scripts/                # 一致性检查与提示词同步
└── tests/                  # Python 单元/烟雾测试
```

## 来源与许可

- 本项目主体采用 MIT License。
- 部分操作 Skill 改编自 `CallMeGuLab/dsh-purge-safe`；当前上游采用 Apache License 2.0。
- 相关署名、修改说明和许可证副本见 `NOTICE`、`THIRD_PARTY_NOTICES.md` 与 `LICENSES/Apache-2.0.txt`。

项目与 DeepSeek AI、DSH 官方无隶属关系。
