---
name: passive-recon
description: 【侦察】被动信息收集：不接触目标主机，仅使用公开数据源
whenToUse: 需要在不暴露自身的情况下收集目标资产情报时
role: recon
category: 侦察
tags: [osint, passive, dns]
enabled: true
---



## 数据源
- 证书透明日志（crt.sh）：`curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sort -u`
- DNS 记录：`dig +short <domain> A/AAAA/MX/TXT/NS`
- whois：注册人、网段、ASN
- 搜索引擎与代码托管平台：泄露的子域、密钥、内部地址
- 公开端口测绘数据（Shodan/Censys/FOFA 等，需授权 API）

## 落库要求
每条发现调用 redteam_asset_upsert，provenance 固定为 `passive`，tool 记录具体数据源。

## 判废
| 现象 | 结论 |
|---|---|
| 被动源返回的历史 IP 已失效 | 记"历史 IP 失效"，不当结论 |
| 只拿到公开 WHOIS | 无额外信息 |
| 社交平台搜到同名账号 | 需归属验证，不算资产 |

## 一·补、可执行命令

```bash
curl -sS "https://api.hackertarget.com/hostsearch/?q=<domain>"
curl -sS "https://otx.alienvault.com/api/v1/indicators/domain/<domain>/passive_dns"
curl -sS "https://api.mnemonic.no/pdns/v3/<domain>"
curl -sS "https://rapiddns.io/subdomain/<domain>?full=1"
curl -sS "https://crt.sh/?q=%25.<domain>&output=json"
curl -sS "https://web.archive.org/cdx/search/cdx?url=*.<domain>&output=json&limit=200"
curl -sS "https://rdap.org/domain/<domain>"
```
