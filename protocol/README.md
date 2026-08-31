# Tozo Security Protocol v1 — 测试向量

本目录是**协议事实来源**，不是 PHP SDK 的一部分。任何语言的实现都必须逐字节复现这里的向量。

## 文件

| 文件 | 用途 |
|---|---|
| `test-vectors-v1.json` | Protocol v1 固定测试向量（10 组，70 条） |

## 使用方式

PHP 参考实现由 `tests/Unit/ProtocolVectorTest.php` **只读消费**该文件。

新语言实现接入时：

1. 直接读取本 JSON，不要复制后各自修改。
2. 对每个向量组实现对应函数，逐条断言输出与 `expected` 完全一致。
3. 全部通过后才可以宣称"支持 Protocol v1"。

## 向量组说明

| 组 | 条数 | 验证内容 |
|---|---:|---|
| `normalize_path` | 14 | path 规范化：折叠斜杠、解析 `.`/`..` 点段、去尾斜杠、剥离 query/fragment |
| `canonical_query_string` | 15 | 原始 query 字符串规范化：拆对、解码重编码、字节序排序 |
| `canonical_query_array` | 9 | 数组入口渲染为 wire 字节 + 规范化结果（两者必须与字符串入口一致） |
| `normalize_content_type` | 5 | 主类型小写、去除 `; charset=` 参数 |
| `base64url_encode` | 7 | RFC 4648 §5 无 padding 编码 |
| `base64url_decode` | 6 | 严格解码；非法输入必须为 `null`（不得宽松解出错误字节） |
| `signature` | 5 | 11 字段规范化串 + Body SHA-256 + HMAC-SHA256 签名 |
| `aead_aad` | 3 | AES-GCM 的 7 字段方向绑定 AAD |
| `response_signature` | 3 | 响应签名 6 字段原文 + 签名值 |
| `replay_ttl` | 3 | ReplayStore TTL 公式 |

## 关键固定规则

### 规范化串（11 字段，`\n` 连接，顺序不可变）

```text
protocol_version
METHOD                 统一大写
path                   规范化后
query                  规范化后
content_type           小写、去参数
body_sha256_hex        小写十六进制
timestamp              Unix 秒
nonce
client_id
target_service
key_id
```

### query 规范化（最容易出错的一项）

**必须以线上原始 query 字符串为唯一输入，不得先转成本语言的 map/dict/数组。**

原因：多数语言的 query 解析会把重复键 `?a=1&a=2` 折叠为最后一个值，把 `?filter[status]=open` 解析成嵌套结构。若调用端与服务端各自从解析结果重建，会得到不同签名原文，合法请求被误判为签名失败；嵌套结构还会丢失子键名，使不同 query 折叠出同一原文（签名不再唯一绑定 query）。

步骤：

1. 去掉前导 `?`；空串直接返回空串。
2. 按 `&` 拆分，丢弃空段。
3. 每段按**首个** `=` 拆为键、值；无 `=` 时值为空串。
4. 键与值分别解码（`+` 视为空格；字面加号必须以 `%2B` 传输），再以 RFC 3986 规则重新百分号编码。
5. 把每个 `键=值` 字符串按**字节序**排序。
6. 用 `&` 连接。

该函数必须**幂等**：`canonical(canonical(x)) == canonical(x)`。最终 URL 本身就应是规范形态。

### 数组/map 入口的渲染规则

当调用方只持有结构化参数时，先渲染为 wire 字节再走上面的规范化：

- **顺序列表 → 重复键**：`{tag: ["one","two"]}` → `tag=one&tag=two`
  不使用 `tag[0]=one`（方括号索引是 PHP 特有语义，其他语言会当作字面键名）。
- **关联结构 → 方括号子键**：`{filter: {status: "open"}}` → `filter%5Bstatus%5D=open`
  必须保留子键名，否则产生字节碰撞。

### path 规范化

1. 仅当输入带 scheme（`https://…`）时才解析出 path 部分；纯路径不要交给 URL 解析器（前导 `//` 会被当成主机名而丢掉第一段）。
2. 剥离 query 与 fragment。
3. 折叠连续 `/`。
4. 逐段解析：空段与 `.` 丢弃，`..` 回退一层（已在根目录时忽略，不得逃出根）。
5. 结果以 `/` 开头；无段时为 `/`。

### AEAD AAD（7 字段，`\n` 连接）

```text
envelope_version
direction              request 或 response
client_id
target_service
METHOD                 大写（响应方向可为空串）
path                   规范化后
key_id                 该方向的加密用途 key_id
```

方向绑定使请求方向的密文无法当作响应通过校验。

### 响应签名原文（6 字段，`\n` 连接）

```text
envelope_version
"response"             固定字面量
client_id
target_service
body_sha256_hex
key_id                 响应签名用途 key_id
```

### ReplayStore TTL

```text
ttl = max_age_seconds + 2 × clock_skew_seconds + replay_safety_margin_seconds
```

实现不得把 TTL 设置得低于该结果，否则合法重试可能被误判或重放窗口出现空隙。

## 关于向量中的密钥

`_meta.hmac_key_ascii` 是公开示例密钥（32 个 `k` 字符），**仅供测试向量使用**。任何环境都不得使用该值。

## 变更规则

本文件一旦冻结即视为协议契约：

- 修改任何 `expected` 值 = 破坏性协议变更，必须升协议版本（v2），不能改 v1。
- 新增向量组或条目属于兼容性补充，可在 v1 内进行。
- 实现与向量不一致时，**以向量为准修实现**，不得为了让测试通过而改向量。
