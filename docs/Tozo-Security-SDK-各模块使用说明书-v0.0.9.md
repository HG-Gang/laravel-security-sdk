# Tozo Security SDK 各模块使用说明书

版本：v0.0.9（配置精简后修订）
编制日期：2026-08-30
上一版本：v0.0.5（2026-08-28）
运行基线：PHP >= 7.4；当前 Composer 实际要求 Illuminate Console ^8.83，完整 Laravel 8.5 应用尚未完成真实环境验证；Protocol v1

自动化证据：

```text
PHP 8.0.2（本轮）  →  lint 127 文件 0 失败 ｜ 319 tests, 1561 assertions 全通过
PHP 7.4.3（本轮）  →  lint 127 文件 0 失败 ｜ 319 tests, 1561 assertions 全通过；八项检查全过
规范自查   →  方法注释合规、类成员与配置键均有中文注释且说明深度达标、0 BOM、0 Tab、0 孤立注释块、0 未使用导入
协议向量   →  protocol/test-vectors-v1.json 冻结 70 条；PHP / Python 3.9.13 / Go 1.25.7 三实现逐字节一致
示例包     →  docs/四系统实际配置文件-v0.0.9 共 45 个文件，与生成规则逐字节一致
```

## 0. 本版变化（配置精简）

配置形态发生根本变化：**接入方只需声明「我是谁 / 什么环境 / 跟谁通信」三项**，
Profile、`features`、`defaults`、`key_id` 全部由 SDK 按对端名单推导。

| 项目 | v0.0.5 | v0.0.9 |
|---|---|---|
| 配置文件数 | 2（`tozo_security` + `tozo_services`） | 1 |
| 单套配置行数 | 548 | 约 25 |
| 单套配置键数 | 224 | 3 |
| `.env` Tozo 变量数 | 31（含 12 个密钥） | 0 |
| 密钥来源 | 环境变量，变量名需人工从 `key_id` 推导 | 受控目录，`key_id` 由 SDK 推导 |
| 出站调用 | 手写目标 URL 与 Profile | `->to('pos-api')` |

协议层未改动：签名规范化串、AEAD AAD、响应签名原文的字段与顺序完全不变，
v0.0.5 与 v0.0.9 的系统可互相通信（前提是双方 `key_id` 对齐）。

旧的完整配置形态**仍受支持**：`ConfigNormalizer` 只在检测到极简形态时才展开，
已有部署不需要立即迁移。本文第 4、5、6 节中关于手写 Profile 与 `features` 的说明
对旧形态继续有效。

四系统落地文件：[`四系统实际配置文件-v0.0.9/README.md`](四系统实际配置文件-v0.0.9/README.md)。
按四个系统分别提供 `testing` 与 `production`，共 8 套接入文件；每套只有 4 个文件，
配置文件仅 3 个键，不含任何密钥占位符——密钥由 `tozo:security:install` 生成到受控目录。
每个显式 `tozo_profile` 路由仍必须携带匹配的 `X-Tozo-Client-Id`，该 Header 不是可省略的装饰字段。

配置精简的方案空间、否决理由与硬约束清单见
[`Tozo-Security-SDK-配置精简方案-v0.0.9.md`](Tozo-Security-SDK-配置精简方案-v0.0.9.md)；
六步接入流程见
[`Tozo-Security-SDK-四系统Composer安装与两两互调操作指南-v0.0.9.md`](Tozo-Security-SDK-四系统Composer安装与两两互调操作指南-v0.0.9.md)；
生产部署（权限、共享缓存、上线顺序、排障、回滚、密钥轮换）见
[`Tozo-Security-SDK-生产部署手册-v0.0.9.md`](Tozo-Security-SDK-生产部署手册-v0.0.9.md)。

三份文档的分界：本说明书讲**每个模块怎么用**，接入指南讲**怎么装进项目**，
部署手册讲**怎么安全送上生产**。

## 1. 能力矩阵

只描述**已实现并有测试覆盖**的能力。

| 能力 | driver | 状态 |
|---|---|---|
| 认证 | `jwt`、`hmac_bearer_sha256` | supported |
| 请求签名 | `hmac_sha256` | supported |
| 请求/响应加密 | `aes_256_gcm` | supported |
| 响应完整性 | `encrypted`、`signed`（生成 + 验证双向） | supported |
| Token | `jwt_rs256`、`jwt_hs256` | supported |
| KeyProvider | `env`、`file`、`array`（仅测试） | supported |
| 审计 | `cache`、`log` | supported |
| 防重放 / 吊销 | Laravel Cache 适配器 | supported |
| `api_key`、`legacy_signature`、`sodium_secretbox`、`opaque_token`、Refresh Token | — | unsupported |

SDK 不替代 TLS，不提供集中式密钥管理、用户登录或 OAuth/OIDC 端点。

## 2. 安装与验证

```bash
composer require tozo/security-sdk
php artisan vendor:publish --tag=tozo-security-config
```

填好 `config/tozo_security.php` 的三个键后生成密钥：

```bash
php artisan tozo:security:install            # 生成全部密钥文件 + 写 .gitignore
php artisan tozo:security:install --dry-run  # 只列清单，不写任何文件
```

命令按 `peers` 推导出全部 `key_id`，在 `storage/app/tozo/keys/` 下生成同名 `.key` 文件，
并输出需与对端交换的密钥清单与入站路由要绑定的 Profile 名。
已存在的密钥**不会被覆盖**——覆盖会立即切断该关系两端的通信；轮换需先删除两端旧文件。

同一条关系两端必须持有**内容完全相同**的同名 `.key` 文件。这一步无法自动完成：
两端各自生成会得到不同内容，结果是验签失败而非配置报错。

`ServiceProvider::register()` 先经 `ConfigNormalizer` 把极简配置展开为内部完整形态；
`ServiceProvider::boot()` 再构建并全量校验所有启用 Profile。结构错误、模式矛盾、
引用未开启功能、非法 driver 或非法 `key_id` 格式在**启动阶段**抛 `ConfigurationException`。

部署前体检：

```bash
php artisan tozo:security:check-config            # 结构链路
php artisan tozo:security:check-config --runtime  # 追加密钥存在性与缓存连通性
```

返回码 `0` 通过、`1` 有错，可直接用于 CI。`--runtime` 只报告能否解析，输出不含密钥值。

开发本包时的验证入口：

```bash
composer run verify          # 全部检查项
composer run conformance     # PHP + Python + Go 三语言协议一致性
composer run lint            # 仅语法检查
composer run audit-style     # 方法注释完整性、BOM、Tab、孤立注释块、未使用导入
composer run audit-members   # 每个类成员与配置键都有中文注释
composer run audit-depth     # 中文注释深度：实质说明字数与方法三段说明
composer run headers-check   # 每个文件都有 PhpStorm 头部标识块
composer run test            # 仅测试
composer run vectors-check   # 仅检查冻结向量未被实现改写
composer run examples-check  # 四系统示例包与生成规则一致
composer run examples        # 重新生成四系统示例包
```

### 2.1 PHP 7.4 兼容性保障

三层保障，缺一不可：

| 层 | 机制 |
|---|---|
| 依赖解析 | `composer.json` 的 `config.platform.php = "7.4.0"`，使 lock 文件解析出 7.4 可安装的组合 |
| 静态语法 | `tests/Unit/Php74CompatibilityTest.php` 扫描全量源码，禁止 8.0+ 专有语法 |
| 运行时 | 用 PHP 7.4 二进制实跑 `tools/lint.php` 与全量测试 |

若缺少 `config.platform.php`，Composer 会按开发机 PHP 版本解析依赖，生成的 lock 在 7.4 宿主上会被 `vendor/composer/platform_check.php` 直接拒绝启动。

被静态守卫拦截的构造：8.0 新增字符串/类型函数、`match`、`?->`、构造器属性提升、`mixed`/`static` 类型声明、Attributes、非捕获 `catch`、`throw` 表达式。

## 3. 密钥管理（Key 模块）

### 3.1 受控文件（极简配置的默认方式）

极简配置默认使用 `file` driver，目录为 `storage/app/tozo/keys`，无需在配置文件中声明。
落在 `storage/app/` 下是因为 Laravel 默认不把该目录暴露给 web 服务器。

文件形态 `{key_id}.key`。`key_id` 必须匹配 `^[A-Za-z0-9._-]+$`，
解析后的真实路径必须仍在受控目录内（目录穿越被拒绝）。

需要指向其他受控挂载点（如容器 secret 卷）时显式覆盖：

```php
'key_providers' => [
    'driver' => 'file',
    'file' => ['path' => '/etc/tozo/keys'],
],
```

或在安装时用 `--dir` 指定：

```bash
php artisan tozo:security:install --dir=/etc/tozo/keys
```

**目录存在性在检索期校验，不在构造期**。这样设计是为了避免全新安装时的死锁——
若构造期就要求目录存在，`artisan` 会因目录缺失而无法启动，那条创建目录的
`tozo:security:install` 命令就永远跑不起来。目录缺失时 `getKey` 抛
`KeyNotFoundException`，使 `check-config --runtime` 能列出完整错误清单而非直接崩掉。

### 3.2 环境变量（旧部署方式，仍受支持）

`key_id` 转换规则：非字母数字替换为 `_`，整体大写，拼前缀 `TOZO_SECURITY_KEY_`。

```env
TOZO_SECURITY_KEY_DRIVER=env
# key_id=order-signing        → TOZO_SECURITY_KEY_ORDER_SIGNING
# key_id=order.api-encryption → TOZO_SECURITY_KEY_ORDER_API_ENCRYPTION
```

变量缺失或为空串一律抛 `KeyNotFoundException`，**不回退默认密钥**。

极简配置不再使用这种方式，原因是变量名需人工从 `key_id` 推导，
推导错误的表现是「配了但读不到」的 `KeyNotFoundException`；而推导后的变量名很长
（如 `TOZO_SECURITY_KEY_PRODUCTION_TOZO_APP_API_TO_APP_ADMIN_API_REQUEST`），
12 个密钥逐个手写极易出错。

### 3.3 密钥用途隔离（强制）

七类密钥必须是不同的 `key_id`，Profile 校验阶段强制其中两组：

```text
signature.key_id                          请求签名
encryption.key_id                         请求加密
response_integrity.encryption.key_id      响应加密（强制 ≠ 请求加密密钥）
response_integrity.signature.key_id       响应签名（强制 ≠ 请求签名密钥）
token.signing_key_id                      Token 签发
token.allowed_kids[kid]                   Token 验证公钥
authentication.key_id                     HMAC-Bearer 认证
```

### 3.4 轮换状态机

```text
pending → active → verify_only / decrypt_only → retired
```

写方向（签名、加密、签发、响应签名生成）**仅接受 `active`**；读方向（验签、解密、验证）接受 `active` 加对应迁移期状态。`retired` 任何用途都拒绝。

`ArrayKeyProvider` 可注入状态映射用于测试轮换；`Env`/`File` 不带状态元数据，视为全部 `active`。

## 4. Profile 与安全模式矩阵

Profile 表示一条**单向**通信信任关系，必须声明 `direction`。同一条调用链需要两个 Profile：调用方 `outbound`，被调用方 `inbound`。

| 模式 | 入站必须通过 | 出站必须附加 | `signature.enabled` | Token 开关 |
|---|---|---|---|---|
| `token_only` | 认证器 | Token | 必须 `false` | 入站 `verify_enabled=true` 或 `hmac_bearer_sha256`；出站 `attach_enabled`/`issue_enabled` |
| `signed_request` | 签名器 | 签名 | 必须 `true` | 禁止 attach/verify |
| `token_plus_request_signature` | 签名器 **AND** 认证器 | 签名 **AND** Token | 必须 `true` | 同 `token_only` 方向要求 |

三条硬规则：

- `token_plus_request_signature` 是 **AND** 语义，任一失败整体拒绝，绝不退化为另一模式。
- `signed_request` 以签名 `key_id` 归属为唯一认证主体，禁止叠加 Token 作为第二认证分支。
- `token_only` 仅允许用于评审过的低风险幂等路由，禁止用于写操作、资金、权限或敏感数据修改。
- Token 开关必须与 Profile 方向一致：入站只允许 `verify_enabled=true`，出站只允许 `attach_enabled=true` 或 `issue_enabled=true`；`token_revocation.enabled=true` 必须同时位于入站 `verify_enabled=true` 的 Profile。

### 4.1 配置优先级

```text
Profile 显式值 > tozo_security.defaults > SDK 内置默认值 > 安全必填项直接失败
```

`defaults` 只填充**完全缺失**的字段（`signature`/`encryption`/`token` 三段）。显式写 `null` 不被覆盖，保留到校验阶段按配置错误失败。关闭功能必须用 `enabled=false`，不能用 `null`。

## 5. 功能开关（features）

**极简配置下不需要声明 `features`，由 SDK 自动推导。**

`ConfigNormalizer` 遍历展开出的 Profile，按实际引用置位：

| 推导结果 | 触发条件 |
|---|---|
| `signature` | 存在 `signature.enabled=true` 的 Profile（基线即满足） |
| `response_integrity` | 存在 `response_integrity.required=true` 的 Profile（基线即满足） |
| `http_client`、`audit` | 存在出站 Profile（声明任意对端即满足） |
| `encryption` | 某条关系声明 `encryption => true` |
| `token_verifier`、`scope` | 某条关系升级为含 Token 验证腿的模式 |
| `token_issuer` | 某条关系升级为含 Token 附加腿的模式 |
| `authentication` | 入站 Profile 声明了 `authentication.driver` |
| `token_revocation` | 恒为 `false`，需显式配置完整形态才能开启 |

只声明对端而不升级安全模式时，`token_issuer` 与 `token_verifier` 均为 `false`——
保持「默认安装只验证不签发」这一设计约束（设计 §13）。

原先的双门控（开关为 `true` **且** 至少一个 Profile 引用）中，前一半完全可由后一半推导，
因此在极简配置中被移除。以下说明只对仍使用完整配置形态的旧部署有效：

有效能力需同时满足：

```text
features.{name} = true   AND   至少一个启用 Profile 实际引用该功能
```

两者任一不满足则不注册容器绑定。Profile 引用已关闭功能时，启动阶段抛 `ConfigurationException`。

```php
'features' => [
    'authentication' => true,
    'signature' => true,
    'encryption' => true,
    'response_integrity' => true,
    'token_verifier' => true,
    'token_issuer' => false,      // 默认关闭：只有授权签发系统才开
    'token_revocation' => false,
    'scope' => true,
    'http_client' => true,
    'audit' => true,
],
```

`token_issuer` 默认 `false` 是刻意设计：关闭时不注册 `TokenIssuerInterface`，避免普通系统无意加载 JWT 私钥。

## 6. 配置示例

### 6.0 极简形态（推荐）

整个配置文件只有三个键：

```php
return [
    // service string｜本系统身份；参与签名原文与 AAD 绑定，是全部推导的起点。
    'service'     => 'tozo-app-api',

    // environment string｜运行环境；作为密钥命名空间前缀，两个环境不共用任何密钥。
    'environment' => 'production',

    // peers array｜对端名单；键为对端服务标识，值为其 HTTPS 根地址。
    'peers'       => [
        'app-admin-api' => 'https://app-admin-api.example.com',
        'pmc-api'       => 'https://api-pms.example.com',
        'pos-api'       => 'https://pos-api.example.com',
    ],
];
```

推导规则：

| 推导项 | 规则 |
|---|---|
| Profile 名 | `{service}_outbound_to_{peer}` / `{service}_inbound_from_{peer}`（服务标识转 snake_case） |
| `client_id` | outbound 取 `service`；inbound 取 `peer` |
| `target_service` | outbound 取 `peer`；inbound 取 `service` |
| `subject_type` | 恒为 `service` |
| `subject_id` | 同 `client_id` |
| `signature.key_id` | `{environment}_{调用方}_to_{接收方}_request` |
| `response_integrity.signature.key_id` | `{environment}_{调用方}_to_{接收方}_response` |
| `security_mode` | `signed_request`（基线，可按关系升级） |
| 其余 19 个字段 | SDK 内置常量（协议版本、算法、时间窗、防重放、存储驱动） |

三个对端展开为 6 个 Profile 与 12 个密钥标识。展开结果仍经 `Profile::validate` 全量校验，
展开器不放宽任何约束。

上例域名为占位值（`example.com` / `example.test` 是 RFC 2606 保留域名，不会解析到真实主机），
接入时替换为本环境实际地址。

`peers` 的键与值性质不同：**键是对端服务标识，参与签名原文绑定，两端必须一致**，
改键名会直接导致验签失败；**值只是出站选路用的根地址，不参与签名**，
换域名、切内网地址、加端口都只改值，不影响密钥与 Profile 推导。

不需要某个对端时，把该条注释掉或删除即可 —— 不生成对应 Profile、不需要其密钥，其余关系不受影响：

```php
'peers' => [
    'app-admin-api' => 'https://app-admin-api.内网域名',
    // 'pos-api'    => 'https://pos.内网域名',  // 暂不与 POS 互调
],
```

`peers` 为空数组时 SDK 正常启动但不建立任何信任关系、不加载任何密钥，
这是 `vendor:publish` 后的初始状态。域名只改值不必重跑 `tozo:security:install`，
但建议跑 `tozo:security:check-config --runtime` 确认配置自洽。

### 6.0.1 按关系升级安全等级

某条关系需要 Token AND 语义或请求加密时改用数组形态，其余关系保持字符串形态：

```php
'peers' => [
    'pos-api' => [
        'base_uri'      => 'https://pos-api.example.com',
        'security_mode' => 'token_plus_request_signature',
        'encryption'    => true,
    ],
    'pmc-api' => 'https://api-pms.example.com',
],
```

升级后 SDK 追加推导 `encryption.key_id` 与 `token.signing_key_id`，
Token 腿按方向装配（出站附加、入站验证，两侧都不签发）。
重新执行 `tozo:security:install` 补齐新增密钥并与对端同步。

### 6.0.2 可选覆盖项

以下均有内置默认值，不声明时不出现在配置文件中：

```php
// http array｜出站传输参数。默认 timeout=10、connect_timeout=3、verify=true、min_version=TLSv1.2。
'http' => ['timeout' => 30],

// key_providers array｜密钥来源。默认 file，目录为 storage/app/tozo/keys。
'key_providers' => ['driver' => 'file', 'file' => ['path' => '/etc/tozo/keys']],

// logging array｜SDK 安全日志。默认 enabled=true、channel=null、level=info。
'logging' => ['channel' => 'security'],

// default_profile string｜绑定默认出站 Profile 后可省略 to() 调用。
// 不声明时每次调用必须经 to() 选路，避免请求被签往意料之外的目标。
'default_profile' => 'tozo_app_api_outbound_to_pos_api',
```

原 `tozo_services.php` 的 11 个键去向：`base_urls` 并入 `peers`；`environment` 与
`tozo_security.environment` 合并为单一事实来源；`tls`/`http` 四项下沉为上表的内置默认值。

### 6.1 完整形态：出站 Profile（调用方）

以下是旧的完整配置形态，仍受 SDK 支持。极简配置的展开结果与此等价，
接入方无需手写——列出是为了说明展开器生成了什么，以及旧部署如何继续维护。

```php
'svc_to_order' => [
    'enabled' => true,
    'direction' => 'outbound',
    'client_id' => 'product-center-production',
    'subject_type' => 'service',
    'subject_id' => 'product-center',
    'target_service' => 'order-api',
    'security_mode' => 'token_plus_request_signature',

    'authentication' => ['driver' => 'jwt'],

    'signature' => [
        'enabled' => true,
        'driver' => 'hmac_sha256',
        'key_id' => 'order-signing',
        'max_age_seconds' => 300,
        'clock_skew_seconds' => 60,
        'replay_protection' => true,
        'replay_safety_margin_seconds' => 5,
    ],

    'encryption' => [
        'enabled' => true,
        'driver' => 'aes_256_gcm',
        'key_id' => 'order-request-encryption',
    ],

    'response_integrity' => [
        'required' => true,
        'mode' => 'encrypted',
        'encryption' => ['key_id' => 'order-response-encryption'],
    ],

    'token' => [
        'attach_enabled' => true,
        'driver' => 'jwt_rs256',
        'issuer' => 'tozo-auth',
        'audience' => ['order-api'],
        'ttl_seconds' => 900,
        'signing_key_id' => 'product-center-token-signing',
    ],

    'scope' => ['allowed_scopes' => ['order.read', 'order.write']],
],
```

### 6.2 完整形态：入站 Profile（被调用方）

```php
'order_api_inbound' => [
    'enabled' => true,
    'direction' => 'inbound',
    'client_id' => 'product-center-production',
    'subject_type' => 'service',
    'target_service' => 'order-api',
    'security_mode' => 'token_plus_request_signature',

    'authentication' => ['driver' => 'jwt'],

    'signature' => [
        'enabled' => true,
        'driver' => 'hmac_sha256',
        'key_id' => 'order-signing',
    ],

    'encryption' => [
        'enabled' => true,
        'driver' => 'aes_256_gcm',
        'key_id' => 'order-request-encryption',
    ],

    // 必须与调用方 outbound 的 response_integrity 完全一致，否则响应会被对方拒绝。
    'response_integrity' => [
        'required' => true,
        'mode' => 'encrypted',
        'encryption' => ['key_id' => 'order-response-encryption'],
    ],

    'token' => [
        'verify_enabled' => true,
        'driver' => 'jwt_rs256',
        'issuer' => 'tozo-auth',
        'audience' => ['order-api'],
        'expected_client_id' => 'product-center-production',
        'allowed_subject_types' => ['service'],
        'allowed_kids' => ['tozo-auth-2026-08' => 'order-api-jwt-public-2026-08'],
        // 可选：'allowed_tenants' => ['t01', 't02'],
    ],

    'scope' => ['allowed_scopes' => ['order.read', 'order.write']],
    'replay_store' => ['driver' => 'cache'],
    'audit' => ['driver' => 'log'],
],
```

`client_id` 与 `target_service` 在配对的两个 Profile 中描述同一条信任关系，**必须相同**——它们参与签名原文与 AEAD AAD 的绑定。

## 7. 调用端：安全 HTTP Client

### 7.1 按对端名选路（推荐）

```php
use Tozo\Security\Contracts\HttpClientInterface;

public function __construct(HttpClientInterface $http)
{
    $this->http = $http;
}

public function createOrder(array $data)
{
    // to() 按 peers 声明选路：不必记 Profile 名，也不必拼 URL。
    $response = $this->http->to('pos-api')->post('/api/orders', $data);

    // required=true 时，到这里 Body 已完成完整性验证（encrypted 模式已是明文）。
    return $response->json();
}
```

`to($service)` 的语义：

| 行为 | 说明 |
|---|---|
| 选路依据 | 配置 `peers` 中声明的对端标识；根地址取该对端的 `base_uri` |
| 未声明的对端 | 抛 `ConfigurationException` 并列出已声明的对端，**不回退**到任意 Profile |
| 返回值 | **新实例**，原实例状态不变——与 `setProfile()` 的就地修改不同 |
| 相对路径 | 按绑定的根地址补全；传绝对 URL 时原样使用 |

返回新实例这一点很重要：`setProfile()` 会修改当前实例，若业务把同一实例存入静态属性
或跨服务传递，后调用者会覆盖前者的目标 Profile，使请求被签往错误的目标服务且无任何报错。
`to()` 与 `withProfile()` 都返回副本，从根上消除该污染。

### 7.1.1 绝对 URL 形态（旧写法，仍受支持）

```php
$profile  = app('tozo_security.profiles')['tozo_app_api_outbound_to_pos_api'];
$response = $this->http->post('https://pos-api.example.com/api/orders', $data, [], $profile);
```

五个入口：`get`、`post`、`put`、`patch`、`delete`。最后一个参数可传请求级 `Profile` 覆盖默认绑定。
未经 `to()` 选路且未配 `default_profile` 时，不传 `$profile` 会抛
`ConfigurationException('TozoHttpClient requires a profile')`——不猜测目标是有意设计。

### 7.2 出站七步固定流程

```text
1. 解析生效 Profile 并 validate()
2. 稳定序列化 Body（options.body 直传优先）
3. 可选加密 → Body 替换为信封 JSON（Encrypt-then-Sign 的"先加密"）
4. 对最终 wire Body 签名 → 写入 timestamp/nonce/body_hash/signature/key_id
5. 组装 Header 并按 attach_enabled 签发 Token
6. 发送 → 按 response_integrity 验证响应
7. 写入脱敏审计事件
```

顺序不可颠倒：签名必须覆盖**加密后**的最终字节，服务端才能在解密前完成身份与完整性验证。

### 7.3 请求选项

```php
$this->http->post($url, $data, [
    'headers' => ['X-Lang' => 'php'],   // 业务自定义头；X-Tozo-* 与 Authorization 会被安全值覆盖
    'query' => ['page' => 2],           // 按顶层键覆盖 URL 原有同名参数
    'request_id' => 'req-0001',         // 透传为 X-Request-Id
    'body' => '{"raw":true}',           // 直传原始 Body，跳过 $data 序列化
]);
```

### 7.4 构造签名

`auditSink` 是唯一必需依赖，位于首位：

```php
new TozoHttpClient(
    $auditSink,      // 必需
    $signer,         // 可选：signed/plus 模式必需
    $cipher,         // 可选：加密 Profile 必需
    $integrity,      // 可选：response_integrity.required 必需
    $tokenIssuer,    // 可选：attach_enabled 必需
    $transport       // 可选：测试桩；null 时回退 PendingRequest（需 guzzle）
);
```

必需参数若排在可选参数之后，PHP 会把前面的可选参数隐式当作必需参数，这是 v0.0.4 修复的缺陷，由测试固化。

### 7.5 Facade（可选）

```php
use Tozo\Security\Facade as TozoSecurity;

TozoSecurity::post('https://order-api.internal/api/orders', $data);  // 代理到 HttpClient
TozoSecurity::profile('svc_to_order');                              // 取已校验 Profile
TozoSecurity::featureEnabled('token_issuer');
```

代理调用依赖容器键 `tozo_security`，由 Provider 在 `features.http_client=true` 时绑定。核心代码仍应依赖接口注入而非 Facade。

## 8. 服务端：中间件

### 8.1 注册

```php
// app/Http/Kernel.php
protected $routeMiddleware = [
    'tozo.inbound' => \Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware::class,
    'tozo.response' => \Tozo\Security\Laravel\Middleware\ResponseIntegrityMiddleware::class,
];
```

或直接用容器绑定：`tozo.middleware.inbound`、`tozo.middleware.response`、`tozo.middleware.outbound`。

### 8.2 路由挂载

```php
// 顺序要求：入站认证在前，响应保护在后（响应保护依赖认证写入的 Profile）
Route::middleware(['tozo.inbound:order.write', 'tozo.response'])
    ->post('/api/orders', [OrderController::class, 'store']);

// 路由显式绑定 Profile（推荐：避免依赖 Header 索引）
Route::middleware(['tozo.inbound', 'tozo.response'])
    ->defaults('tozo_profile', 'order_api_inbound')
    ->post('/api/orders', [OrderController::class, 'store']);
```

中间件参数是逗号分隔的 required scopes，例如 `tozo.inbound:order.read,order.write`。

### 8.3 入站六步固定流程

```text
1. 解析唯一 Profile 候选（路由绑定优先，Header 仅作不可信索引）
2. 协议版本白名单校验
3. 按 security_mode 执行 AND 语义验证（验签内含 Nonce 原子登记）
4. 按需解密请求体并替换 Body
5. Scope 授权（required ⊆ granted，且主体类型命中白名单）
6. 注入 subject/profile/payload 到 request attributes 后放行
```

Profile 候选必须**唯一**。未知或多候选一律拒绝，绝不遍历 Profile 直到某个验签成功。

### 8.4 业务层读取认证结果

```php
public function store(Request $request)
{
    /** @var \Tozo\Security\Identity\Subject $subject */
    $subject = $request->attributes->get('tozo_security_subject');

    $subject->getSub();          // "service:product-center"
    $subject->getClientId();     // "product-center-production"
    $subject->getSubjectType();  // "service"
    $subject->getScopes();       // ["order.read"]
    $subject->getTenantId();     // 多租户上下文或 null
    $subject->getJti();          // 吊销与审计用
    $subject->hasScope('order.write');

    // 加密 Profile 下 $request->getContent() 已是解密明文。
    return response()->json(['ok' => true]);
}
```

### 8.5 响应完整性中间件

调用端声明 `response_integrity.required=true` 后，被调用方**必须**产出对应保护。挂载 `tozo.response` 即可自动完成。

| 条件 | 行为 |
|---|---|
| 请求未经入站认证（无 Profile attribute） | 原样放行（不为伪造请求签发有效证明） |
| `required != true` | 原样放行 |
| 响应非 2xx | 原样放行（保留错误状态语义） |
| `mode=encrypted` | Body 替换为信封 JSON，`Content-Type` 改为 `application/json` |
| `mode=signed` | Body 保持明文，追加 `X-Tozo-Response-Signature` 头 |
| 生成失败 / 绑定缺失 / 密钥不可用 | 返回 500 `internal_error`，**绝不写出未受保护 Body** |

手动调用（非中间件场景）：

```php
use Tozo\Security\Contracts\ResponseIntegrityInterface;

// 服务端生成
$envelope  = $integrity->protectEncryptedResponse($body, $inboundProfile);
$signature = $integrity->protectSignedResponse($body, $inboundProfile);
$header    = $integrity->getSignatureHeaderName();

// 调用端验证
$plaintext = $integrity->decryptEncryptedResponse($envelope, $outboundProfile);
$integrity->verifySignedResponse($body, $headers, $outboundProfile);
```

### 8.6 对外错误码映射

对外只暴露安全类别码，内部原因码仅进日志：

| 异常族 | HTTP | 对外 `error` |
|---|---|---|
| `ReplayStoreUnavailable` / `RevocationStoreUnavailable` | 503 | `temporarily_unavailable` |
| `Decryption` / `Protocol` | 400 | `invalid_request` |
| `Signature`（含重放、时钟偏差） | 401 | `invalid_signature` |
| `Scope` | 403 | `access_denied` |
| `Configuration` | 500 | `internal_error` |
| 其余认证族 | 401 | `invalid_authentication` |

响应体固定为 `{"error":"<类别>"}`，不含 Profile 名称、候选数量、密钥存在性或预期签名。

## 9. Signature 模块与 Protocol v1

### 9.1 规范化串（11 字段，`\n` 连接，顺序不可变）

```text
protocol_version / METHOD / path / query / content_type /
body_sha256_hex / timestamp / nonce / client_id / target_service / key_id
```

固定规则：

- `METHOD` 统一大写。
- `path` 以 `/` 开头，折叠连续斜杠，解析 `.` 与 `..` 点段（RFC 3986 §5.2.4），去尾斜杠（根路径除外），剥离 query 与 fragment。
- `query` 以**线上原始 query 字符串**为唯一事实来源。
- `content_type` 小写并去除 `; charset=...` 参数。
- `body` 为最终 wire-level Body 的 SHA-256 十六进制小写。

### 9.2 query 规范化的关键约束

**不得先把 query 转成 PHP 数组再规范化。** PHP/Symfony 会把重复键 `?a=1&a=2` 折叠为最后一个值、把 `?filter[status]=open` 解析成嵌套数组。双端若各自从数组重建，会得到不同签名原文，导致合法请求被误判为 `invalid_signature`；嵌套数组还会丢失子键名，使不同 query 折叠出同一原文。

数组入口（`options.query`）的渲染规则：

- 顺序列表 → **重复键**：`['tag'=>['one','two']]` → `tag=one&tag=two`（不用 PHP 的 `tag[0]=`，保证跨语言可复现）
- 关联数组 → **方括号子键**：`['filter'=>['status'=>'open']]` → `filter%5Bstatus%5D=open`
- `+` 与 `%20` 归一为 `%20`；字面加号必须以 `%2B` 传输

该函数是幂等的：`canonical(canonical(x)) == canonical(x)`，最终 URL 本身即规范形态。

### 9.3 时间窗与防重放

```text
接受窗口：|now - timestamp| <= max_age_seconds + clock_skew_seconds
ReplayStore TTL = max_age_seconds + 2 × clock_skew_seconds + replay_safety_margin_seconds
默认：300 + 2×60 + 5 = 425 秒
```

Nonce 为 16 字节 CSPRNG（32 hex 字符），**仅在签名常量时间比较通过后**才原子登记，避免无效请求污染共享状态。存储故障一律抛 `ReplayStoreUnavailableException`（fail-closed），禁止降级为仅时间校验。

生产必须使用所有实例可访问的共享存储，`add()` 需具备等价 `SET key value NX EX ttl` 的原子语义。多实例部署禁止用进程内数组或单机文件。

### 9.4 Header 集合

```text
X-Tozo-Protocol-Version   X-Tozo-Client-Id   X-Tozo-Key-Id
X-Tozo-Timestamp          X-Tozo-Nonce       X-Tozo-Signature
X-Request-Id              Authorization
```

任何 Header 都不能指定 driver、算法、Audience 或密钥。`token_only` 不写签名类 Header，且调用方残留的安全 Header 会被清除。

### 9.5 协议测试向量

`protocol/test-vectors-v1.json` 冻结 70 条向量（10 组），是跨语言实现的唯一一致性基准：

| 组 | 条数 | 验证内容 |
|---|---:|---|
| `normalize_path` | 14 | path 规范化 |
| `canonical_query_string` | 15 | 原始 query 规范化 |
| `canonical_query_array` | 9 | 数组入口 wire 字节 + 规范化 |
| `normalize_content_type` | 5 | 主类型小写去参数 |
| `base64url_encode` / `decode` | 7 / 6 | RFC 4648 §5 无 padding |
| `signature` | 5 | 11 字段串 + Body 哈希 + HMAC |
| `aead_aad` | 3 | 7 字段方向绑定 AAD |
| `response_signature` | 3 | 6 字段响应签名原文 |
| `replay_ttl` | 3 | TTL 公式 |

由 `tests/Unit/ProtocolVectorTest.php` **只读消费**。向量一经冻结即为协议契约：修改任何 `expected` 值等于破坏性协议变更，必须升协议版本，不能改 v1。实现与向量不一致时**以向量为准修实现**。

详见 `protocol/README.md`。

## 10. Encryption 模块

### 10.1 信封格式

```json
{
  "version": "1",
  "algorithm": "aes_256_gcm",
  "key_id": "order-request-encryption",
  "iv": "base64url-12字节",
  "ciphertext": "base64url",
  "tag": "base64url-16字节"
}
```

`algorithm` 与 `key_id` 只用于描述格式和索引候选密钥，服务端仍以 Profile 白名单为准；不一致立即拒绝。该方向未配置密钥时直接拒绝，不允许空 `key_id` 命中比对。

### 10.2 Nonce 与 AAD

`iv` 是 96-bit nonce，每次加密由 SDK 内部 CSPRNG 生成。**API 不接受外部注入 IV**，同一密钥下绝不重用。

AAD 绑定七字段（`\n` 连接）：

```text
信封版本 / 方向(request|response) / client_id / target_service /
大写 METHOD / 规范化 path / 加密 key_id
```

方向绑定使请求方向密文无法当作响应通过校验，也无法复制到另一客户端或另一接口。任何 AAD、tag、nonce 或密文校验失败都返回统一的解密失败结果，不部分解析明文。

### 10.3 密钥长度

对称密钥必须**恰好 32 字节**（AES-256）。长度不符抛 `ConfigurationException`，防止误配短密钥静默降级为更弱强度。

## 11. Token 模块

### 11.1 签发（默认关闭）

需同时满足：`features.token_issuer=true`、Profile `token.issue_enabled=true`、配置 `signing_key_id` 与 `subject_id`。

```php
$token = $issuer->issue($profile);
$token = $issuer->issue($profile, ['device_id' => 'd-01']);  // 附加自定义 claims
```

固定 claims：`iss`、`aud`、`sub`（`subject_type:subject_id`）、`client_id`、`subject_type`、`scope`、`iat`、`nbf`、`exp`、`jti`（16 字节 CSPRNG）。Header 携带 `kid = signing_key_id`。

受保护 claims 不可通过 `$extraClaims` 覆盖：`iss`、`aud`、`sub`、`client_id`、`subject_type`、`scope`、`iat`、`nbf`、`exp`、`jti`。

`granted_scopes = Profile allowed_scopes`，签发不得扩大权限。

### 11.2 验证

```php
$subject = $verifier->verify($token, $inboundProfile);
```

验证覆盖：固定算法（由 Profile driver 决定，**绝不信任 Header `alg`**）、签名、`kid` 白名单、`iss`、`aud` 交集、`iat/nbf/exp`（leeway 取 `token.clock_skew_seconds`）、`sub` 格式与类型白名单、`client_id`/`azp` 绑定、`scope` 白名单、`tenant_id` 白名单、吊销状态。

主体类型只以 `sub` 前缀为准，不信任 Token 自带的 `subject_type` 声明。

### 11.3 算法混淆防护

`tests/Unit/TokenAlgorithmConfusionTest.php` 固化以下负向断言（含正向对照）：

- `alg=none` 无签名 Token 被拒绝
- 用 RSA 公钥当 HMAC 密钥签出的 HS256 Token 被 RS256 Profile 拒绝（经典算法混淆）
- 不支持的算法声明被拒绝
- 未知 `kid` 被拒绝（原因码 `unknown_kid`）
- 缺失 `kid` 被拒绝
- 真实 RS256 Token 被 HS256 Profile 拒绝

防护原理：SDK 从不读取 Header `alg`，而是由 Profile driver 固定算法，以 `Key(材料, 算法)` 形式传入；底层库以常量时间比较 Header `alg` 与 Key 算法，不一致即抛异常。

### 11.4 kid 轮换

```php
'allowed_kids' => [
    'tozo-auth-2026-07' => 'order-api-jwt-public-2026-07',  // 旧公钥标记 verify_only
    'tozo-auth-2026-08' => 'order-api-jwt-public-2026-08',  // 新公钥 active
],
```

`kid` 必须先命中白名单才能取得候选公钥，不扫描所有公钥。

### 11.5 吊销（fail-closed）

```php
$store->revoke($subject->getJti(), $subject->getExpiresAt() - time() + $clockSkew);
```

`jti` 缺失、已吊销、存储故障、超时均拒绝该 Token，原因码分别为 `token_revoked` 或 `revocation_store_unavailable`。

`jti` 用于吊销与审计，**不等同于请求级防重放**——Bearer Token 在有效期内可重复提交，需要请求级防篡改必须选 `token_plus_request_signature`。

## 12. Scope 模块

```text
授权条件：required_scopes ⊆ granted_scopes
granted_scopes = Token scope ∩ Profile allowed_scopes
```

先校验主体类型命中 `allowed_subject_types`，再逐项校验 Scope。用户、服务、合作方的同名 Scope 不互相替代。

首版**禁止通配符**：`*` 或 `order.*` 在配置校验与运行期授权两处都会被拒绝。精确匹配，`order.read` 不匹配 `order.readonly`。

资源所有权、租户数据隔离和行级权限仍由业务层处理。

## 13. Storage 模块

| 契约 | 实现 | 键前缀 | 故障行为 |
|---|---|---|---|
| `ReplayStoreInterface` | `LaravelCacheReplayStore` | `tozo_replay\|` | `ReplayStoreUnavailableException` → 503 |
| `TokenRevocationStoreInterface` | `LaravelCacheTokenRevocationStore` | `tozo_revocation\|` | `RevocationStoreUnavailableException` → 503 |
| `AuditSinkInterface` | `LaravelCacheAuditSink` / `LaravelLogAuditSink` | `tozo_audit\|` | `SecurityException(audit_sink_unavailable)` → 503 |

HMAC-Bearer 认证使用独立前缀 `tozo_replay_auth|`，与请求签名 Nonce 隔离。ReplayStore 与 TokenRevocationStore 是两个独立契约，禁止混用同一条记录语义。

## 14. Audit 模块

审计后端按 Profile `audit.driver` 选择 `cache` 或 `log`。`log` 需要容器中存在 `Psr\Log\LoggerInterface` 绑定。由于 `AuditSinkInterface` 是共享容器绑定，多个启用的出站 Profile 必须使用同一个 driver；未声明时按 `cache` 处理，发现 `cache`/`log` 冲突会在 Provider 注册阶段抛出 `ConfigurationException`，不会静默采用首个 Profile。

`AuditSanitizer` 是唯一脱敏事实来源，落盘前强制剔除以下键（大小写不敏感）：

```text
signature  jwt  authorization  token  body
plaintext  secret  password  refresh_token  id_token
```

`payload.body_hash` 也会被剔除（属于请求内容派生信息）。

允许记录：请求 ID、主体、客户端、Profile、协议版本、`key_id`、driver、目标接口、原因码、状态码、耗时。

新增审计字段前必须先确认不落入禁止清单。

## 15. 异常体系

全部继承 `SecurityException`，携带稳定内部原因码：

```text
ConfigurationException          UnsupportedDriverException
AuthenticationException         InvalidSignatureException
ClockSkewException              ReplayProtectionException
ReplayStoreUnavailableException RevocationStoreUnavailableException
EncryptionException             DecryptionException
InvalidCiphertextException      ResponseIntegrityException
TokenIssuanceException          TokenVerificationException
InvalidTokenException           TokenExpiredException
TokenFormatException            TokenRevokedException
IssuerMismatchException         AudienceMismatchException
ClientIdMismatchException       SubjectTypeMismatchException
TenantMismatchException         ScopeMismatchException
ScopeDeniedException            KeyNotFoundException
ProtocolException
```

```php
try {
    $response = $this->http->post($url, $data);
} catch (\Tozo\Security\Exceptions\ResponseIntegrityException $e) {
    // 响应未通过完整性验证，不得使用 Body
    Log::warning('response rejected', ['reason' => $e->getReasonCode()]);
    throw $e;
}
```

`getReasonCode()` 属于内部信息，禁止直接返回给外部调用方。

## 16. 代码风格约定

本项目自有方法遵循三条硬约定，均由测试固化：

| 约定 | 固化测试 |
|---|---|
| 不使用返回类型声明 | `ApiStyleTest` |
| 不使用 `?Type` nullable 参数（用 `Type $param = null`） | `ApiStyleTest` |
| 不使用 PHP 8.0+ 专有语法 | `Php74CompatibilityTest` |

```php
// 正确
public function verify(string $token, Profile $profile){

// 错误：方法声明尾部增加返回类型；本项目不允许该声明
public function verify(string $token, Profile $profile){ /* 返回类型声明 */

// 错误：参数类型前增加 nullable 问号；本项目使用 Profile $profile = null
public function authenticate(Payload $payload, Profile $profile = null){
```

注释规范以 `docs/中文注释标准-v0.0.3.md` 为现行权威，由 `composer run audit-style` 校验：src 下每个具名方法必须有 PHPDoc，`@param` 覆盖全部签名参数，非构造器必须有 `@return`；src/tests/config/tools 同时接受 BOM、Tab 缩进、孤立注释块和未使用导入检查。v0.0.2 仅为被继承的历史版本。

## 17. 安全默认值与失败原则

- 默认拒绝未知 Profile、driver、`key_id` 和协议版本。
- 启用签名的 Profile 默认开启时间窗口与防重放。
- HMAC 与签名比较一律使用 `hash_equals` 常量时间比较。
- 配置、密钥、ReplayStore、吊销存储或审计后端缺失时**直接失败**，不 fail-open。
- 加密、验签、Token 异常不被吞掉。
- 生产禁止 `ArrayKeyProvider`（`environment=production` 时 Provider 直接拒绝）。
- 生产禁止输出安全中间值的调试接口。
- 结构校验不读取生产密钥、不连接 Redis；真实密钥与外部依赖只在运行期首次解析时接触。

## 18. 依赖版本说明

| 依赖 | 锁定版本 | 说明 |
|---|---|---|
| `firebase/php-jwt` | v6.10.0 | 6.x 中支持 PHP 7.4 的最高版本；6.11+ 与 7.x 均要求 PHP ^8.0 |
| `illuminate/*` | v8.83.27 | Laravel 8 LTS 线 |
| `symfony/*` | v5.4.x | 由 platform 锁定解析而来；v6.x 要求 PHP >= 8.0.2 |

### 关于 firebase/php-jwt 的 CVE-2025-45769

`firebase/php-jwt < 7.0.0` 存在 CVE-2025-45769（低危，标题为 weak encryption）。修复版本 7.x 要求 PHP ^8.0，与本 SDK 的 PHP >= 7.4 基线冲突，因此锁定在 6.10.0。

本 SDK 的用法不受该 CVE 的算法混淆攻击面影响，理由与证据：

1. 算法由 Profile driver 固定（`jwt_rs256` → RS256，`jwt_hs256` → HS256），SDK 从不读取 Header `alg`。
2. 密钥以 `Key(材料, 算法)` 形式传入，底层以常量时间比较 Header `alg` 与 Key 算法，不一致即抛异常。
3. `alg=none` 被底层的空算法与不支持算法两道检查拦截。
4. 上述行为由 `TokenAlgorithmConfusionTest` 的 7 个用例（含正向对照）固化。

若宿主项目可以接受 PHP >= 8.0 基线，建议改用 `firebase/php-jwt ^7.0` 并移除 `config.platform.php`。这属于宿主项目的版本策略决定，不是本 SDK 的默认选择。

## 19. 迁移指引（v0.0.5 → v0.0.9）

**协议层未改动**，签名规范化串、AEAD AAD、响应签名原文的字段与顺序完全不变。
两版系统可互相通信，前提是双方 `key_id` 对齐。

| 变更 | 影响 | 处理方式 |
|---|---|---|
| 配置可用极简形态（3 个键） | 配置文件 | 可选。旧完整形态继续可用，`ConfigNormalizer` 只在检测到极简形态时才展开 |
| `tozo_services.php` 取消 | 配置文件 | 迁移到极简形态时删除该文件；`base_urls` 并入 `peers`，`tls`/`http` 下沉为内置默认 |
| 不再读 `.env` | 部署 | 迁移到极简形态后 31 个 Tozo 环境变量可全部移除 |
| `features`/`defaults` 自动推导 | 配置文件 | 迁移到极简形态时删除这两段 |
| 密钥默认来源改为 `file` | 部署 | 执行 `tozo:security:install` 生成到受控目录；仍可显式声明 `key_providers.driver=env` 保留旧方式 |
| `key_id` 命名变化 | **密钥物料** | 见下方迁移路径 |
| `HttpClientInterface` 新增 `to()` | 自定义实现 | 若项目自行实现了该接口，需补上 `to()`；SDK 内只有 `TozoHttpClient` 一个实现 |
| `FileKeyProvider` 目录校验时机后移 | 启动行为 | 无需操作。目录缺失不再让 `artisan` 起不来，改为检索期报 `KeyNotFoundException` |
| 新增 `tozo:security:install` 命令 | 运维流程 | 替代手工创建 12 个密钥文件 |

### 19.1 迁移到极简形态

```php
// 迁移前：548 行、224 键、依赖 .env 的 31 个变量
// 迁移后：
return [
    'service'     => 'tozo-app-api',
    'environment' => 'production',
    'peers'       => [
        'app-admin-api' => 'https://app-admin-api.example.com',
        'pmc-api'       => 'https://api-pms.example.com',
        'pos-api'       => 'https://pos-api.example.com',
    ],
];
```

删除 `profiles`、`features`、`defaults`、`protocol_version`、`default_profile` 五段与
整个 `tozo_services.php`，随后执行 `tozo:security:install`。

### 19.2 `key_id` 命名变化与灰度

推导规则改为 `{environment}_{调用方}_to_{接收方}_{用途}`，例如：

```text
迁移前：production_a_to_b_request
迁移后：production_tozo-app-api_to_app-admin-api_request
```

原 a/b/c/d 字母代号虽是全局稳定映射，但要求所有人记住字母表，新人接手易出错。

**升级即断连的风险**：两端 `key_id` 不一致会导致验签失败。三种处理方式：

1. 两端同时切换（停机窗口内完成，最简单）
2. 灰度期保留旧命名：在极简配置外显式覆盖该 Profile 的 `key_id`
3. 把旧密钥文件按新命名复制一份，两套命名并存，确认无旧命名流量后再删旧文件

### 19.3 v0.0.4 → v0.0.5 的变更（历史）

| 变更 | 影响 | 处理方式 |
|---|---|---|
| 新增 `config.platform.php = 7.4.0` | 依赖版本 | 执行 `composer update` 使 lock 与 7.4 兼容 |
| `firebase/php-jwt` 降至 6.10.0 | JWT 行为 | 无 API 变化；如宿主已在 PHP 8 且需 7.x，见 §18 |
| 新增 `protocol/test-vectors-v1.json` | 跨语言实现 | 新语言实现须消费该文件 |
| 新增 `tools/lint.php`、`tools/audit.php` | 开发流程 | 用 `composer run verify` 替代手工检查 |
| 新增 `.gitattributes` | 分发体积 | 无需操作；`composer install` 不再拉取 tests/docs |

v0.0.3 → v0.0.4 的变更（`TozoHttpClient` 构造顺序、`ResponseIntegrityInterface` 新增方法、Payload `query` 语义、`tozo.middleware.response`、config BOM）见 v0.0.4 说明书第 18 节。

## 20. 未在本地验证的范围

以下项目**不能**因测试全绿而视为已证明：

| 项目 | 当前状态 |
|---|---|
| PHP 7.4 语法与运行时 | **已验证**：当前 checkout 在 PHP 7.4.3 跑通全部八项检查（127 文件 lint、319 tests） |
| Protocol v1 固定向量 | **已冻结并独立复核**（70 条） |
| JWT 算法混淆防护 | **已验证**（7 个负向 + 正向对照用例） |
| 完整 Laravel 8.5 应用 | 未验证：HTTP Kernel、路由参数、中间件 alias、`config:cache`、package discovery；Composer 当前实际锁定 Illuminate Console ^8.83 |
| Redis 多实例原子性 | 未验证：`add()` 原子性、TTL 精度、网络故障传播、并发压测 |
| 真实 HTTPS 传输 | 未验证：Guzzle、TLS、代理、超时、4xx/5xx、响应 Header 归一化 |
| 跨语言一致性 | **已验证**：Python 3.9.13 与 Go 1.25.7 两份独立实现与冻结向量逐字节一致（见 v0.0.6 报告） |
| 生产密钥管理 | 未验证：Vault/KMS、权限、轮换、备份、泄露响应流程 |
| 高并发性能 | 未验证：签名/加解密吞吐、Cache 争用、大 Body 内存 |
| 业务适用性 | SDK 不能替项目方判断某条路由是否适合 `token_only` |

四系统配置包的 8 套 `tozo_security.php` 已由 `FourSystemConfigurationTest` 逐个展开后通过
`ConfigChecker` 结构验证，每套 6 个 Profile；测试还验证 12 条有向关系两端密钥一致、
两个环境不共用任何密钥、路由绑定与 README 清单均回指展开结果、v0.0.9 的 32 个与 v0.0.8 的
48 个示例 PHP 文件语法有效。传输参数（timeout、connect_timeout、TLS verify）已下沉为
`ConfigNormalizer` 的内置默认值，最低 TLS 版本仍由宿主 TLS 栈或代理执行。

`ConfigNormalizerTest` 另以 17 个用例锁死推导规则的对称性：四系统各自独立展开后，
12 条有向关系在两端推导出的请求/响应密钥必须逐字符一致。这条是配置精简能否成立的前提——
推导规则若不对称，表现是验签失败而非配置报错。

这些仓库内验证不等于四个真实 Laravel 项目已经安装或完成 staging 互调。

接入生产前建议按此表逐项闭环。
