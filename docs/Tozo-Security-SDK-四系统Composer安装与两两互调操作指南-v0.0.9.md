# Tozo Security SDK 四系统 Composer 安装与两两互调操作指南

版本：v0.0.9
编制日期：2026-08-30
适用 SDK：`tozo/security-sdk` 0.0.x
上一版本：v0.0.7（配置精简前，保留作回退参照）

## 0. 本版变化

配置精简后接入步数从约 38 步降到 6 步。以下三节在本版**整段删除**，不再需要：

| v0.0.7 章节 | 处置 |
|---|---|
| §4 环境变量模板（31 个变量） | 删除。不再读 `.env` |
| §5 `config/tozo_security.php` 最小配置（100 行） | 删除。配置只剩 3 个键 |
| §8 24 个 Profile 清单与密钥（53 行） | 删除。由 `tozo:security:install` 输出 |

可直接复制的实际接入文件入口：[`docs/四系统实际配置文件-v0.0.9/README.md`](四系统实际配置文件-v0.0.9/README.md)。

**本指南到 `check-config --runtime` 通过为止。** 上生产还需处理密钥目录权限、
共享缓存后端、分批上线顺序、健康检查、排障与回滚——那些内容在
[`Tozo-Security-SDK-生产部署手册-v0.0.9.md`](Tozo-Security-SDK-生产部署手册-v0.0.9.md)。

> 本指南是操作模板。四个业务仓库、Redis、TLS 证书和测试数据不在本 SDK 仓库中，
> 因此本文落盘不等于四系统已完成真实安装或互调验收。

## 1. 目标与边界

四个系统使用同一个 Composer 包。每声明一个对端，SDK 自动生成一对 Profile（出站 + 入站）与四个用途密钥标识。

基线是 `signed_request`：请求 HMAC-SHA256、Nonce 防重放、时间窗、独立的响应 HMAC-SHA256。
需要 Token AND 语义或 Scope 时，把该条关系升级为 `token_plus_request_signature`。

`signed_request` 下签名密钥的归属就是认证主体，不产生 Token Scope。因此基线路由不要写 `tozo.inbound:scope`。

SDK 不替代 HTTPS、反向代理访问控制、Redis 高可用、密钥管理系统、限流与业务授权。
请求密钥与响应密钥始终分离，测试与生产密钥始终分离——后者由 `environment` 参与密钥命名空间强制保证。

## 2. 四个系统环境

| 系统目录 | 服务标识 | 测试域名 | 生产域名 |
|---|---|---|---|
| `tozoApp-api` | `tozo-app-api` | `https://app-api.example.test` | `https://app-api.example.com` |
| `app-admin-api` | `app-admin-api` | `https://app-admin-api.example.test` | `https://app-admin-api.example.com` |
| `pmc-api` | `pmc-api` | `https://pmc-api.example.test` | `https://api-pms.example.com` |
| `pos-api` | `pos-api` | `https://pos-api.example.test` | `https://pos-api.example.com` |

服务标识参与签名原文绑定，不可随意改动。域名只出现在配置的 `peers` 段。

> 上表域名是**占位值**。`example.com` / `example.test` 是 RFC 2606 保留域名，
> 不会解析到真实主机，照抄上线会在出站时连接失败。请替换为本环境实际部署地址。
> 本仓库不记录真实域名，实际值由各系统在自己的 `config/tozo_security.php` 中填写。

### 2.1 域名怎么配

域名是配置项，不是代码常量。SDK 内部没有任何硬编码地址，出站地址一律从
`config/tozo_security.php` 的 `peers` 段读取，因此换域名、加对端、下线对端都只改这一个文件，
不需要改动 SDK、不需要 `.env`、不需要重新生成密钥。

`peers` 的键值分工不同，改动代价也不同：

| 项 | 含义 | 是否参与签名 | 改动影响 |
|---|---|---|---|
| 键（服务标识） | 对端身份，如 `pos-api` | **是**，绑定进签名原文 | 两端必须一致，改了就验签失败 |
| 值（`base_uri`） | 对端 HTTPS 根地址 | 否，仅用于出站选路 | 可随时改，不影响签名与密钥 |

**要用的时候**——填上真实地址即可，一行一个对端：

```php
'peers' => [
    'app-admin-api' => 'https://app-admin-api.内网域名',
    'pmc-api'       => 'https://pms.内网域名',
    'pos-api'       => 'https://pos.内网域名',
],
```

**不用的时候**——整条注释掉或删除。该对端不生成 Profile、不需要其密钥，其余关系不受影响。
保留成注释是记住服务标识拼写的最省事做法：

```php
'peers' => [
    'app-admin-api' => 'https://app-admin-api.内网域名',
    // 'pos-api'    => 'https://pos.内网域名',  // 暂不与 POS 互调
],
```

`peers` 留空数组（`[]`）表示尚未接入：SDK 装上即可启动，但不建立任何信任关系、不加载任何密钥。
这是 `vendor:publish` 后的初始状态，方便先装包、后接线。

**测试与生产的域名分别写在各自环境的配置里。** 同一份代码换环境只改 `environment` 与
`peers` 的域名两处；`environment` 参与密钥命名空间，因此两个环境不共用任何密钥文件，
测试域名不可能借用生产密钥。

改完域名后不必重跑 `tozo:security:install`（密钥只与 `service` / `environment` / 对端标识有关，
与域名无关），但建议跑一次体检确认配置自洽：

```bash
php artisan tozo:security:check-config --runtime
```

## 3. 接入六步

以下是单个系统的完整接入流程。四个系统各执行一遍，差异只有 `service` 与 `peers` 两项。

### 第 1 步：安装

```bash
composer require tozo/security-sdk:^0.0
php artisan vendor:publish --tag=tozo-security-config
```

包发现自动注册 `Tozo\Security\ServiceProvider`。若宿主关闭了 package discovery，在 `config/app.php` 手动加入：

```php
'providers' => [
    \Tozo\Security\ServiceProvider::class,
],
```

### 第 2 步：填三个键

编辑 `config/tozo_security.php`。以 `tozo-app-api` 生产环境为例：

```php
return [
    // service string｜本系统身份；参与签名原文与 AAD 绑定，是全部推导的起点。
    'service'     => 'tozo-app-api',

    // environment string｜运行环境；作为密钥命名空间前缀，两个环境不共用任何密钥。
    'environment' => 'production',

    // peers array｜对端名单；键为对端服务标识，值为其 HTTPS 根地址。
    // 域名为占位值，替换为本环境实际地址；键名不要改动。配置规则见 §2.1。
    'peers'       => [
        'app-admin-api' => 'https://app-admin-api.example.com',
        'pmc-api'       => 'https://api-pms.example.com',
        'pos-api'       => 'https://pos-api.example.com',
    ],
];
```

三个键里只有 `peers` 的域名需要填真实值，且只填本环境的。占位域名不替换会在第 6 步互调时连接失败。

到此为止不需要写 Profile、`features`、`defaults`、`key_id`，也不需要 `.env` 与 `tozo_services.php`。

### 第 3 步：生成密钥

```bash
php artisan tozo:security:install
```

命令按 `peers` 推导出本系统需要的 12 个 `key_id`，在 `storage/app/tozo/keys/` 下生成同名 `.key` 文件，
并写入 `.gitignore` 忽略全部 `*.key`。

正式执行前可先预览计划：

```bash
php artisan tozo:security:install --dry-run
```

已存在的密钥文件**不会被覆盖**——覆盖会立即切断该关系两端的通信。轮换需先删除两端旧文件再重新执行。

### 第 4 步：与对端交换密钥

这是整套流程唯一无法自动完成的一步，也是最容易出错的一步。

| 要求 | 原因 |
|---|---|
| 同一条关系两端持有**内容完全相同**的同名 `.key` 文件 | 两端各自生成会得到内容不同的同名文件，结果是验签失败而非配置报错 |
| 只能一方生成后同步给另一方 | 同上 |
| 经安全通道同步，不用邮件、聊天工具或工单系统 | 这些渠道会留下无法回收的副本 |

以 `tozo-app-api` 与 `pos-api` 之间为例，两边都必须持有这四个文件且内容一致：

```text
production_tozo-app-api_to_pos-api_request.key
production_tozo-app-api_to_pos-api_response.key
production_pos-api_to_tozo-app-api_request.key
production_pos-api_to_tozo-app-api_response.key
```

### 第 5 步：挂载中间件与路由

把两个别名合并进 `app/Http/Kernel.php` 的 `$routeMiddleware`（不要覆盖整个 Kernel）：

```php
'tozo.inbound'  => \Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware::class,
'tozo.response' => \Tozo\Security\Laravel\Middleware\ResponseIntegrityMiddleware::class,
```

为每个对端注册一条入站路由。Profile 名由第 3 步的命令输出，不要手写：

```php
Route::middleware(['tozo.inbound', 'tozo.response'])
    ->defaults('tozo_profile', 'tozo_app_api_inbound_from_pos_api')
    ->post('/api/internal/tozo-security/from-pos-api/health', [TozoSecurityController::class, 'handle']);
```

两个中间件顺序固定：先 `tozo.inbound` 验签，再 `tozo.response` 生成响应保护。
入站解析绝不回退默认 Profile，因此漏绑或绑错会直接失败，不会静默按错误规则放行。

### 第 6 步：体检

```bash
php artisan tozo:security:check-config --runtime
```

`--runtime` 会额外探测每个被引用的密钥是否可读、缓存后端是否连通。通过后再接流量。

## 4. 出站调用

按对端服务标识选路，不需要记 Profile 名，也不需要拼 URL：

```php
$response = app('tozo.http')
    ->to('pos-api')
    ->post('/api/orders', ['id' => 1]);

$data = $response->json();
```

加密、签名、附加 Token、响应完整性验证全部由 SDK 完成。未在 `peers` 中声明的对端会抛
`ConfigurationException` 并列出已声明的对端，不会静默回退到其他 Profile。

绝对 URL 的旧写法仍然支持，但需显式传 Profile：

```php
$profile = app('tozo_security.profiles')['tozo_app_api_outbound_to_pos_api'];
app('tozo.http')->post('https://pos-api.example.com/api/orders', ['id' => 1], [], $profile);
```

## 5. 入站读取调用方身份

只读取中间件写入的已验证值，不要从 `input()`/`query()` 重新取身份字段——那些值未经验签：

```php
public function handle(Request $request)
{
    $profile = $request->attributes->get('tozo_security_profile');
    $subject = $request->attributes->get('tozo_security_subject');

    return response()->json([
        'status'  => 'ok',
        'profile' => $profile === null ? null : $profile->getName(),
        'caller'  => $subject === null ? null : $subject->getClientId(),
    ]);
}
```

## 6. 12 条有向互调关系

四系统两两互调共 12 条有向关系。每条关系两端各持一个 Profile，共 24 个：

| 调用方 | 接收方 | 调用方的 Profile | 接收方的 Profile |
|---|---|---|---|
| `tozo-app-api` | `app-admin-api` | `tozo_app_api_outbound_to_app_admin_api` | `app_admin_api_inbound_from_tozo_app_api` |
| `tozo-app-api` | `pmc-api` | `tozo_app_api_outbound_to_pmc_api` | `pmc_api_inbound_from_tozo_app_api` |
| `tozo-app-api` | `pos-api` | `tozo_app_api_outbound_to_pos_api` | `pos_api_inbound_from_tozo_app_api` |
| `app-admin-api` | `tozo-app-api` | `app_admin_api_outbound_to_tozo_app_api` | `tozo_app_api_inbound_from_app_admin_api` |
| `app-admin-api` | `pmc-api` | `app_admin_api_outbound_to_pmc_api` | `pmc_api_inbound_from_app_admin_api` |
| `app-admin-api` | `pos-api` | `app_admin_api_outbound_to_pos_api` | `pos_api_inbound_from_app_admin_api` |
| `pmc-api` | `tozo-app-api` | `pmc_api_outbound_to_tozo_app_api` | `tozo_app_api_inbound_from_pmc_api` |
| `pmc-api` | `app-admin-api` | `pmc_api_outbound_to_app_admin_api` | `app_admin_api_inbound_from_pmc_api` |
| `pmc-api` | `pos-api` | `pmc_api_outbound_to_pos_api` | `pos_api_inbound_from_pmc_api` |
| `pos-api` | `tozo-app-api` | `pos_api_outbound_to_tozo_app_api` | `tozo_app_api_inbound_from_pos_api` |
| `pos-api` | `app-admin-api` | `pos_api_outbound_to_app_admin_api` | `app_admin_api_inbound_from_pos_api` |
| `pos-api` | `pmc-api` | `pos_api_outbound_to_pmc_api` | `pmc_api_inbound_from_pos_api` |

密钥标识按 `{environment}_{调用方}_to_{接收方}_{用途}` 推导。全网每环境 24 个密钥
（12 条关系 × 请求/响应），每个系统持有与自己相关的 12 个。

上表由 `ConfigNormalizer` 的推导规则唯一决定，`ConfigNormalizerTest` 与
`FourSystemConfigurationTest` 共同锁死其对称性——两端推导结果不一致时测试即失败。

## 7. 按关系升级安全等级

需要 Token AND 语义时，把该对端改为数组形态。其余对端保持字符串形态，不受影响：

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

| `security_mode` | 语义 | 适用场景 |
|---|---|---|
| `signed_request`（默认） | 只验请求签名，签名密钥归属即认证主体 | 内部系统互调基线 |
| `token_plus_request_signature` | Token 与签名必须同时通过（AND） | 写操作、敏感操作、外部合作方 |
| `token_only` | 只验 Token，不做请求签名 | 仅限评审过的低风险幂等读接口 |

升级后重新执行 `tozo:security:install` 补齐新增的加密与 Token 密钥，并与对端同步。

## 8. 可选覆盖项

以下均有内置默认值，只在需要偏离时才写进配置文件：

```php
// http array｜出站传输参数。默认 timeout=10、connect_timeout=3、verify=true、min_version=TLSv1.2。
'http' => [
    'timeout' => 30,
],

// key_providers array｜密钥来源。默认 file，目录为 storage/app/tozo/keys。
'key_providers' => [
    'driver' => 'file',
    'file'   => ['path' => '/etc/tozo/keys'],
],

// logging array｜SDK 安全日志。默认 enabled=true、channel=null、level=info。
'logging' => [
    'channel' => 'security',
],

// default_profile string｜绑定默认出站 Profile 后可省略 to() 调用。
// 不声明时每次调用必须经 to() 选路，避免请求被签往意料之外的目标。
'default_profile' => 'tozo_app_api_outbound_to_pos_api',
```

TLS 证书校验默认开启，生产环境不得关闭。

## 9. 与 v0.0.7 的对照

| 项目 | v0.0.7 | v0.0.9 |
|---|---|---|
| 配置文件数 | 2（`tozo_security` + `tozo_services`） | 1 |
| 单套配置行数 | 548 | 约 25 |
| 单套配置键数 | 224 | 3 |
| `.env` Tozo 变量数 | 31（含 12 个密钥） | 0 |
| 手写样板代码 | 1856 行 | 0 |
| 密钥来源 | 环境变量，变量名需人工从 `key_id` 推导 | 受控目录，`key_id` 由 SDK 推导 |
| 出站调用 | 手写 `TozoSecurityClient`（每套 108 行） | `->to('pos-api')` |
| 跑通一次 A→B | 约 38 步 | 6 步 |

## 10. 兼容性

Protocol v1 未改动。签名规范化串、AEAD AAD、响应签名原文的字段与顺序完全不变，
因此 v0.0.7 与 v0.0.9 的系统可以互相通信——前提是双方 `key_id` 对齐。

旧的完整配置形态仍受支持：`ConfigNormalizer` 只在检测到极简形态（同时存在非空 `service`
与数组 `peers`）时才展开，已有部署不需要立即迁移。

从 v0.0.7 迁移时 `key_id` 命名会变化（原 `production_a_to_b_request` 变为
`production_tozo-app-api_to_app-admin-api_request`）。灰度期可在配置中显式覆盖
`key_id` 保持旧命名，或两端同时切换。

## 11. 未由本仓库证明的事项

以下内容本 SDK 仓库无法验证，必须由业务项目在自己的环境中验收：

- 真实 Laravel 8.5 应用的完整启动与中间件链路
- Redis 作为共享 ReplayStore 的多实例原子性
- TLS 证书链、反向代理转发与 `X-Forwarded-*` 处理
- staging 环境四系统两两互调的端到端连通性
- 密钥经部署系统注入受控目录的权限与轮换流程
