# Tozo Security SDK (PHP/Laravel)

Tozo 统一身份认证与安全通信 SDK —— 单一 Composer 包，提供按 Profile 隔离的认证、请求签名、加解密、Token 签发/验证、Scope 授权与防重放能力。

> 权威设计基线：`docs/superpowers/specs/2026-08-21-Tozo统一身份认证与安全通信SDK设计报告-v0.0.2.md`
>
> 权威注释标准：`docs/中文注释标准-v0.0.3.md`（v0.0.2 仅为被继承的历史版本）

## 安装

```bash
composer require tozo/security-sdk
```

运行基线：PHP `>=7.4`；当前 Composer 约束实际要求 `illuminate/console ^8.83`，因此按 Illuminate 8.83+ 使用。完整 Laravel 8.5 应用尚未完成真实环境验证。可选依赖：`guzzlehttp/guzzle ^7.0`（使用内置 HTTP 传输时）。

PHP 7.4 兼容性由 `composer.json` 的 `config.platform.php = "7.4.0"` 锁定依赖解析目标。本轮当前 checkout 已在 PHP 8.0.2 与 PHP 7.4.3 两个版本上分别跑通全部八项检查。

## 快速开始

### 1. 发布配置并填三个键

```bash
php artisan vendor:publish --tag=tozo-security-config
```

`config/tozo_security.php` 只有三个键，不需要 `.env`：

```php
return [
    // service string｜本系统身份；参与签名原文绑定，是全部推导的起点。
    'service'     => 'tozo-app-api',

    // environment string｜运行环境；作为密钥命名空间前缀，两个环境不共用任何密钥。
    'environment' => 'production',

    // peers array｜对端名单；键为对端服务标识，值为其 HTTPS 根地址。
    // 声明即建立双向信任：自动生成 outbound_to_X 与 inbound_from_X 两个 Profile。
    'peers'       => [
        'pos-api' => 'https://pos-api.example.com',
    ],
];
```

Profile、`features`、`defaults`、`key_id` 全部由 SDK 按 `peers` 推导，无需手写。

### 2. 生成密钥

```bash
php artisan tozo:security:install
```

按 `peers` 推导出全部 `key_id`，在 `storage/app/tozo/keys/` 下生成同名 `.key` 文件并写 `.gitignore`。
加 `--dry-run` 只列清单不写盘。已存在的密钥不会被覆盖——覆盖会立即切断该关系两端的通信。

同一条关系两端必须持有**内容完全相同**的同名 `.key` 文件，需经安全通道同步；
两端各自生成会得到不同内容，结果是验签失败。

### 3. 挂载中间件与路由

把两个别名合并进 `app/Http/Kernel.php` 的 `$routeMiddleware`：

```php
'tozo.inbound'  => \Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware::class,
'tozo.response' => \Tozo\Security\Laravel\Middleware\ResponseIntegrityMiddleware::class,
```

Profile 名由第 2 步的命令输出，不要手写：

```php
Route::middleware(['tozo.inbound', 'tozo.response'])
    ->defaults('tozo_profile', 'tozo_app_api_inbound_from_pos_api')
    ->post('/api/callback', [CallbackController::class, 'handle']);
```

顺序固定：先 `tozo.inbound` 验签，再 `tozo.response` 生成响应保护。
入站解析绝不回退默认 Profile，漏绑或绑错会直接失败而非按错误规则放行。

### 4. 出站调用

按对端服务名选路，不必记 Profile 名，也不必拼 URL：

```php
app('tozo.http')->to('pos-api')->post('/api/orders', ['id' => 1]);
```

加密、签名、附加 Token、响应完整性验证全部由 SDK 完成。
未在 `peers` 中声明的对端会抛 `ConfigurationException`，不会静默回退到其他 Profile。

### 5. 体检

```bash
php artisan tozo:security:check-config --runtime
```

`--runtime` 追加密钥可读性与缓存连通性探测。通过后再接流量。

完整接入指南见 [`docs/Tozo-Security-SDK-四系统Composer安装与两两互调操作指南-v0.0.9.md`](docs/Tozo-Security-SDK-四系统Composer安装与两两互调操作指南-v0.0.9.md)，
可直接复制的八套实际配置见 [`docs/四系统实际配置文件-v0.0.9/`](docs/四系统实际配置文件-v0.0.9/README.md)。

上生产前请读 [`docs/Tozo-Security-SDK-生产部署手册-v0.0.9.md`](docs/Tozo-Security-SDK-生产部署手册-v0.0.9.md)：
覆盖密钥目录权限、共享缓存后端要求、分批上线顺序、健康检查、排障对照表、回滚与密钥轮换。
上面这份快速开始只保证「装上能跑」，不覆盖生产环境的权限与基础设施约束。

## 安全默认值（摘要）

- Token 签发默认关闭（`features.token_issuer=false`）；
- HMAC-SHA256 常量时间比较；防重放 TTL = max_age + 2×clock_skew + margin（默认 ≥425s）；
- AES-256-GCM 信封 v1（CSPRNG 96-bit nonce，AAD 方向绑定，禁止外部 IV）；
- JWT 固定算法 + kid 白名单 + iss/aud/sub/client/scope 强绑定；吊销查询 fail-closed；
- 响应完整性双向闭环：服务端按固定 mode 生成保护，调用端先验证后交业务；
- 签名 query 以线上原始字节为唯一事实来源（重复键与方括号键不折叠、不碰撞）；
- ReplayStore / 吊销存储故障一律拒绝请求（503 temporarily_unavailable）。
- Profile 安全配置显式 `null` 一律拒绝；关闭功能必须写明确的 `false`，省略字段才允许使用约定默认值。
- Token 开关必须与 Profile 方向一致：入站只允许 `verify_enabled`，出站只允许 `attach_enabled`/`issue_enabled`；吊销只允许入站 Token 验证。

## 协议一致性

`protocol/test-vectors-v1.json` 冻结了 Protocol v1 的 10 组 70 条固定测试向量，是跨语言实现的唯一一致性基准。规则说明见 [`protocol/README.md`](protocol/README.md)。

三种语言的独立实现均已逐字节复现该向量：

| 实现 | 版本 | 比对项 | 结果 |
|---|---|---:|---|
| PHP（参考实现） | 7.4.3 / 8.0.2 | 115 断言 | 一致 |
| Python（仅标准库） | 3.9.13 | 92 | 一致 |
| Go（仅标准库） | 1.25.7 | 92 | 一致 |

```bash
composer run conformance    # 一次跑完 PHP + Python + Go
```

Python 与 Go 实现位于 `protocol/conformance/`，从零按协议文字规则编写、不移植 PHP 源码——只有这样才能证明规范本身无歧义。详见 [`protocol/conformance/README.md`](protocol/conformance/README.md)。

新语言实现接入时直接读取向量文件，不要复制后各自修改。

## 代码风格约定

本项目自有方法遵循三条硬约定，均由测试固化：

| 约定 | 固化测试 |
|---|---|
| 不使用返回类型声明 | `ApiStyleTest` |
| 不使用 `?Type` nullable 参数（用 `Type $param = null`） | `ApiStyleTest` |
| 不使用 PHP 8.0+ 专有语法 | `Php74CompatibilityTest` |

## 验证

```bash
composer install
composer run verify        # lint + 规范自查 + 全量测试 + 向量漂移检查
composer run conformance   # PHP + Python + Go 三语言协议一致性
```

单项入口：

| 命令 | 作用 |
|---|---|
| `composer run lint` | src/tests/config/tools 全量 `php -l` |
| `composer run audit-style` | 方法注释完整性、BOM、Tab、孤立注释块、未使用导入 |
| `composer run audit-members` | 每个类成员与配置键都有中文注释 |
| `composer run audit-depth` | 中文注释深度：剥掉标注后的实质说明字数与方法三段说明 |
| `composer run headers-check` | 每个文件都有 PhpStorm 头部标识块 |
| `composer run test` | 全量单元与集成测试 |
| `composer run vectors-check` | 冻结向量未被实现悄悄改写 |
| `composer run vectors` | 重新生成向量（破坏性变更须升协议版本） |
| `composer run examples-check` | 四系统示例包与生成规则一致 |
| `composer run examples` | 重新生成 `docs/四系统实际配置文件-v0.0.9/` |

用指定 PHP 版本验证最低兼容性：

```bash
path\to\php7.4\php.exe tools/lint.php
path\to\php7.4\php.exe vendor/bin/phpunit --no-coverage
```

CI 配置见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)：PHP 7.4/8.0/8.1/8.2 矩阵（含 7.4 最低依赖组合）+ 跨语言协议一致性 + 分发包内容检查。

当前验证状态：

```text
PHP 8.0.2（本轮）→ lint 127 个文件 0 失败 ｜ 319 tests, 1561 assertions 全通过
PHP 7.4.3（本轮）→ lint 127 个文件 0 失败 ｜ 319 tests, 1561 assertions 全通过；八项检查全过
规范自查       → src 具名方法注释合规、类成员与配置键均有中文注释且说明深度达标、0 BOM、0 Tab、0 孤立注释块、0 未使用导入
协议一致性 →  PHP 8.0.2 / Python 3.9.13 / Go 1.25.7 三实现与 70 条冻结向量逐字节一致
示例包       → docs/四系统实际配置文件-v0.0.9 共 45 个文件，与生成规则逐字节一致
```

完整验证结果与安全行为的测试锚点见 [`docs/test-reports/2026-08-30-Tozo-SDK-验证报告-v0.0.9.md`](docs/test-reports/2026-08-30-Tozo-SDK-验证报告-v0.0.9.md)，
详细模块接入方式见 [`docs/Tozo-Security-SDK-各模块使用说明书-v0.0.9.md`](docs/Tozo-Security-SDK-各模块使用说明书-v0.0.9.md)，生产部署见 [`docs/Tozo-Security-SDK-生产部署手册-v0.0.9.md`](docs/Tozo-Security-SDK-生产部署手册-v0.0.9.md)，四系统安装与互调方式见 [`docs/Tozo-Security-SDK-四系统Composer安装与两两互调操作指南-v0.0.9.md`](docs/Tozo-Security-SDK-四系统Composer安装与两两互调操作指南-v0.0.9.md)，可直接复制的测试/生产配置文件见 [`docs/四系统实际配置文件-v0.0.9/README.md`](docs/四系统实际配置文件-v0.0.9/README.md)，配置精简的方案空间与否决理由见 [`docs/Tozo-Security-SDK-配置精简方案-v0.0.9.md`](docs/Tozo-Security-SDK-配置精简方案-v0.0.9.md)，审查结论与已修复缺陷清单见 [`docs/Tozo-Security-SDK-全量审查与可行性报告-v0.0.5.md`](docs/Tozo-Security-SDK-全量审查与可行性报告-v0.0.5.md)。
