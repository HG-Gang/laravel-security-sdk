# Tozo Security SDK 生产部署手册

版本：v0.0.9
编制日期：2026-08-30
适用 SDK：`tozo/security-sdk` 0.0.x

## 本手册的定位

接入指南回答「怎么把 SDK 装进项目」，本手册回答「怎么把它安全地送上生产」。
两者的分界：接入指南到 `check-config --runtime` 通过为止；
本手册从那之后开始，覆盖权限、基础设施依赖、上线顺序、回滚与排障。

前置阅读：[四系统 Composer 安装与两两互调操作指南](Tozo-Security-SDK-四系统Composer安装与两两互调操作指南-v0.0.9.md)。

> 本手册的每条命令都可直接执行，但**未在真实生产环境验证过**——
> 本 SDK 仓库不含 Laravel 应用、Redis 与 TLS 证书。
> 首次部署请先在 testing 环境完整走一遍。

---

## 1. 部署前检查清单

逐项确认后再动手。任一项不满足就先解决它，不要「先上再说」。

| # | 检查项 | 确认方式 | 不满足的后果 |
|---|---|---|---|
| 1 | PHP >= 7.4，含 json / openssl 扩展 | `php -m \| findstr "json openssl"` | 启动即失败 |
| 2 | 缓存驱动是**多实例共享**的后端 | 见 §3 | 防重放静默失效，无任何报错 |
| 3 | 密钥目录存在且权限收紧 | 见 §2 | 密钥可被同机其他账号读取 |
| 4 | 密钥目录不在 web 可访问路径下 | 见 §2.3 | 密钥可被 HTTP 直接下载 |
| 5 | 对端已持有内容相同的密钥文件 | 见 §4 | 验签失败，链路不通 |
| 6 | 出站方向 HTTPS 可达且证书有效 | `curl -I https://对端域名` | 请求超时或 TLS 握手失败 |
| 7 | `.gitignore` 已忽略 `*.key` | `git check-ignore -v storage/app/tozo/keys/*.key` | 生产密钥进版本库 |

---

## 2. 密钥目录与权限

### 2.1 默认位置

```text
storage/app/tozo/keys/{key_id}.key
```

选这个位置的原因：Laravel 默认不把 `storage/app/` 暴露给 web 服务器。
放在 `public/` 或项目根目录会让密钥可被 HTTP 直接下载。

### 2.2 权限要求

`tozo:security:install` 会自动按下表设置。手工创建时必须自己设。

| 对象 | 权限 | 说明 |
|---|---|---|
| 密钥目录 | `0700` | 只有属主可读写与列目录；同机其他账号连文件名都看不到 |
| 密钥文件 | `0600` | 只有属主可读写 |
| 属主 | PHP 运行账号 | 通常是 `www-data` / `nginx` / `php-fpm` |

```bash
# 确认权限（Linux）
ls -la storage/app/tozo/keys/
# 期望：drwx------ 目录，-rw------- 文件

# 修正权限
chmod 700 storage/app/tozo/keys
chmod 600 storage/app/tozo/keys/*.key
chown -R www-data:www-data storage/app/tozo/keys
```

Windows 环境用 `icacls` 限制到 PHP 运行账号，仅授予读取权限。

### 2.3 验证密钥不可被 web 访问

```bash
curl -i https://你的域名/storage/app/tozo/keys/production_a_to_b_request.key
```

期望 404 或 403。若返回 200 并吐出密钥内容，**立即停止部署**，
检查 web 服务器的 root 配置与是否误建了 `public/storage` 软链接指向了 `storage/app`。

### 2.4 放到 Laravel 之外

密钥由外部 secret 管理系统挂载时，用绝对路径覆盖：

```php
// config/tozo_security.php
'key_providers' => [
    'driver' => 'file',
    'file'   => ['path' => '/etc/tozo/keys'],
],
```

或安装时指定：

```bash
php artisan tozo:security:install --dir=/etc/tozo/keys
```

该目录同样要求 `0700`，且属主为 PHP 运行账号。

---

## 3. 缓存后端（防重放的基础设施依赖）

### 3.1 为什么必须是共享后端

SDK 用缓存实现 Nonce 的「只写一次」语义：同一个 Nonce 第二次出现即判为重放并拒绝。

这个语义要求**全部应用实例看到同一份数据**。若用 `file` 或 `array` 驱动：

```text
实例 A 收到 Nonce=x → 本地无记录 → 放行
实例 B 收到 Nonce=x → 本地无记录 → 也放行   ← 重放成功
```

结果是防重放形同失效，且**不产生任何报错**——两个实例各自都认为自己工作正常。
这一点 SDK 无法检测，只能由部署方保证。

### 3.2 配置

```env
CACHE_DRIVER=redis
REDIS_HOST=你的 Redis 地址
REDIS_PORT=6379
REDIS_PASSWORD=你的密码
```

单机开发可用 `CACHE_DRIVER=array`，但**生产禁止**。

### 3.3 Redis 必须满足的条件

| 条件 | 原因 |
|---|---|
| 全部应用实例连同一个 Redis（或同一集群） | 见 §3.1 |
| 支持 `SET NX`（Laravel 的 `Cache::add` 依赖它） | 这是「只写一次」的原子性来源 |
| 有密码且网络 ACL 限制来源 | Redis 里存着防重放与吊销记录，可被篡改则两项机制均失效 |
| 内存策略**不是** `allkeys-lru` | LRU 会在内存压力下淘汰 Nonce 记录，淘汰即等于重放窗口打开 |

内存策略建议 `noeviction` 或 `volatile-ttl`。用 `allkeys-lru` 时防重放会在高负载期
静默降级——这类问题在压测中很难复现，但在生产峰值时会真实发生。

### 3.4 验证连通性

```bash
php artisan tozo:security:check-config --runtime
```

`--runtime` 会做一次 put/has/forget 往返。输出含
`runtime: replay store backend unavailable` 表示连不通，
`runtime: cache probe failed` 表示连上了但读写不一致（通常是驱动配错）。

---

## 4. 密钥交换（唯一无法自动化的一步）

### 4.1 核心约束

同一条关系的两端必须持有**内容完全相同**的同名 `.key` 文件。

```text
tozo-app-api 侧：storage/app/tozo/keys/production_tozo-app-api_to_pos-api_request.key
pos-api 侧：    storage/app/tozo/keys/production_tozo-app-api_to_pos-api_request.key
                                      ↑ 文件名相同，内容也必须相同
```

### 4.2 正确流程

```bash
# 第 1 步：一方（约定由调用方）生成
php artisan tozo:security:install

# 第 2 步：列出需要同步给对端的文件
php artisan tozo:security:install --dry-run

# 第 3 步：经安全通道同步给对端
# 第 4 步：两端各自体检
php artisan tozo:security:check-config --runtime
```

### 4.3 常见错误

| 错误做法 | 后果 |
|---|---|
| 两端各自执行 install | 同名文件内容不同，验签必然失败 |
| 用邮件、聊天工具、工单传输 | 留下无法回收的密钥副本 |
| 复制时被编辑器加了换行或 BOM | `FileKeyProvider` 会 rtrim 行尾，但 BOM 会让内容不一致 |
| 只同步了 request 忘了 response | 请求通过但响应验证失败，表现为「调用成功却拿不到数据」 |

传输建议：加密压缩包 + 带外口令，或直接由部署系统从 secret 管理服务下发。

### 4.4 校验两端一致

两端分别执行，比对输出的哈希：

```bash
# Linux
sha256sum storage/app/tozo/keys/production_tozo-app-api_to_pos-api_request.key

# Windows
certutil -hashfile storage\app\tozo\keys\production_tozo-app-api_to_pos-api_request.key SHA256
```

哈希不同即内容不同，链路一定不通。这一步比事后排查验签失败快得多。

---

## 5. 上线顺序

四系统两两互调有 12 条关系，一次性全开会让故障定位变得困难。建议分四批。

### 5.1 为什么顺序重要

入站防护与出站调用是**独立**的两件事：

- 挂载了入站中间件但对端还没配 → 对端调不通你（对端的请求没有签名）
- 配了出站但你自己没挂入站 → 你能调对端，对端调你时不做任何验证

因此安全的顺序是**先两端都挂入站，再逐步开出站**。

### 5.2 分批步骤

```text
第 1 批：全部系统只部署配置 + 密钥，不挂中间件、不改业务代码
        → 验证：check-config --runtime 全部通过
        → 此时零风险，SDK 已装但不拦任何流量

第 2 批：全部系统挂载入站中间件（tozo.inbound + tozo.response）
        → 验证：用未签名请求访问受保护路由，应返回 401/403
        → 此时对端还没开出站，受保护路由暂无正常流量

第 3 批：挑一对关系开出站（建议流量最小的那对）
        → 验证：该方向调用成功，响应可解析
        → 观察 24 小时，确认审计日志无异常

第 4 批：逐对开通剩余 11 条关系
```

### 5.3 每批的验证命令

```bash
# 配置与密钥自洽
php artisan tozo:security:check-config --runtime

# 确认 Profile 注册表符合预期（应为 对端数 × 2）
php artisan tinker
>>> count(app('tozo_security.profiles'))

# 确认选路表可用
>>> app('tozo.http')->to('pos-api')->getProfile()->getName()
```

### 5.4 `config:cache` 注意事项

Laravel 缓存配置后，改 `config/tozo_security.php` 不会生效：

```bash
php artisan config:clear    # 改配置后必须执行
php artisan config:cache    # 重新缓存
```

配置缓存的是**展开后**的完整形态还是极简形态，取决于缓存时机——
`ConfigNormalizer` 在 `register()` 阶段展开，而 `config:cache` 序列化的是配置文件原文，
因此缓存里存的是极简形态，每次启动仍会展开。这一点不影响正确性，
但意味着**改了配置一定要 `config:clear`**，否则会看到「明明改了却没生效」。

---

## 6. 部署后健康检查

### 6.1 立即检查

```bash
# 1. 配置与密钥
php artisan tozo:security:check-config --runtime
# 期望：退出码 0

# 2. 密钥不可被 web 访问
curl -i https://你的域名/storage/app/tozo/keys/任意一个.key
# 期望：404 或 403

# 3. 未签名请求被拒
curl -i -X POST https://你的域名/api/internal/tozo-security/from-pos-api/health
# 期望：401 或 403，且响应体不含验证细节

# 4. 正常调用成功（在对端执行）
php artisan tinker
>>> app('tozo.http')->to('tozo-app-api')->post('/api/internal/tozo-security/from-pos-api/health', ['ping'=>1])->getStatus()
# 期望：200
```

### 6.2 观察期指标

上线后 24 小时关注这几项，任一异常都说明配置有问题：

| 指标 | 异常信号 | 可能原因 |
|---|---|---|
| 验签失败率 | 持续 > 0 | 两端密钥不一致，或时钟偏差超出 60 秒容忍 |
| 防重放拒绝数 | 持续 > 0 且无重放攻击 | 缓存后端未共享（见 §3.1），合法重试被误判 |
| 响应验证失败数 | 持续 > 0 | 响应密钥未同步，或对端未挂 `tozo.response` |
| 503 数量 | 突增 | ReplayStore 或吊销存储不可用（fail-closed 生效） |
| 出站超时 | 突增 | 对端不可达，或 10 秒默认超时对该接口偏短 |

### 6.3 时钟同步

签名接受窗口是 `max_age(300s) + clock_skew(60s)`。两端时钟偏差超过 60 秒即验签失败。

```bash
# 确认 NTP 正常
timedatectl status        # 期望 "System clock synchronized: yes"
```

时钟漂移导致的验签失败有个特征：**间歇性、且随时间推移越来越频繁**。
遇到这种模式先查 NTP，不要先查密钥。

---

## 7. 排障

下表的异常消息均取自 SDK 源码，可直接用于日志检索。

### 7.1 启动期失败

| 异常消息 | 原因 | 处理 |
|---|---|---|
| `tozo_security.environment is required in compact configuration` | 填了 `service` 与 `peers` 但漏了 `environment` | 补上 `environment` |
| `tozo_security.peers [X] requires a non-empty base_uri` | 某对端用数组形态但没写 `base_uri` | 补 `base_uri`，或改回字符串简写 |
| `tozo_security.peers [X] must not equal the local service identifier` | `peers` 里写了自己 | 删掉自己那条 |
| `tozo_security.peers [X] security_mode must be one of: ...` | `security_mode` 拼错 | 只能是三个合法值之一 |
| `ArrayKeyProvider is not allowed in production` | `environment=production` 却用了 array driver | 改用 file 或 env driver |
| `default_profile [X] does not match any enabled profile` | `default_profile` 指向不存在的 Profile | 用 install 命令输出的 Profile 名 |
| `profile [X] uses feature [Y] which is disabled` | 旧完整配置形态下 `features` 与 Profile 不一致 | 极简形态会自动推导，不会有此错；旧形态需手工对齐 |

### 7.2 运行期失败

| 异常消息 | 原因 | 处理 |
|---|---|---|
| `Key file not found for key_id: X` | 密钥文件不存在或名字不对 | 跑 `install --dry-run` 比对期望文件名 |
| `Key directory does not exist: X` | 密钥目录还没建 | 跑 `tozo:security:install`（它会建目录） |
| `Key file not readable for key_id: X` | 权限不对 | 属主应为 PHP 运行账号，见 §2.2 |
| `Key file is empty for key_id: X` | 文件存在但内容空 | 同步过程被截断，重新同步 |
| `TozoHttpClient requires a profile` | 没经 `to()` 选路，也没配 `default_profile` | 用 `->to('对端标识')` |
| `No outbound relation configured for target service [X]` | `to()` 的参数不在 `peers` 里 | 异常消息会列出已声明的对端，照它改 |
| `Encryption enabled but cipher binding is missing` | Profile 开了加密但容器没绑 cipher | 检查 `features.encryption`（旧形态）或重启清缓存 |
| 503 `temporarily_unavailable` | ReplayStore 或吊销存储不可用 | 这是 fail-closed 的预期行为，查 Redis |

### 7.3 「调用成功但对端说验签失败」

这是最常见的一类，按顺序排查：

```text
1. 两端密钥哈希是否相同        → §4.4
2. 两端 environment 是否相同    → 不同会推导出不同 key_id
3. 两端服务标识拼写是否一致      → tozo-app-api ≠ tozo_app_api
4. 时钟偏差是否超过 60 秒        → §6.3
5. 中间是否有网关改写了请求体     → 签名覆盖 Body，改写即失效
6. 中间是否有网关剥掉了 X-Tozo-* 头 → 缺头等于没签名
```

第 5、6 项容易被忽略：某些 WAF 或 API 网关会规范化 JSON、补默认字段或删自定义头，
这些改动都会让签名失效。判断方法是在对端记录收到的原始 Body 字节，与调用端发出的比对。

### 7.4 「请求通过但拿不到响应数据」

响应方向的保护没配通。检查：

```text
1. 被调用方是否挂了 tozo.response 中间件
2. 中间件顺序是否为 tozo.inbound 在前、tozo.response 在后
3. 响应密钥（_response 结尾的）是否也同步了
4. 网关是否剥掉了 X-Tozo-Response-Signature 头
```

### 7.5 打开诊断日志

```php
// config/tozo_security.php
'logging' => [
    'enabled' => true,
    'channel' => 'security',   // 指向 config/logging.php 中的通道
    'level'   => 'info',
],
```

日志只含原因码与元数据，不含密钥、完整 Token 与请求体。
排障结束后建议把通道调回收敛的级别——安全日志的读取面应当受控。

---

## 8. 回滚

### 8.1 回滚的分界

| 情形 | 回滚方式 | 影响 |
|---|---|---|
| 入站中间件误拦合法流量 | 从路由摘掉 `tozo.inbound`、`tozo.response` | 该路由回到无防护状态 |
| 出站调用失败 | 业务代码回退到原有 HTTP 调用 | 该调用回到无签名状态 |
| 配置错误导致应用起不来 | 恢复上一版 `config/tozo_security.php` | 完全回到部署前 |
| 密钥被误覆盖 | 见 §8.3 | — |

### 8.2 最小回滚：只摘中间件

不需要卸载 SDK，也不需要改配置：

```php
// 回滚前
Route::middleware(['tozo.inbound', 'tozo.response'])->...

// 回滚后（注释掉中间件即可）
Route::post('/api/internal/...', [Controller::class, 'handle']);
```

SDK 仍装着、配置仍在，只是不再拦这条路由。这是**最快**的回滚方式，
适合线上正在报错、需要立即止损的场景。

### 8.3 密钥被误覆盖的处理

`install` 命令不覆盖已存在的密钥，因此正常操作不会发生。
若被手工覆盖，且对端还持有旧密钥：

```text
1. 立即从对端取回该密钥文件（对端那份是旧的、正确的）
2. 覆盖回本端
3. 校验哈希一致（§4.4）
```

若两端都已丢失原始内容，只能重新生成并两端同步——期间该条关系不可用。
这也是为什么 `install` 设计成不覆盖：一次误运行不该造成不可恢复的状态。

### 8.4 完全卸载

```bash
composer remove tozo/security-sdk
rm config/tozo_security.php
rm -rf storage/app/tozo
# 从 Kernel.php 移除两个中间件别名
# 从 routes 移除相关路由
```

卸载前确认对端已同步停止向你发送签名请求，否则对端会收到 404 或未防护的响应。

---

## 9. 定期维护

| 周期 | 事项 |
|---|---|
| 每次发版 | `composer verify` 通过；`check-config --runtime` 通过 |
| 每月 | 检查密钥目录权限未被部署脚本改宽 |
| 每季度 | 在 testing 环境做一次密钥轮换演练（见 §10） |
| 每年 / 或人员变动时 | 轮换全部生产密钥 |

---

## 10. 密钥轮换

### 10.1 当前能力边界（须先了解）

SDK 内部有轮换状态机（`KeyUsage` 的 `active` / `verify_only` / `decrypt_only` / `retired`），
写方向只接受 `active`，读方向额外接受对应的迁移期状态——这套设计支持不停机轮换。

**但目前只有 `ArrayKeyProvider`（仅测试用）能注入状态。**
生产用的 `FileKeyProvider` 不带状态元数据，全部视为 `active`。

因此当前生产轮换**需要短暂停机窗口**，无法平滑迁移。
需要不停机轮换时，要先给 `FileKeyProvider` 加状态支持（例如按 `{key_id}.state` 附属文件读取）。
这是已知缺口，不是使用方式问题。

### 10.2 停机窗口内的轮换步骤

以 `tozo-app-api ↔ pos-api` 的请求密钥为例：

```bash
# 第 1 步：两端同时停止该方向流量（摘中间件或下线路由）

# 第 2 步：两端删除旧密钥
rm storage/app/tozo/keys/production_tozo-app-api_to_pos-api_request.key

# 第 3 步：一方重新生成（只会补齐缺失的，已有的不动）
php artisan tozo:security:install

# 第 4 步：同步给对端，校验哈希一致
sha256sum storage/app/tozo/keys/production_tozo-app-api_to_pos-api_request.key

# 第 5 步：两端体检
php artisan tozo:security:check-config --runtime

# 第 6 步：恢复流量，观察验签失败率
```

一条关系有请求与响应两把密钥，四个用途密钥全换时按同样步骤处理。

### 10.3 演练要回答的问题

在 testing 环境走完上述步骤，记录并确认：

```text
- 整个流程实际耗时多久？
- 停机窗口能否压缩到业务可接受范围？
- 第 2 步漏删一端会怎样？（预期：验签失败，且错误信息能指向密钥不一致）
- 第 4 步同步错文件会怎样？（预期：同上）
- 回滚是否可行？（把旧密钥放回两端即可）
```

演练的价值在于：真正需要紧急轮换（密钥泄露）时，流程已经跑过一遍，
不必在压力下第一次尝试。

---

## 11. 未在本仓库验证的事项

以下内容本 SDK 仓库无法验证，必须在你的环境中确认：

| 项目 | 说明 |
|---|---|
| 真实 Laravel 8.5 应用 | HTTP Kernel、路由参数、中间件 alias、package discovery |
| Redis 多实例原子性 | `SET NX` 原子性、TTL 精度、网络故障传播、并发压测 |
| 真实 HTTPS 传输 | Guzzle、TLS 握手、代理转发、`X-Forwarded-*` 处理 |
| 网关行为 | WAF / API 网关是否改写 Body 或剥离自定义头 |
| 密钥管理集成 | Vault / KMS 下发、权限、备份、泄露响应流程 |
| 高并发性能 | 签名与加解密吞吐、Cache 争用、大 Body 内存占用 |
| 业务适用性 | SDK 不能替你判断某条路由是否适合 `token_only` |

本 SDK 已验证的部分：PHP 8.0.2 与 7.4.3 双版本下 lint 127 文件 0 失败、
319 tests / 1561 assertions 全通过、八项检查全过；
PHP / Python 3.9.13 / Go 1.25.7 三实现与 70 条冻结协议向量逐字节一致。
