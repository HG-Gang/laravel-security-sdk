# 四系统实际配置文件 v0.0.9

配置精简后的接入示例。每套只有 4 个文件，其中配置文件仅 3 个键。

## 目录对应关系

| 目录 | 服务标识 | 说明 |
|---|---|---|
| `tozoApp-api` | `tozo-app-api` | App 端 API |
| `app-admin-api` | `app-admin-api` | 后台管理 API |
| `pmc-api` | `pmc-api` | 生产管理 API |
| `pos-api` | `pos-api` | POS API |

## 域名怎么配

各套配置里的域名是**占位值**。`example.com`（生产）与 `example.test`（测试）
是 RFC 2606 保留域名，不会解析到真实主机，照抄上线会在出站时连接失败——
这是有意为之，防止占位值被误当成可用配置。

复制配置后只改 `peers` 段的域名：

- **键（服务标识）不要改**：参与签名原文绑定，两端必须一致，改了就验签失败。
- **值（根地址）替换为本环境实际地址**：只用于出站选路，不参与签名，
  换域名、切内网地址、加端口都不影响密钥与 Profile 推导。
- **暂不互调的对端整条注释掉**：不生成 Profile、不需要其密钥，其余关系不受影响。

测试与生产的域名分别写在各自环境的配置里，`environment` 参与密钥命名空间，
两个环境不共用任何密钥文件。改域名不必重跑 `tozo:security:install`，
但建议跑一次 `php artisan tozo:security:check-config --runtime` 确认配置自洽。

## 与配置精简前的差异

| 项目 | 精简前 | 现在 |
|---|---|---|
| 每套文件数 | 8 | 4 |
| 配置文件行数 | 548 | 约 25 |
| 配置键数 | 224 | 3 |
| `.env` | 每套 31 个变量 | 不再需要 |
| `config/tozo_services.php` | 需要 | 并入 SDK 内置默认 |
| 手写 HTTP Client | 每套 108 行样板 | 由 SDK 的 `to()` 提供 |
| 密钥来源 | 环境变量 | `storage/app/tozo/keys/` |

本目录由 `composer examples` 生成，请勿手工修改——
手工改动会被 `composer examples-check` 判为与生成规则不一致。

## 每套包含的文件

```text
config/tozo_security.php                              三个键的极简配置
app/Http/Kernel.tozo-security.php                     中间件别名增量
routes/tozo_security.php                              三条入站路由
app/Http/Controllers/Internal/TozoSecurityController.php  入站与出站范例
README.md                                             该套的部署核对清单
```

## 密钥对称要求

12 条有向关系 × 请求/响应两种用途 = 全网 24 个密钥，每个系统持有与自己相关的 12 个。
同一条关系两端的同名密钥文件内容必须完全相同，否则验签失败。

密钥标识由 SDK 按 `{environment}_{调用方}_to_{接收方}_{用途}` 推导，无需手工命名。
