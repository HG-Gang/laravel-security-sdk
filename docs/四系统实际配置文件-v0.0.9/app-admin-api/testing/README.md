# 后台管理 API（app-admin-api）测试环境接入说明

## 配置文件

把 `config/tozo_security.php` 复制到项目 `config/` 下即可。该文件只有三个键：

| 键 | 值 |
|---|---|
| `service` | `app-admin-api` |
| `environment` | `testing` |
| `peers` | 另外三个系统的根地址 |

不需要 `.env`，不需要 `tozo_services.php`，不需要手写 Profile。

## 展开出的 6 个 Profile

- `app_admin_api_outbound_to_tozo_app_api`：出站到 tozo-app-api
- `app_admin_api_inbound_from_tozo_app_api`：入站自 tozo-app-api
- `app_admin_api_outbound_to_pmc_api`：出站到 pmc-api
- `app_admin_api_inbound_from_pmc_api`：入站自 pmc-api
- `app_admin_api_outbound_to_pos_api`：出站到 pos-api
- `app_admin_api_inbound_from_pos_api`：入站自 pos-api

## 需要部署的 12 个密钥文件

位置：`storage/app/tozo/keys/`。由安装命令生成：

```bash
php artisan tozo:security:install
```

- `testing_app-admin-api_to_tozo-app-api_request.key`
- `testing_app-admin-api_to_tozo-app-api_response.key`
- `testing_tozo-app-api_to_app-admin-api_request.key`
- `testing_tozo-app-api_to_app-admin-api_response.key`
- `testing_app-admin-api_to_pmc-api_request.key`
- `testing_app-admin-api_to_pmc-api_response.key`
- `testing_pmc-api_to_app-admin-api_request.key`
- `testing_pmc-api_to_app-admin-api_response.key`
- `testing_app-admin-api_to_pos-api_request.key`
- `testing_app-admin-api_to_pos-api_response.key`
- `testing_pos-api_to_app-admin-api_request.key`
- `testing_pos-api_to_app-admin-api_response.key`

同一条关系的两端必须持有**内容相同**的密钥文件。例如本系统与 tozo-app-api 之间的请求密钥，两边的 `.key` 文件内容必须一致。

## 接入步骤

1. 复制 `config/tozo_security.php`
2. 把 `app/Http/Kernel.tozo-security.php` 的三个别名合并进 `app/Http/Kernel.php` 的 `$routeMiddleware`
3. 复制 `routes/tozo_security.php` 并在 `RouteServiceProvider` 中加载
4. 复制 `app/Http/Controllers/Internal/TozoSecurityController.php`
5. 执行 `php artisan tozo:security:install` 生成密钥，与对端交换
6. 执行 `php artisan tozo:security:check-config --runtime` 确认自洽

## 出站调用

```php
app('tozo.http')->to('tozo-app-api')->post('/api/orders', ['id' => 1]);
```
