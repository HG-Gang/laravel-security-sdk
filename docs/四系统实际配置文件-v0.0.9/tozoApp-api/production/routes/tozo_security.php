<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 04:10
 */

/**
 * App 端 API（tozo-app-api）生产环境入站安全路由
 *
 * 文件功能：
 * - 为三个对端各注册一条入站健康检查路由，作为可复制的挂载范例
 *
 * 安全边界：
 * - 每条路由显式绑定唯一 inbound Profile；入站解析绝不回退默认 Profile，
 *   否则来自 A 的请求可能被按 B 的规则放行
 * - 两个中间件顺序固定：先 tozo.inbound 验证，再 tozo.response 生成响应保护
 */

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Internal\TozoSecurityController;

// 来自 app-admin-api 的入站请求：先验签，再生成响应签名。
Route::middleware(['tozo.inbound', 'tozo.response'])
    ->defaults('tozo_profile', 'tozo_app_api_inbound_from_app_admin_api')
    ->post('/api/internal/tozo-security/from-app-admin-api/health', [TozoSecurityController::class, 'handle']);

// 来自 pmc-api 的入站请求：先验签，再生成响应签名。
Route::middleware(['tozo.inbound', 'tozo.response'])
    ->defaults('tozo_profile', 'tozo_app_api_inbound_from_pmc_api')
    ->post('/api/internal/tozo-security/from-pmc-api/health', [TozoSecurityController::class, 'handle']);

// 来自 pos-api 的入站请求：先验签，再生成响应签名。
Route::middleware(['tozo.inbound', 'tozo.response'])
    ->defaults('tozo_profile', 'tozo_app_api_inbound_from_pos_api')
    ->post('/api/internal/tozo-security/from-pos-api/health', [TozoSecurityController::class, 'handle']);
