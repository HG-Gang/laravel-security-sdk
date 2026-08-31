<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 04:10
 */

/**
 * 生产管理 API（pmc-api）测试环境 Kernel 中间件别名增量
 *
 * 文件功能：
 * - 提供可合并进 app/Http/Kernel.php 的 $routeMiddleware 条目
 *
 * 使用边界：
 * - 这是增量片段而非完整 Kernel 类，必须合并进宿主既有数组
 * - 直接用本文件覆盖宿主 Kernel 会删掉项目原有中间件
 */

return [
    // tozo.inbound string｜入站验证别名；验签成功后向请求注入可信 Subject 与 Profile。
    'tozo.inbound'  => \Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware::class,

    // tozo.response string｜响应完整性别名；必须排在 tozo.inbound 之后才能拿到已验证的 Profile。
    'tozo.response' => \Tozo\Security\Laravel\Middleware\ResponseIntegrityMiddleware::class,

    // tozo.outbound string｜代理出站保护别名；仅在用中间件方式转发请求时需要，
    // 业务代码直接调用 app('tozo.http')->to(...) 时不需要挂载它。
    'tozo.outbound' => \Tozo\Security\Laravel\Middleware\OutboundSignerMiddleware::class,
];
