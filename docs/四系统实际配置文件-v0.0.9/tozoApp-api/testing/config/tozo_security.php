<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 04:10
 */

/**
 * App 端 API（tozo-app-api）测试环境安全配置
 *
 * 文件功能：
 * - 本系统接入 Tozo Security SDK 的唯一配置文件，复制到 config/tozo_security.php 即可
 * - 三个键展开为 6 个 Profile（3 个对端 × 出站/入站）与 12 个用途密钥标识
 *
 * 安全边界：
 * - 本文件不含任何密钥，可随代码提交与审计
 * - 密钥由 php artisan tozo:security:install 生成到 storage/app/tozo/keys/，不经过 .env
 */

return [
    // service string｜本系统身份；参与签名原文与 AAD 绑定，是全部推导的起点。
    'service'     => 'tozo-app-api',

    // environment string｜运行环境；作为密钥命名空间前缀，两个环境不共用任何密钥。
    'environment' => 'testing',

    // peers array｜对端名单；键为对端服务标识，值为其 HTTPS 根地址。
    // 出站调用用 app('tozo.http')->to('对端标识') 选路，无需记 Profile 名。
    // 下面的域名是占位值（example.com/example.test 为保留域名，不会解析到真实主机），
    // 接入时必须逐条替换为本环境实际部署地址；服务标识（键名）不要改动。
    // 暂不互调的对端整条注释掉即可：不生成 Profile、不需要其密钥，其余关系不受影响。
    'peers'       => [
        // app-admin-api string｜后台管理 API 的 HTTPS 根地址；声明即与该系统建立双向信任。
        'app-admin-api'  => 'https://app-admin-api.example.test',
        // pmc-api string｜生产管理 API 的 HTTPS 根地址；声明即与该系统建立双向信任。
        'pmc-api'        => 'https://pmc-api.example.test',
        // pos-api string｜POS API 的 HTTPS 根地址；声明即与该系统建立双向信任。
        'pos-api'        => 'https://pos-api.example.test',
    ],
];
