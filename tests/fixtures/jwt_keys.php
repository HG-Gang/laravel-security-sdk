<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * JWT 测试密钥夹具装载器（仅测试用途）。
 *
 * 返回：[jwt-private-2026-08 => 私钥PEM, jwt-public-2026-08 => 公钥PEM]
 */

function jwt_test_keys(){
    $dir = __DIR__;

    return [
        'jwt-private-2026-08' => (string) file_get_contents($dir . '/jwt-test-private.pem'),
        'jwt-public-2026-08' => (string) file_get_contents($dir . '/jwt-test-public.pem'),
    ];
}
