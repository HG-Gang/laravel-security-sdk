<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 测试全局助手桩（全局命名空间）。
 *
 * 非 Laravel 环境下 ServiceProvider::boot() 依赖的框架函数在此提供最小实现。
 */

if (!function_exists('config_path')) {
    function config_path(string $path = ''){
        return sys_get_temp_dir() . '/tozo-sdk-test/' . $path;
    }
}
