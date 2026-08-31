<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Tozo\Security\Tests\TestCase;

/**
 * 自动加载闭环测试：src 下每个 PHP 文件必须能按 PSR-4 映射加载。
 */
class AutoloadTest extends TestCase
{
    public function test_every_source_file_maps_to_a_loadable_symbol(){
        $srcDir = dirname(__DIR__, 2) . '/src/Tozo/Security';
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($srcDir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        $checked = 0;
        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            $relative = substr($file->getPathname(), strlen($srcDir) + 1, -4);
            $fqcn = 'Tozo\\Security\\' . str_replace(DIRECTORY_SEPARATOR, '\\', $relative);

            $this->assertTrue(
                class_exists($fqcn) || interface_exists($fqcn),
                "Symbol [{$fqcn}] cannot be autoloaded (check PSR-4 mapping and file name case)"
            );
            $checked++;
        }

        // 防御：目录扫描失败时测试不能静默通过。
        $this->assertGreaterThan(40, $checked);
    }

    public function test_composer_extra_provider_and_alias_classes_exist(){
        $composer = json_decode(
            (string) file_get_contents(dirname(__DIR__, 2) . '/composer.json'),
            true
        );

        $provider = $composer['extra']['laravel']['providers'][0];
        $alias = $composer['extra']['laravel']['aliases']['TozoSecurity'];

        $this->assertTrue(class_exists($provider), "Provider [{$provider}] missing");
        $this->assertTrue(class_exists($alias), "Alias [{$alias}] missing");
    }
}
