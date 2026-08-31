<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\KeyNotFoundException;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Key\EnvKeyProvider;
use Tozo\Security\Key\FileKeyProvider;
use Tozo\Security\Tests\TestCase;

class KeyProvidersTest extends TestCase
{
    public function test_env_provider_resolves_prefixed_environment_variable(){
        putenv('TOZO_SECURITY_KEY_UNIT_TEST_SECRET=raw-secret-bytes');

        try {
            $provider = new EnvKeyProvider();

            $this->assertSame('raw-secret-bytes', $provider->getKey('unit.test-secret'));
            $this->assertTrue($provider->hasKey('unit.test-secret'));
        } finally {
            // 环境变量只服务当前用例，结束时立即清理，避免污染后续测试进程。
            putenv('TOZO_SECURITY_KEY_UNIT_TEST_SECRET');
        }
    }

    public function test_env_provider_fails_closed_when_variable_missing_or_empty(){
        $provider = new EnvKeyProvider();

        try {
            $provider->getKey('missing.key');
            $this->fail('Expected KeyNotFoundException for missing env key');
        } catch (KeyNotFoundException $e) {
            // 异常消息只包含变量名，不包含任何密钥内容。
            $this->assertStringContainsString('TOZO_SECURITY_KEY_MISSING_KEY', $e->getMessage());
        }

        try {
            putenv('TOZO_SECURITY_KEY_EMPTY_SECRET=');
            try {
                $provider->getKey('empty.secret');
                $this->fail('Expected KeyNotFoundException for empty env key');
            } catch (KeyNotFoundException $e) {
                $this->addToAssertionCount(1);
            }
        } finally {
            putenv('TOZO_SECURITY_KEY_EMPTY_SECRET');
        }
    }

    public function test_file_provider_reads_key_and_rejects_traversal(){
        $dir = sys_get_temp_dir() . '/tozo-key-test-' . bin2hex(random_bytes(4));
        mkdir($dir, 0700, true);
        file_put_contents($dir . '/valid.key', "file-key-content\n");

        $provider = new FileKeyProvider($dir);

        // 行尾换行被剥离，空内容视为缺失。
        $this->assertSame('file-key-content', $provider->getKey('valid'));

        try {
            $provider->getKey('../etc/passwd');
            $this->fail('Expected KeyNotFoundException for illegal key_id');
        } catch (KeyNotFoundException $e) {
            $this->addToAssertionCount(1);
        }

        unlink($dir . '/valid.key');
        rmdir($dir);
    }

    public function test_file_provider_requires_directory_outside_laravel(){
        $this->expectException(ConfigurationException::class);

        new FileKeyProvider(null);
    }

    public function test_array_provider_is_test_only_lookup(){
        $provider = new ArrayKeyProvider(['k1' => 'v1']);

        $this->assertSame('v1', $provider->getKey('k1'));
        $this->assertFalse($provider->hasKey('k2'));

        $this->expectException(KeyNotFoundException::class);
        $provider->getKey('k2');
    }
}
