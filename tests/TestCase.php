<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 测试基座
 *
 * 文件功能：
 * - 构建最小 Illuminate 容器（config + array cache + array key provider）
 * - 注册 Tozo Security ServiceProvider 并按需执行 boot 结构校验
 * - 提供确定性的 Profile/密钥/时钟测试夹具
 *
 * 安全边界：
 * - 测试密钥全部为内存随机值，不使用任何真实生产密钥
 */

namespace Tozo\Security\Tests;

use Illuminate\Cache\ArrayStore;
use Illuminate\Container\Container;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Contracts\KeyProviderInterface;
use PHPUnit\Framework\TestCase as PhpUnitTestCase;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository as ConfigRepository;
use Tozo\Security\ServiceProvider;

// 非 Laravel 环境下 ServiceProvider::boot() 依赖的助手函数桩。
if (!function_exists('config_path')) {
    function config_path(string $path = '')
    {
        return sys_get_temp_dir() . '/tozo-sdk-test/' . $path;
    }
}

abstract class TestCase extends PhpUnitTestCase
{
    /**
     * 测试用请求签名 key_id，对应 defaultKeys() 中的 32 字节内存密钥。
     * 与 RESP_ENC_KEY、ENC_KEY 分开命名是刻意的：用例需要验证
     * 「响应密钥不得复用请求密钥」这条强制约束，
     * 若夹具本身就复用同一 key_id，那条约束的用例会永远通过而发现不了实现遗漏。
     */
    public const HMAC_KEY = 'order-signing';
    
    /**
     * 测试用请求加密 key_id。与响应加密密钥严格分开，
     * 以便用例能验证"响应密钥不得复用请求密钥"这条约束。
     */
    public const ENC_KEY = 'order-encryption';
    
    /**
     * 测试用响应加密 key_id，与请求加密的 ENC_KEY 严格分开。
     * Profile 校验期会强制这两者不同——响应密钥复用请求密钥时，
     * 同一段密文可被跨方向重放，方向绑定失效。
     * 夹具保持分离才能让那条校验的用例真实生效。
     */
    public const RESP_ENC_KEY = 'order-response-encryption';
    
    /**
     * 构建注册完成的容器。
     *
     * @param array $overrides 点号路径覆盖（如 features.token_issuer => true）
     * @param array $keys key_id => 密钥内容
     */
    protected function makeContainer(array $overrides = [], array $keys = [])
    {
        $container = new Container();
        
        $config = $this->baseConfig();
        
        // 覆盖点号路径作用于 tozo_security.* 子树（调用方无需携带前缀）。
        foreach ($overrides as $dots => $value) {
            $this->setDot($config['tozo_security'], $dots, $value);
        }
        
        $container->instance('config', new ConfigRepository($config));
        
        // 绑定容器契约接口；具体 Repository 由 Laravel 的 cache.store 提供时同样可解析。
        $container->singleton(\Illuminate\Contracts\Cache\Repository::class, function () {
            return new CacheRepository(new ArrayStore());
        });
        
        $container->singleton(KeyProviderInterface::class, function () use ($keys) {
            return new ArrayKeyProvider(array_merge($this->defaultKeys(), $keys));
        });
        
        $provider = new ServiceProvider($container);
        $provider->register();
        
        return $container;
    }
    
    /**
     * 基础配置：出站 + 入站 Profile 对（共享 HMAC 与 JWT 公私钥约定）。
     */
    protected function baseConfig()
    {
        return [
            'tozo_security' => [
                'default_profile'  => 'svc_to_order',
                'environment'      => 'testing',
                'protocol_version' => '1',
                'features'         => [
                    'authentication'     => true,
                    'signature'          => true,
                    'encryption'         => true,
                    'response_integrity' => true,
                    'token_verifier'     => true,
                    'token_issuer'       => true, // 夹具启用以匹配出站 attach；生产默认必须为 false
                    'token_revocation'   => false,
                    'scope'              => true,
                    'http_client'        => true,
                    'audit'              => true,
                ],
                'profiles'         => [
                    'svc_to_order'  => $this->outboundProfile(),
                    'order_inbound' => $this->inboundProfile(),
                ],
                'key_providers'    => [
                    'driver' => 'array',
                ],
            ],
        ];
    }
    
    /**
     * 出站 Profile：product-center → order-api。
     */
    protected function outboundProfile()
    {
        return [
            'enabled'            => true,
            'direction'          => 'outbound',
            'client_id'          => 'product-center',
            'subject_type'       => 'service',
            'subject_id'         => 'product-center',
            'target_service'     => 'order-api',
            'security_mode'      => 'token_plus_request_signature',
            'authentication'     => ['driver' => 'jwt'],
            'signature'          => [
                'enabled'                      => true,
                'driver'                       => 'hmac_sha256',
                'key_id'                       => self::HMAC_KEY,
                'max_age_seconds'              => 300,
                'clock_skew_seconds'           => 60,
                'replay_protection'            => true,
                'replay_safety_margin_seconds' => 5,
            ],
            'encryption'         => [
                'enabled' => true,
                'driver'  => 'aes_256_gcm',
                'key_id'  => self::ENC_KEY,
            ],
            'response_integrity' => [
                'required'   => true,
                'mode'       => 'encrypted',
                'encryption' => ['key_id' => self::RESP_ENC_KEY],
            ],
            'token'              => [
                'attach_enabled'        => true,
                'verify_enabled'        => false,
                'issue_enabled'         => false,
                'driver'                => 'jwt_rs256',
                'issuer'                => 'tozo-auth',
                'audience'              => ['order-api'],
                'ttl_seconds'           => 900,
                'clock_skew_seconds'    => 60,
                'allowed_subject_types' => ['service'],
                'signing_key_id'        => 'jwt-private-2026-08',
            ],
            'scope'              => [
                'allowed_scopes' => ['order.read', 'order.write'],
            ],
        ];
    }
    
    /**
     * 入站 Profile：order-api 接收 product-center 调用。
     */
    protected function inboundProfile()
    {
        return [
            'enabled'        => true,
            'direction'      => 'inbound',
            'client_id'      => 'product-center',
            'subject_type'   => 'service',
            'target_service' => 'order-api',
            'security_mode'  => 'token_plus_request_signature',
            'authentication' => ['driver' => 'jwt'],
            'signature'      => [
                'enabled'                      => true,
                'driver'                       => 'hmac_sha256',
                'key_id'                       => self::HMAC_KEY,
                'max_age_seconds'              => 300,
                'clock_skew_seconds'           => 60,
                'replay_protection'            => true,
                'replay_safety_margin_seconds' => 5,
            ],
            'token'          => [
                'attach_enabled'        => false,
                'verify_enabled'        => true,
                'issue_enabled'         => false,
                'driver'                => 'jwt_rs256',
                'issuer'                => 'tozo-auth',
                'audience'              => ['order-api'],
                'ttl_seconds'           => 900,
                'clock_skew_seconds'    => 60,
                'expected_client_id'    => 'product-center',
                'allowed_subject_types' => ['service'],
                // kid 与签发方 signing_key_id 对齐（测试向量约定）。
                'allowed_kids'          => ['jwt-private-2026-08' => 'jwt-public-2026-08'],
            ],
            'scope'          => [
                'allowed_scopes' => ['order.read', 'order.write'],
            ],
            'replay_store'   => ['driver' => 'cache'],
        ];
    }
    
    /**
     * 按点号路径写入数组。
     *
     * @param mixed $value
     */
    private function setDot(array &$target, string $dots, $value)
    {
        $segments = explode('.', $dots);
        $ref      = &$target;
        foreach ($segments as $segment) {
            if (!isset($ref[$segment]) || !is_array($ref[$segment])) {
                $ref[$segment] = [];
            }
            $ref = &$ref[$segment];
        }
        $ref = $value;
    }
    
    /**
     * 默认测试密钥集；HMAC 密钥任意长度，AES 密钥必须 32 字节。
     */
    protected function defaultKeys()
    {
        return [
            self::HMAC_KEY     => str_repeat('a', 32),
            self::ENC_KEY      => str_repeat('b', 32),
            self::RESP_ENC_KEY => str_repeat('c', 32),
        ];
    }
    
    /**
     * 生成 RSA 2048 公私钥对（每次测试运行独立生成）。
     *
     * @return array{0:string,1:string} [privatePem, publicPem]
     */
    protected function generateRsaKeyPair()
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        
        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);
        
        return [$privatePem, $details['key']];
    }
}
