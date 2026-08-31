<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 加密体积闸门测试
 *
 * 文件功能：
 * - 固化「超大明文必须以可捕获异常失败，而不是触发 fatal OOM」这一要求
 * - 覆盖闸门生效、边界值、未配置时不限制、非法配置被拒四类路径
 *
 * 为什么必须固化：
 * - 实测加密峰值内存为明文体积的 3.5～6 倍（明文、密文、Base64、JSON 同时驻留）。
 *   PHP memory_limit=128M 下 24 MB 明文峰值已达 124 MB；再大即 fatal OOM。
 *   fatal OOM 不可捕获：调用方拿不到异常、写不了审计、返回不了干净错误，
 *   fail-closed 语义退化为"进程被杀"，不受 SDK 控制。
 *
 * 安全边界：
 * - 闸门必须在任何大块分配之前触发，否则失去意义
 * - 异常消息只含体积数字，不得含明文片段
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Exceptions\EncryptionException;
use Tozo\Security\Profile;
use Tozo\Security\Support\ConfigNormalizer;
use Tozo\Security\Exceptions\ConfigurationException;

class PayloadSizeGuardTest extends TestCase
{
    /**
     * 超出上限的明文必须抛可捕获异常，并带 payload_too_large 原因码。
     */
    public function test_oversized_plaintext_is_rejected_with_catchable_exception()
    {
        $cipher  = $this->cipher();
        $profile = $this->profileWithLimit(1024);
        
        try {
            $cipher->encryptString(str_repeat('x', 2048), $profile, 'request', 'POST', '/api/x');
            $this->fail('超出上限的明文应被拒绝');
        } catch (EncryptionException $e) {
            $this->assertSame('payload_too_large', $e->getReasonCode());
            $this->assertSame(413, $e->getCode());
        }
    }
    
    /**
     * 构造加解密器。
     *
     * @return AesGcmCipher AEAD 实现实例。
     */
    private function cipher()
    {
        return new AesGcmCipher($this->keys());
    }
    
    /**
     * 构造测试密钥提供器。
     *
     * @return ArrayKeyProvider 含签名与加密密钥的内存提供器。
     */
    private function keys()
    {
        return new ArrayKeyProvider($this->defaultKeys());
    }
    
    /**
     * 构造带指定上限的加密 Profile。
     *
     * @param int $limit 明文体积上限（字节）。
     * @return Profile 已校验的 Profile 实例。
     */
    private function profileWithLimit(int $limit)
    {
        $config                                      = $this->encryptionProfileConfig();
        $config['encryption']['max_plaintext_bytes'] = $limit;
        
        return Profile::fromConfig('limited', $config, $this->keys());
    }
    
    /**
     * 构造启用加密的出站 Profile 配置骨架。
     *
     * @return array Profile 配置数组。
     */
    private function encryptionProfileConfig()
    {
        $config                            = $this->outboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['token']['attach_enabled'] = false;
        unset($config['response_integrity']);
        $config['encryption'] = [
            'enabled' => true,
            'driver'  => 'aes_256_gcm',
            'key_id'  => self::ENC_KEY,
        ];
        
        return $config;
    }
    
    /**
     * 异常消息必须给出实际体积与上限，便于直接调参；且不得含明文片段。
     */
    public function test_exception_message_is_actionable_but_leaks_no_plaintext()
    {
        $cipher  = $this->cipher();
        $profile = $this->profileWithLimit(1024);
        
        // 使用高度可识别的明文标记，确认它不会出现在消息中。
        $marker    = 'CARDNUMBER4111111111111111';
        $plaintext = $marker . str_repeat('x', 4096);
        
        try {
            $cipher->encryptString($plaintext, $profile, 'request', 'POST', '/api/x');
            $this->fail('超出上限的明文应被拒绝');
        } catch (EncryptionException $e) {
            $message = $e->getMessage();
            
            $this->assertStringContainsString((string)strlen($plaintext), $message, '消息应含实际体积');
            $this->assertStringContainsString('1024', $message, '消息应含配置上限');
            $this->assertStringNotContainsString($marker, $message, '消息不得包含明文片段');
        }
    }
    
    /**
     * 恰好等于上限的明文必须放行（边界值不应误拒）。
     */
    public function test_plaintext_exactly_at_limit_is_allowed()
    {
        $cipher  = $this->cipher();
        $profile = $this->profileWithLimit(1024);
        
        $envelope = $cipher->encryptString(str_repeat('x', 1024), $profile, 'request', 'POST', '/api/x');
        
        $this->assertSame(
            str_repeat('x', 1024),
            $cipher->decryptEnvelopeJson($envelope, $profile, 'request', 'POST', '/api/x')
        );
    }
    
    /**
     * 未配置上限时不限制，保持既有行为不被静默改变。
     */
    public function test_absent_limit_means_no_restriction()
    {
        $cipher = $this->cipher();
        
        $config = $this->encryptionProfileConfig();
        // 显式移除该键：表示"不限制"。
        unset($config['encryption']['max_plaintext_bytes']);
        $profile = Profile::fromConfig('no-limit', $config, $this->keys());
        
        $this->assertNull($profile->getEncryptionMaxPlaintextBytes());
        
        $plaintext = str_repeat('x', 64 * 1024);
        $envelope  = $cipher->encryptString($plaintext, $profile, 'request', 'POST', '/api/x');
        
        $this->assertSame(
            $plaintext,
            $cipher->decryptEnvelopeJson($envelope, $profile, 'request', 'POST', '/api/x')
        );
    }
    
    /**
     * 上限写成 0 或负数属于配置错误：那样闸门形同虚设。
     *
     * @dataProvider invalidLimitProvider
     */
    public function test_non_positive_limit_is_a_configuration_error($limit)
    {
        $config                                      = $this->encryptionProfileConfig();
        $config['encryption']['max_plaintext_bytes'] = $limit;
        
        $this->expectException(ConfigurationException::class);
        Profile::fromConfig('bad-limit', $config, $this->keys());
    }
    
    public function invalidLimitProvider()
    {
        return [
            'zero'        => [0],
            'negative'    => [-1],
            'non numeric' => ['unlimited'],
        ];
    }
    
    /**
     * 闸门同样作用于响应方向加密（服务端生成响应保护时）。
     */
    public function test_guard_applies_to_response_direction()
    {
        $cipher = $this->cipher();
        
        $config                                      = $this->encryptionProfileConfig();
        $config['response_integrity']                = [
            'required'   => true,
            'mode'       => 'encrypted',
            'encryption' => ['key_id' => self::RESP_ENC_KEY],
        ];
        $config['encryption']['max_plaintext_bytes'] = 512;
        $profile                                     = Profile::fromConfig('resp-limit', $config, $this->keys());
        
        $this->expectException(EncryptionException::class);
        $cipher->encryptString(str_repeat('x', 1024), $profile, 'response');
    }
    
    /**
     * 包内默认配置展开后必须已设置上限，使下游默认就受保护。
     *
     * 为什么断言展开结果而不是配置文件原文：
     * 配置精简后包内不再有模板 Profile，体积上限由 ConfigNormalizer 固化为内置常量
     * 并写入每个展开出的 Profile。保护意图不变，事实来源从配置文件移到展开器。
     */
    public function test_shipped_config_sets_a_positive_limit()
    {
        $config = require dirname(__DIR__, 2) . '/config/tozo_security.php';

        // 声明一个对端使配置进入极简形态，取展开后的 Profile 检查上限。
        $normalized = ConfigNormalizer::normalize(array_merge($config, [
            'service' => 'tozo-app-api',
            'peers'   => ['pos-api' => 'https://pos-api.example.com'],
        ]));

        $this->assertNotSame([], $normalized['profiles'], '声明对端后应展开出 Profile');

        foreach ($normalized['profiles'] as $name => $profile) {
            $limit = $profile['encryption']['max_plaintext_bytes'] ?? null;

            $this->assertNotNull($limit, "{$name} 应显式设置加密体积上限");
            $this->assertGreaterThan(0, (int)$limit, $name);
        }
    }
}
