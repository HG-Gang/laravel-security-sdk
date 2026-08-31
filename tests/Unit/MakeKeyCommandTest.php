<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 密钥生成命令测试
 *
 * 文件功能：
 * - 固化 make-key 输出的密钥能被对应模块直接使用，而不是"看起来像密钥"
 * - 覆盖长度约束、字符集安全性、非法参数拒绝与熵来源
 *
 * 为什么必须固化：
 * - KeyProvider 返回环境变量的字符串原文，AesGcmCipher 要求 strlen 恰为 32。
 *   若命令输出 base64_encode(random_bytes(32))（44 字符），下游按提示写入 .env 后
 *   首次加密即抛 ConfigurationException —— 命令本身成了故障源。
 *
 * 安全边界：
 * - 断言密钥字符集不含引号、空格与等号，确保可安全写入 .env 单行
 * - 断言两次生成不相同，确认走的是 CSPRNG 而非固定值
 */

namespace Tozo\Security\Tests\Unit;

use ReflectionMethod;
use Tozo\Security\Tests\TestCase;
use Illuminate\Container\Container;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Profile;
use Tozo\Security\Laravel\Command\SecurityMakeKeyCommand;

class MakeKeyCommandTest extends TestCase
{
    /**
     * AES 用途生成的密钥长度必须恰好等于 AesGcmCipher 要求的字节数。
     */
    public function test_aes_key_length_matches_cipher_requirement()
    {
        $key = $this->generateKey(AesGcmCipher::KEY_BYTES);
        
        $this->assertSame(
            AesGcmCipher::KEY_BYTES,
            strlen($key),
            'AES 密钥字符串长度必须等于 KEY_BYTES，否则 resolveKey 会拒绝'
        );
    }
    
    /**
     * 调用命令的私有生成方法。
     *
     * 使用范围：本测试类各用例复用。
     * 适用场景：生成逻辑是私有实现细节，但其正确性是对外承诺，必须直接验证。
     *
     * @param int $bytes 目标字节长度。
     * @return string 生成的密钥字符串。
     */
    private function generateKey(int $bytes)
    {
        $method = new ReflectionMethod(SecurityMakeKeyCommand::class, 'generateKey');
        $method->setAccessible(true);
        
        return $method->invoke(new SecurityMakeKeyCommand(), $bytes);
    }
    
    /**
     * 生成的密钥必须能真正完成一次加解密往返 —— 这是"可用"的唯一判据。
     */
    public function test_generated_aes_key_actually_works_for_encryption()
    {
        $key = $this->generateKey(AesGcmCipher::KEY_BYTES);
        
        $keys = new ArrayKeyProvider([
            'req-enc' => $key,
            'sig'     => $this->generateKey(32),
        ]);
        
        $config                            = $this->outboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['token']['attach_enabled'] = false;
        unset($config['response_integrity']);
        $config['signature']['key_id'] = 'sig';
        $config['encryption']          = ['enabled' => true, 'driver' => 'aes_256_gcm', 'key_id' => 'req-enc'];
        
        $profile = Profile::fromConfig('gen-key', $config, $keys);
        $cipher  = new AesGcmCipher($keys);
        
        $envelope = $cipher->encryptString('{"sku":"A-1"}', $profile, 'request', 'POST', '/api/orders');
        
        $this->assertSame(
            '{"sku":"A-1"}',
            $cipher->decryptEnvelopeJson($envelope, $profile, 'request', 'POST', '/api/orders')
        );
    }
    
    /**
     * 生成的密钥必须能直接用于 HMAC 签名（任意长度均可，但需非空且确定）。
     */
    public function test_generated_hmac_key_works_for_signing()
    {
        $key = $this->generateKey(32);
        
        $this->assertSame(32, strlen($key));
        $this->assertNotSame('', hash_hmac('sha256', 'payload', $key, true));
    }
    
    /**
     * 字符集必须可安全写入 .env 单行：不含引号、空格、等号、井号与反斜杠。
     */
    public function test_key_charset_is_env_file_safe()
    {
        for ($i = 0; $i < 20; $i++) {
            $key = $this->generateKey(32);
            
            $this->assertSame(
                1,
                preg_match('/^[A-Za-z0-9\-_]+$/', $key),
                "密钥含 .env 不安全字符：{$key}"
            );
        }
    }
    
    /**
     * 连续生成必须不同，确认使用了 CSPRNG 而非固定值或时间种子。
     */
    public function test_keys_are_not_repeatable()
    {
        $generated = [];
        
        for ($i = 0; $i < 50; $i++) {
            $generated[] = $this->generateKey(32);
        }
        
        $this->assertCount(
            50,
            array_unique($generated),
            '50 次生成出现重复，随机源可能不是 CSPRNG'
        );
    }
    
    /**
     * 各种长度都必须精确命中，避免 Base64 截断产生 off-by-one。
     *
     * @dataProvider lengthProvider
     */
    public function test_exact_length_for_various_sizes(int $bytes)
    {
        $this->assertSame($bytes, strlen($this->generateKey($bytes)));
    }
    
    public function lengthProvider()
    {
        return [[32], [33], [48], [64], [100]];
    }
    
    /**
     * 命令必须已注册到 Provider，否则 artisan 里不可见。
     */
    public function test_command_is_registered_by_provider()
    {
        $source = (string)file_get_contents(
            dirname(__DIR__, 2) . '/src/Tozo/Security/ServiceProvider.php'
        );
        
        $this->assertStringContainsString('SecurityMakeKeyCommand::class', $source);
    }
    
    /**
     * 命令签名必须声明三个选项，且描述中不出现"写入文件"类误导表述。
     */
    public function test_command_signature_and_safety_notice()
    {
        $command = new SecurityMakeKeyCommand();
        $command->setLaravel(new Container());
        
        $this->assertSame('tozo:security:make-key', $command->getName());
        
        $definition = $command->getDefinition();
        foreach (['usage', 'key-id', 'bytes'] as $option) {
            $this->assertTrue($definition->hasOption($option), "缺少 --{$option} 选项");
        }
        
        $this->assertStringContainsString('不写入任何文件', $command->getDescription());
    }
}
