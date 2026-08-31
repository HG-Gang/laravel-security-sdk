<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Payload;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\InvalidCiphertextException;

class AesGcmCipherTest extends TestCase
{
    public function test_encrypt_decrypt_roundtrip_restores_plaintext()
    {
        $cipher  = $this->cipher();
        $profile = $this->profile(['encryption' => [
            'enabled' => true,
            'driver'  => 'aes_256_gcm',
            'key_id'  => self::ENC_KEY,
        ]]);
        
        $payload = new Payload([
            'method' => 'POST',
            'path'   => '/api/orders',
            'body'   => '{"order_id":42}',
        ]);
        
        $encrypted = $cipher->encrypt($payload, $profile);
        
        // 加密后 Body 即信封 JSON（Encrypt-then-Sign 的签名对象）。
        $envelope = json_decode((string)$encrypted->get('body'), true);
        $this->assertSame('1', $envelope['version']);
        $this->assertSame('aes_256_gcm', $envelope['algorithm']);
        $this->assertSame(self::ENC_KEY, $envelope['key_id']);
        
        $decrypted = $cipher->decrypt($encrypted, $profile);
        $this->assertSame('{"order_id":42}', (string)$decrypted->get('body'));
    }
    
    private function cipher()
    {
        return new AesGcmCipher(new ArrayKeyProvider($this->defaultKeys()));
    }
    
    private function profile(array $overrides = [])
    {
        $config = array_merge($this->outboundProfile(), $overrides);
        
        return \Tozo\Security\Profile::fromConfig('svc_to_order', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_nonce_is_unique_per_encryption()
    {
        $cipher  = $this->cipher();
        $profile = $this->profile(['encryption' => [
            'enabled' => true,
            'driver'  => 'aes_256_gcm',
            'key_id'  => self::ENC_KEY,
        ]]);
        
        $ivs = [];
        for ($i = 0; $i < 8; $i++) {
            $json  = $cipher->encryptString('same-plaintext', $profile, 'request', 'POST', '/x');
            $ivs[] = json_decode($json, true)['iv'];
        }
        
        $this->assertCount(8, array_unique($ivs));
    }
    
    public function test_tampered_ciphertext_fails_unified()
    {
        $cipher  = $this->cipher();
        $profile = $this->profile(['encryption' => [
            'enabled' => true,
            'driver'  => 'aes_256_gcm',
            'key_id'  => self::ENC_KEY,
        ]]);
        
        $envelope = json_decode(
            $cipher->encryptString('secret-body', $profile, 'request', 'POST', '/api'),
            true
        );
        
        // 翻转密文首字节。
        $raw                    = base64_decode(strtr($envelope['ciphertext'], '-_', '+/'));
        $raw[0]                 = $raw[0] ^ "\x01";
        $envelope['ciphertext'] = rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
        
        try {
            $cipher->decryptEnvelopeJson(json_encode($envelope), $profile, 'request', 'POST', '/api');
            $this->fail('Expected InvalidCiphertextException');
        } catch (InvalidCiphertextException $e) {
            // 统一失败结果，不区分具体校验项。
            $this->assertSame('decryption_failed', $e->getReasonCode());
        }
    }
    
    public function test_direction_binding_prevents_cross_direction_replay()
    {
        $cipher  = $this->cipher();
        $profile = $this->profile(['encryption' => [
            'enabled' => true,
            'driver'  => 'aes_256_gcm',
            'key_id'  => self::ENC_KEY,
        ]]);
        
        $json = $cipher->encryptString('payload', $profile, 'request', 'POST', '/api');
        
        // 请求方向密文拿到响应方向解密：AAD 不一致必须失败。
        $this->expectException(InvalidCiphertextException::class);
        $cipher->decryptEnvelopeJson($json, $profile, 'response');
    }
    
    public function test_envelope_key_id_must_match_profile()
    {
        $cipher  = $this->cipher();
        $profile = $this->profile(['encryption' => [
            'enabled' => true,
            'driver'  => 'aes_256_gcm',
            'key_id'  => self::ENC_KEY,
        ]]);
        
        $envelope           = json_decode(
            $cipher->encryptString('payload', $profile, 'request', 'POST', '/api'),
            true
        );
        $envelope['key_id'] = 'unknown-key';
        
        $this->expectException(InvalidCiphertextException::class);
        $cipher->decryptEnvelopeJson(json_encode($envelope), $profile, 'request', 'POST', '/api');
    }
    
    public function test_invalid_iv_length_is_rejected()
    {
        $cipher  = $this->cipher();
        $profile = $this->profile(['encryption' => [
            'enabled' => true,
            'driver'  => 'aes_256_gcm',
            'key_id'  => self::ENC_KEY,
        ]]);
        
        $envelope = json_decode(
            $cipher->encryptString('payload', $profile, 'request', 'POST', '/api'),
            true
        );
        
        // 8 字节 iv（应为 12）。
        $envelope['iv'] = rtrim(strtr(base64_encode(str_repeat("\0", 8)), '+/', '-_'), '=');
        
        $this->expectException(InvalidCiphertextException::class);
        $cipher->decryptEnvelopeJson(json_encode($envelope), $profile, 'request', 'POST', '/api');
    }
    
    public function test_wrong_key_length_fails_configuration()
    {
        $keys   = array_merge($this->defaultKeys(), ['short-key' => 'too-short']);
        $cipher = new AesGcmCipher(new ArrayKeyProvider($keys));
        
        $profile = \Tozo\Security\Profile::fromConfig('p', array_merge($this->outboundProfile(), [
            'encryption' => ['enabled' => true, 'driver' => 'aes_256_gcm', 'key_id' => 'short-key'],
        ]), new ArrayKeyProvider($keys));
        
        $this->expectException(ConfigurationException::class);
        $cipher->encryptString('x', $profile, 'request', 'POST', '/');
    }
}
