<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 响应完整性闭环测试
 *
 * 文件功能：
 * - 证明服务端生成的保护能被调用端验证通过（encrypted 与 signed 双模式）
 * - 证明篡改、跨方向复用、缺失保护、错误密钥一律被拒绝
 * - 覆盖 ResponseIntegrityMiddleware 的放行/保护/失败关闭三类路径
 *
 * 安全边界：
 * - 生成侧只允许 active 密钥；验证侧接受迁移期只读状态
 * - required=true 但无法生成保护时必须返回 500，绝不写出明文响应
 */

namespace Tozo\Security\Tests\Unit;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Exceptions\KeyNotFoundException;
use Tozo\Security\Profile;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\ResponseIntegrityException;
use Tozo\Security\Laravel\Middleware\ResponseIntegrityMiddleware;
use Tozo\Security\Encryption\ResponseIntegrityChecker;

class ResponseIntegrityClosureTest extends TestCase
{
    /**
     * 响应签名用途 key_id。独立于请求签名密钥，
     * 使 signed 模式的生成与验证用例都走独立用途密钥路径。
     */
    public const RESP_SIGN_KEY = 'order-response-signing';
    
    /**
     * encrypted 模式：服务端生成信封 → 调用端解密还原同一明文。
     */
    public function test_encrypted_response_round_trips_between_server_and_client()
    {
        $checker = $this->checker();
        $profile = $this->encryptedProfile();
        
        $envelope = $checker->protectEncryptedResponse('{"order_id":42}', $profile);
        
        // 信封本身不得包含明文。
        $this->assertStringNotContainsString('order_id', $envelope);
        $this->assertSame('{"order_id":42}', $checker->decryptEncryptedResponse($envelope, $profile));
    }
    
    private function checker()
    {
        $keys = $this->keyProvider();
        
        return new ResponseIntegrityChecker(new AesGcmCipher($keys), $keys);
    }
    
    private function keyProvider()
    {
        return new ArrayKeyProvider(array_merge($this->defaultKeys(), [
            self::RESP_SIGN_KEY => str_repeat('d', 32),
        ]));
    }
    
    private function encryptedProfile()
    {
        $config                       = $this->inboundProfile();
        $config['encryption']         = ['enabled' => true, 'driver' => 'aes_256_gcm', 'key_id' => self::ENC_KEY];
        $config['response_integrity'] = [
            'required'   => true,
            'mode'       => 'encrypted',
            'encryption' => ['key_id' => self::RESP_ENC_KEY],
        ];
        
        return Profile::fromConfig('order_inbound', $config, $this->keyProvider());
    }
    
    /**
     * encrypted 模式信封结构必须是 Protocol v1 六字段版本化形态。
     */
    public function test_encrypted_response_envelope_shape()
    {
        $envelope = json_decode(
            $this->checker()->protectEncryptedResponse('{"ok":true}', $this->encryptedProfile()),
            true
        );
        
        $this->assertSame('1', $envelope['version']);
        $this->assertSame('aes_256_gcm', $envelope['algorithm']);
        $this->assertSame(self::RESP_ENC_KEY, $envelope['key_id']);
        $this->assertArrayHasKey('iv', $envelope);
        $this->assertArrayHasKey('ciphertext', $envelope);
        $this->assertArrayHasKey('tag', $envelope);
    }
    
    /**
     * 同一明文两次加密必须产生不同 nonce 与密文（CSPRNG nonce 唯一性）。
     */
    public function test_encrypted_response_uses_fresh_nonce_each_time()
    {
        $checker = $this->checker();
        $profile = $this->encryptedProfile();
        
        $first  = json_decode($checker->protectEncryptedResponse('same', $profile), true);
        $second = json_decode($checker->protectEncryptedResponse('same', $profile), true);
        
        $this->assertNotSame($first['iv'], $second['iv']);
        $this->assertNotSame($first['ciphertext'], $second['ciphertext']);
    }
    
    /**
     * 密文被篡改时 GCM tag 校验必须失败。
     */
    public function test_tampered_encrypted_response_is_rejected()
    {
        $checker = $this->checker();
        $profile = $this->encryptedProfile();
        
        $envelope = json_decode($checker->protectEncryptedResponse('{"ok":true}', $profile), true);
        
        // 确定性篡改：把首字符换成一个必然不同的 Base64URL 字符，保证密文真的发生变化。
        $original               = (string)$envelope['ciphertext'];
        $envelope['ciphertext'] = ($original[0] === 'A' ? 'B' : 'A') . substr($original, 1);
        $this->assertNotSame($original, $envelope['ciphertext']);
        
        $this->expectException(ResponseIntegrityException::class);
        $checker->decryptEncryptedResponse((string)json_encode($envelope), $profile);
    }
    
    /**
     * 请求方向密文不得当作响应验证通过：AAD 绑定方向。
     */
    public function test_request_direction_envelope_is_rejected_as_response()
    {
        $keys    = $this->keyProvider();
        $cipher  = new AesGcmCipher($keys);
        $profile = $this->encryptedProfile();
        
        // 以 request 方向加密（使用请求密钥），再试图当作响应验证。
        $requestEnvelope = $cipher->encryptString('{"ok":true}', $profile, 'request', 'POST', '/api/orders');
        
        $this->expectException(ResponseIntegrityException::class);
        $this->checker()->decryptEncryptedResponse($requestEnvelope, $profile);
    }
    
    /**
     * signed 模式：服务端生成签名 → 调用端验证通过。
     */
    public function test_signed_response_round_trips_between_server_and_client()
    {
        $checker = $this->checker();
        $profile = $this->signedProfile();
        $body    = '{"ok":true}';
        
        $signature = $checker->protectSignedResponse($body, $profile);
        
        $checker->verifySignedResponse(
            $body,
            [ResponseIntegrityChecker::SIGNED_MODE_SIGNATURE_HEADER => $signature],
            $profile
        );
        
        $this->assertNotSame('', $signature);
    }
    
    private function signedProfile($keys = null)
    {
        $config                       = $this->inboundProfile();
        $config['response_integrity'] = [
            'required'  => true,
            'mode'      => 'signed',
            'signature' => ['key_id' => self::RESP_SIGN_KEY],
        ];
        
        return Profile::fromConfig('order_inbound', $config, $keys ?? $this->keyProvider());
    }
    
    /**
     * signed 模式 Body 被改动后签名必须不匹配。
     */
    public function test_signed_response_rejects_modified_body()
    {
        $checker = $this->checker();
        $profile = $this->signedProfile();
        
        $signature = $checker->protectSignedResponse('{"ok":true}', $profile);
        
        $this->expectException(ResponseIntegrityException::class);
        $checker->verifySignedResponse(
            '{"ok":false}',
            [ResponseIntegrityChecker::SIGNED_MODE_SIGNATURE_HEADER => $signature],
            $profile
        );
    }
    
    /**
     * 签名头大小写不敏感：网关归一化 Header 后仍必须能验证。
     */
    public function test_signed_response_header_lookup_is_case_insensitive()
    {
        $checker = $this->checker();
        $profile = $this->signedProfile();
        $body    = '{"ok":true}';
        
        $signature = $checker->protectSignedResponse($body, $profile);
        
        $checker->verifySignedResponse($body, ['x-tozo-response-signature' => $signature], $profile);
        $this->assertTrue(true);
    }
    
    /**
     * 生成侧只允许 active 密钥：verify_only 旧密钥不得再签发新响应。
     */
    public function test_signed_response_generation_rejects_verify_only_key()
    {
        $keys    = new ArrayKeyProvider(
            array_merge($this->defaultKeys(), [self::RESP_SIGN_KEY => str_repeat('d', 32)]),
            [self::RESP_SIGN_KEY => 'verify_only']
        );
        $checker = new ResponseIntegrityChecker(new AesGcmCipher($keys), $keys);
        
        $this->expectException(KeyNotFoundException::class);
        $checker->protectSignedResponse('{"ok":true}', $this->signedProfile($keys));
    }
    
    /**
     * Header 名称必须由接口统一暴露，生成与验证共用同一来源。
     */
    public function test_signature_header_name_is_exposed()
    {
        $this->assertSame(
            ResponseIntegrityChecker::SIGNED_MODE_SIGNATURE_HEADER,
            $this->checker()->getSignatureHeaderName()
        );
    }
    
    /**
     * 生成侧同样受 mode 固定约束：signed Profile 不能走 encrypted 生成路径。
     */
    public function test_generation_respects_fixed_mode()
    {
        $this->expectException(ConfigurationException::class);
        $this->checker()->protectEncryptedResponse('{"ok":true}', $this->signedProfile());
    }
    
    /**
     * 中间件：encrypted 模式必须替换 Body 并修正 Content-Type。
     */
    public function test_middleware_encrypts_successful_response()
    {
        $checker    = $this->checker();
        $profile    = $this->encryptedProfile();
        $middleware = new ResponseIntegrityMiddleware($checker);
        
        $response = $middleware->handle(
            $this->authenticatedRequest($profile),
            function () {
                return new Response('{"order_id":42}', 200, ['Content-Type' => 'text/plain']);
            }
        );
        
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
        $this->assertSame(
            '{"order_id":42}',
            $checker->decryptEncryptedResponse((string)$response->getContent(), $profile)
        );
    }
    
    private function authenticatedRequest(Profile $profile)
    {
        $request = Request::create('https://order-api.test/api/orders', 'GET');
        // 模拟 InboundAuthenticatorMiddleware 认证通过后写入的可信 attribute。
        $request->attributes->set('tozo_security_profile', $profile);
        
        return $request;
    }
    
    /**
     * 中间件：signed 模式保留明文 Body 并追加签名头。
     */
    public function test_middleware_signs_successful_response()
    {
        $checker    = $this->checker();
        $profile    = $this->signedProfile();
        $middleware = new ResponseIntegrityMiddleware($checker);
        
        $response = $middleware->handle(
            $this->authenticatedRequest($profile),
            function () {
                return new Response('{"ok":true}', 200);
            }
        );
        
        $this->assertSame('{"ok":true}', (string)$response->getContent());
        
        $checker->verifySignedResponse(
            (string)$response->getContent(),
            [ResponseIntegrityChecker::SIGNED_MODE_SIGNATURE_HEADER
             => $response->headers->get(ResponseIntegrityChecker::SIGNED_MODE_SIGNATURE_HEADER)],
            $profile
        );
    }
    
    /**
     * required=false 的 Profile 响应原样放行，不引入无关保护。
     */
    public function test_middleware_passes_through_when_integrity_not_required()
    {
        $config = $this->inboundProfile();
        unset($config['response_integrity']);
        $profile = Profile::fromConfig('plain', $config, $this->keyProvider());
        
        $response = (new ResponseIntegrityMiddleware($this->checker()))->handle(
            $this->authenticatedRequest($profile),
            function () {
                return new Response('{"ok":true}', 200);
            }
        );
        
        $this->assertSame('{"ok":true}', (string)$response->getContent());
        $this->assertNull($response->headers->get(ResponseIntegrityChecker::SIGNED_MODE_SIGNATURE_HEADER));
    }
    
    /**
     * 未经入站认证的请求不得获得有效响应证明。
     */
    public function test_middleware_does_not_protect_unauthenticated_requests()
    {
        $response = (new ResponseIntegrityMiddleware($this->checker()))->handle(
            Request::create('https://order-api.test/api/orders', 'GET'),
            function () {
                return new Response('{"ok":true}', 200);
            }
        );
        
        $this->assertSame('{"ok":true}', (string)$response->getContent());
    }
    
    /**
     * 错误响应保留原状态与安全类别码，不被加密掩盖。
     */
    public function test_middleware_leaves_error_responses_untouched()
    {
        $response = (new ResponseIntegrityMiddleware($this->checker()))->handle(
            $this->authenticatedRequest($this->encryptedProfile()),
            function () {
                return new Response('{"error":"access_denied"}', 403);
            }
        );
        
        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('{"error":"access_denied"}', (string)$response->getContent());
    }
    
    /**
     * required=true 但生成器绑定缺失时必须 500，绝不退化为明文响应。
     */
    public function test_middleware_fails_closed_when_checker_binding_missing()
    {
        $response = (new ResponseIntegrityMiddleware(null))->handle(
            $this->authenticatedRequest($this->encryptedProfile()),
            function () {
                return new Response('{"secret":true}', 200);
            }
        );
        
        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame('{"error":"internal_error"}', (string)$response->getContent());
        $this->assertStringNotContainsString('secret', (string)$response->getContent());
    }
    
    /**
     * 响应密钥不可解析时同样失败关闭，不写出未受保护 Body。
     */
    public function test_middleware_fails_closed_when_response_key_missing()
    {
        $keys                         = new ArrayKeyProvider($this->defaultKeys());
        $config                       = $this->inboundProfile();
        $config['response_integrity'] = [
            'required'   => true,
            'mode'       => 'encrypted',
            'encryption' => ['key_id' => 'absent-response-key'],
        ];
        $profile                      = Profile::fromConfig('missing-key', $config, $keys);
        
        $response = (new ResponseIntegrityMiddleware(
            new ResponseIntegrityChecker(new AesGcmCipher($keys), $keys)
        ))->handle(
            $this->authenticatedRequest($profile),
            function () {
                return new Response('{"secret":true}', 200);
            }
        );
        
        $this->assertSame(500, $response->getStatusCode());
        $this->assertStringNotContainsString('secret', (string)$response->getContent());
    }
}
