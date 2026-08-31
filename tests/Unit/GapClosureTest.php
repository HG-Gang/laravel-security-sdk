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
use Tozo\Security\Identity\Subject;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Token\JwtTokenIssuer;
use Tozo\Security\Support\ConfigChecker;
use Tozo\Security\Token\JwtTokenVerifier;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Exceptions\ClockSkewException;
use Tozo\Security\Exceptions\KeyNotFoundException;
use Tozo\Security\Profile;
use Tozo\Security\Storage\LaravelCacheReplayStore;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\TokenIssuanceException;
use Tozo\Security\Exceptions\AuthenticationException;
use Tozo\Security\Exceptions\TenantMismatchException;
use Tozo\Security\Exceptions\ReplayProtectionException;
use Tozo\Security\Authentication\HmacBearerAuthenticator;
use Tozo\Security\Protocol\Encoding;
use Tozo\Security\Exceptions\InvalidSignatureException;

/**
 * 七项设计缺口补齐的回归测试（#1 defaults / #2 轮换 / #5 hmac_bearer / #7 tenant-act / #3 checker）。
 */
class GapClosureTest extends TestCase
{
    // ------------------------------------------------------------------ #1
    public function test_app_defaults_fill_missing_fields()
    {
        $config = $this->outboundProfile();
        unset($config['signature']['max_age_seconds']);
        
        $profile = Profile::fromConfig('p', $config, new ArrayKeyProvider($this->defaultKeys()), [
            'signature' => ['max_age_seconds' => 120],
        ]);
        
        $this->assertSame(120, $profile->getSignatureMaxAgeSeconds());
    }
    
    public function test_explicit_null_stays_and_fails_validation()
    {
        $config                        = $this->outboundProfile();
        $config['signature']['key_id'] = null;
        
        $this->expectException(ConfigurationException::class);
        Profile::fromConfig('p', $config, new ArrayKeyProvider($this->defaultKeys()), [
            'signature' => ['key_id' => 'should-not-override-null'],
        ]);
    }
    
    public function test_explicit_null_in_app_defaults_fails_validation()
    {
        $config                            = $this->outboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['encryption']              = ['driver' => 'aes_256_gcm'];
        $config['token']['attach_enabled'] = false;
        
        $this->expectException(ConfigurationException::class);
        Profile::fromConfig('defaults-null', $config, new ArrayKeyProvider($this->defaultKeys()), [
            'encryption' => ['enabled' => null],
        ]);
    }
    
    /**
     * 安全配置中的显式 null 必须被拒绝，不能被解释成关闭或缺省值。
     *
     * @return void 每个字段路径均抛出 ConfigurationException。
     */
    public function test_all_security_explicit_nulls_fail_validation()
    {
        $paths = [
            'enabled',
            'direction',
            'client_id',
            'subject_type',
            'target_service',
            'security_mode',
            'authentication',
            'signature',
            'signature.enabled',
            'signature.driver',
            'signature.key_id',
            'signature.max_age_seconds',
            'encryption',
            'encryption.enabled',
            'encryption.driver',
            'encryption.key_id',
            'response_integrity',
            'response_integrity.required',
            'response_integrity.mode',
            'token',
            'token.attach_enabled',
            'token.verify_enabled',
            'token.issue_enabled',
            'token.driver',
            'token.issuer',
            'token.audience',
            'replay_store',
            'replay_store.driver',
            'token_revocation',
            'audit',
            'audit.driver',
        ];
        
        foreach ($paths as $path) {
            $config = $this->outboundProfile();
            $this->setConfigPath($config, $path, null);
            
            try {
                Profile::fromConfig('null-check', $config, new ArrayKeyProvider($this->defaultKeys()));
                $this->fail('Expected explicit null to fail: ' . $path);
            } catch (ConfigurationException $exception) {
                $this->assertStringContainsString('Profile [null-check]', $exception->getMessage());
                $this->assertStringContainsString('field [' . $path . ']', $exception->getMessage());
            }
        }
    }
    
    /**
     * 按点号路径向测试配置写入值，保留中间段的数组结构。
     *
     * @param array $config 待修改的 Profile 配置。
     * @param string $path 点号分隔的配置路径。
     * @param mixed $value 要写入的值。
     * @return void 配置通过引用被原地修改。
     */
    private function setConfigPath(array &$config, string $path, $value)
    {
        $segments = explode('.', $path);
        $cursor   = &$config;
        $last     = count($segments) - 1;
        
        foreach ($segments as $index => $segment) {
            if ($index === $last) {
                $cursor[$segment] = $value;
                return;
            }
            
            if (!isset($cursor[$segment]) || !is_array($cursor[$segment])) {
                $cursor[$segment] = [];
            }
            $cursor = &$cursor[$segment];
        }
    }
    
    // ------------------------------------------------------------------ #2

    public function test_sign_rejects_verify_only_key()
    {
        $this->expectException(KeyNotFoundException::class);
        $this->makeSigner($this->rotationProvider())
            ->sign(new Payload(['method' => 'POST', 'path' => '/', 'body' => '']), $this->rotationProfile('old-sign'));
    }
    
    private function makeSigner(ArrayKeyProvider $provider)
    {
        return new \Tozo\Security\Signature\HmacSha256Signer(
            $provider,
            new LaravelCacheReplayStore(new \Illuminate\Cache\Repository(new \Illuminate\Cache\ArrayStore())),
            new \Tozo\Security\Clock\SystemClock()
        );
    }
    
    private function rotationProvider()
    {
        return new ArrayKeyProvider(
            array_merge($this->defaultKeys(), ['old-sign' => str_repeat('z', 32)]),
            ['old-sign' => 'verify_only', 'dead-sign' => 'retired']
        );
    }
    
    private function rotationProfile(string $keyId)
    {
        $config                        = $this->outboundProfile();
        $config['signature']['key_id'] = $keyId;
        
        return Profile::fromConfig('p', $config, $this->rotationProvider());
    }
    
    public function test_verify_accepts_verify_only_key()
    {
        $active  = new ArrayKeyProvider([self::HMAC_KEY => str_repeat('a', 32)]);
        $rotated = new ArrayKeyProvider(
            [self::HMAC_KEY => str_repeat('a', 32)],
            [self::HMAC_KEY => 'verify_only']
        );
        
        $payload = new Payload([
            'method'         => 'GET',
            'path'           => '/x',
            'body'           => '',
            'client_id'      => 'product-center',
            'target_service' => 'order-api',
        ]);
        
        $signed = $this->makeSigner($active)->sign($payload, $this->rotationProfile(self::HMAC_KEY));
        
        $this->assertTrue(
            $this->makeSigner($rotated)->verify($signed, $this->rotationProfile(self::HMAC_KEY))
        );
    }
    
    public function test_retired_key_rejected_for_sign()
    {
        $provider = new ArrayKeyProvider(
            ['dead-sign' => str_repeat('d', 32)],
            ['dead-sign' => 'retired']
        );
        
        $this->expectException(KeyNotFoundException::class);
        $this->makeSigner($provider)
            ->sign(new Payload(['method' => 'GET', 'path' => '/', 'body' => '']), $this->rotationProfile('dead-sign'));
    }
    
    // ------------------------------------------------------------------ #5

    public function test_bearer_roundtrip_returns_subject()
    {
        $subject = $this->bearerAuthenticator()
            ->authenticate($this->bearerPayload($this->bearerHeader('{"ping":1}')), $this->bearerProfile());
        
        $this->assertInstanceOf(Subject::class, $subject);
        $this->assertSame('service:product-center', $subject->getSub());
    }
    
    private function bearerAuthenticator()
    {
        return new HmacBearerAuthenticator(
            new ArrayKeyProvider($this->defaultKeys()),
            new LaravelCacheReplayStore(new \Illuminate\Cache\Repository(new \Illuminate\Cache\ArrayStore())),
            new \Tozo\Security\Clock\SystemClock()
        );
    }
    
    private function bearerPayload(string $auth)
    {
        return new Payload([
            'authorization' => $auth,
            'method'        => 'POST',
            'path'          => '/api/echo',
            'body'          => '{"ping":1}',
        ]);
    }
    
    private function bearerHeader(string $body, int $ts = null, string $sigOverride = null)
    {
        $ts        = $ts ?? time();
        $nonce     = bin2hex(random_bytes(16));
        $canonical = implode("\n", [
            CanonicalRequest::PROTOCOL_VERSION,
            (string)$ts,
            $nonce,
            'POST',
            CanonicalRequest::normalizePath('/api/echo'),
            hash('sha256', $body),
        ]);
        $sig       = Encoding::base64UrlEncode(hash_hmac('sha256', $canonical, str_repeat('a', 32), true));
        if ($sigOverride !== null) {
            $sig = $sigOverride;
        }
        
        return 'HMAC-Bearer key_id="' . self::HMAC_KEY . '", timestamp="' . $ts . '", nonce="' . $nonce . '", signature="' . $sig . '"';
    }
    
    private function bearerProfile()
    {
        $config                  = $this->inboundProfile();
        $config['security_mode'] = 'token_only';
        // token_only 要求签名关闭；认证腿由 hmac_bearer_sha256 承担。
        $config['signature']['enabled']    = false;
        $config['authentication']          = ['driver' => 'hmac_bearer_sha256', 'key_id' => self::HMAC_KEY];
        $config['token']['verify_enabled'] = false;
        
        return Profile::fromConfig('bearer_inbound', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_bearer_tampered_proof_rejected()
    {
        $this->expectException(InvalidSignatureException::class);
        $this->bearerAuthenticator()->authenticate(
            $this->bearerPayload($this->bearerHeader('{"ping":1}', null, 'broken-sig')),
            $this->bearerProfile()
        );
    }
    
    public function test_bearer_expired_timestamp_rejected()
    {
        $this->expectException(ClockSkewException::class);
        $this->bearerAuthenticator()->authenticate(
            $this->bearerPayload($this->bearerHeader('{"ping":1}', time() - 1000)),
            $this->bearerProfile()
        );
    }
    
    public function test_bearer_replayed_nonce_rejected()
    {
        $store = new LaravelCacheReplayStore(new \Illuminate\Cache\Repository(new \Illuminate\Cache\ArrayStore()));
        $auth  = new HmacBearerAuthenticator(
            new ArrayKeyProvider($this->defaultKeys()),
            $store,
            new \Tozo\Security\Clock\SystemClock()
        );
        
        $header  = $this->bearerHeader('{"ping":1}');
        $payload = $this->bearerPayload($header);
        
        $auth->authenticate($payload, $this->bearerProfile());
        
        $this->expectException(ReplayProtectionException::class);
        $auth->authenticate($payload, $this->bearerProfile());
    }
    
    public function test_bearer_malformed_header_rejected()
    {
        $this->expectException(AuthenticationException::class);
        $this->bearerAuthenticator()
            ->authenticate($this->bearerPayload('Bearer abc'), $this->bearerProfile());
    }
    
    // ------------------------------------------------------------------ #7

    public function test_extra_claims_cannot_override_protected()
    {
        require_once dirname(__DIR__, 2) . '/tests/fixtures/jwt_keys.php';
        
        $keys                             = $this->tenantKeys();
        $config                           = $this->outboundProfile();
        $config['token']['issue_enabled'] = true;
        
        $issuer = new JwtTokenIssuer(new ArrayKeyProvider($keys), new \Tozo\Security\Clock\SystemClock());
        
        $this->expectException(TokenIssuanceException::class);
        $issuer->issue(
            Profile::fromConfig('i', $config, new ArrayKeyProvider($keys)),
            ['sub' => 'user:999']
        );
    }
    
    private function tenantKeys()
    {
        return array_merge($this->defaultKeys(), jwt_test_keys());
    }
    
    public function test_verifier_enforces_allowed_tenants()
    {
        require_once dirname(__DIR__, 2) . '/tests/fixtures/jwt_keys.php';
        
        $keys                               = $this->tenantKeys();
        $issueCfg                           = $this->outboundProfile();
        $issueCfg['token']['issue_enabled'] = true;
        
        $issuer = new JwtTokenIssuer(new ArrayKeyProvider($keys), new \Tozo\Security\Clock\SystemClock());
        $token  = $issuer->issue(Profile::fromConfig('i', $issueCfg, new ArrayKeyProvider($keys)));
        
        $verifyCfg                             = $this->inboundProfile();
        $verifyCfg['token']['allowed_tenants'] = ['t01'];
        
        $verifier = new JwtTokenVerifier(new ArrayKeyProvider($keys), new \Tozo\Security\Clock\SystemClock());
        
        $this->expectException(TenantMismatchException::class);
        $verifier->verify($token, Profile::fromConfig('v', $verifyCfg, new ArrayKeyProvider($keys)));
    }
    
    // ------------------------------------------------------------------ #3
    public function test_checker_ok_on_valid_config()
    {
        $result = (new ConfigChecker())->check($this->baseConfig()['tozo_security']);
        
        $this->assertTrue($result['ok'], implode('; ', $result['errors']));
        $this->assertSame(2, $result['profiles']);
    }
    
    public function test_checker_reports_disabled_feature_usage()
    {
        $config                          = $this->baseConfig()['tozo_security'];
        $config['features']['signature'] = false;
        
        $result = (new ConfigChecker())->check($config);
        
        $this->assertFalse($result['ok']);
        $this->assertNotEmpty(preg_grep('/uses feature \[signature\]/', $result['errors']));
    }
    
    /**
     * 认证 Profile 引用已关闭认证器时，配置体检必须在启动阶段失败。
     *
     * @return void 错误清单包含 authentication 功能门控冲突。
     */
    public function test_checker_reports_disabled_authentication_usage()
    {
        $config                               = $this->baseConfig()['tozo_security'];
        $config['features']['authentication'] = false;
        
        $result = (new ConfigChecker())->check($config);
        
        $this->assertFalse($result['ok']);
        $this->assertNotEmpty(preg_grep('/uses feature \[authentication\]/', $result['errors']));
    }
    
    public function test_checker_runtime_detects_missing_key()
    {
        $keys = new ArrayKeyProvider([]);
        
        $result = (new ConfigChecker())->check($this->baseConfig()['tozo_security'], $keys, null, true);
        
        $this->assertFalse($result['ok']);
        $this->assertNotEmpty(preg_grep('/not resolvable/', $result['errors']));
    }
    
    /**
     * 配置体检必须与 ServiceProvider 对共享 AuditSink 的冲突判定保持一致。
     *
     * @return void 出站 Profile 混用 cache/log 时报告配置错误。
     */
    public function test_checker_reports_conflicting_outbound_audit_drivers()
    {
        $config                                 = $this->baseConfig()['tozo_security'];
        $second                                 = $this->outboundProfile();
        $second['client_id']                    = 'product-center-2';
        $second['target_service']               = 'billing-api';
        $second['audit']                        = ['driver' => 'log'];
        $config['profiles']['billing_outbound'] = $second;
        
        $result = (new ConfigChecker())->check($config);
        
        $this->assertFalse($result['ok']);
        $this->assertNotEmpty(preg_grep('/audit driver/', $result['errors']));
    }
}
