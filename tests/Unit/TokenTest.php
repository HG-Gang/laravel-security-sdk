<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use Firebase\JWT\JWT;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Token\JwtTokenIssuer;
use Tozo\Security\Token\JwtTokenVerifier;
use Tozo\Security\Contracts\ClockInterface;
use Tozo\Security\Exceptions\InvalidTokenException;
use Tozo\Security\Exceptions\TokenExpiredException;
use Tozo\Security\Exceptions\TokenRevokedException;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\ScopeMismatchException;
use Tozo\Security\Exceptions\ClientIdMismatchException;
use Tozo\Security\Contracts\TokenRevocationStoreInterface;
use Tozo\Security\Exceptions\RevocationStoreUnavailableException;
use Tozo\Security\Exceptions\IssuerMismatchException;

class TokenTest extends TestCase
{
    /**
     * 测试用 RSA 密钥对，static 以便整个用例类只生成一次。
     * 每次运行重新生成而非硬编码 PEM：硬编码的私钥一旦进入仓库，
     * 就成了一份永久可读的真实私钥，即使只用于测试也会被扫描工具报为泄露。
     * RSA 密钥对生成开销较大，因此在类级别复用而非逐用例生成。
     *
     * @var array{private:string,public:string}|null
     */
    private static $keyPair;
    
    public function test_issue_and_verify_roundtrip_returns_bound_subject()
    {
        $profile = $this->issuingProfile(['signing_key_id' => 'jwt-private-2026-08']);
        $token   = $this->issuer()->issue($profile);
        
        // Header 必须携带 kid。
        [$headerB64] = explode('.', $token);
        $header = json_decode(JWT::urlsafeB64Decode($headerB64), true);
        $this->assertSame('RS256', $header['alg']);
        $this->assertSame('jwt-private-2026-08', $header['kid']);
        
        $subject = $this->verifier()->verify($token, $this->verifyingProfile());
        
        $this->assertSame('service:product-center', $subject->getSub());
        $this->assertSame('service', $subject->getSubjectType());
        $this->assertSame('product-center', $subject->getClientId());
        $this->assertTrue($subject->hasScope('order.read'));
    }
    
    private function issuingProfile(array $tokenOverrides = [])
    {
        $config          = $this->outboundProfile();
        $config['token'] = array_merge($config['token'], [
            'issue_enabled'  => true,
            'attach_enabled' => false,
        ], $tokenOverrides);
        
        return \Tozo\Security\Profile::fromConfig('issuer', $config, new ArrayKeyProvider($this->keys()));
    }
    
    private function keys()
    {
        $keyPair = $this->keyPair();
        
        return array_merge($this->defaultKeys(), [
            'jwt-private-2026-08' => $keyPair['private'],
            'jwt-public-2026-08'  => $keyPair['public'],
        ]);
    }
    
    private function keyPair()
    {
        if (self::$keyPair !== null) {
            return self::$keyPair;
        }
        
        $dir           = dirname(__DIR__, 2) . '/tests/fixtures/';
        self::$keyPair = [
            'private' => (string)file_get_contents($dir . 'jwt-test-private.pem'),
            'public'  => (string)file_get_contents($dir . 'jwt-test-public.pem'),
        ];
        
        return self::$keyPair;
    }
    
    private function issuer(int $now = null)
    {
        return new JwtTokenIssuer(new ArrayKeyProvider($this->keys()), $this->clockAt($now ?? time()));
    }
    
    private function clockAt(int $timestamp)
    {
        return new class($timestamp) implements ClockInterface {
            /**
             * 固定的 Unix 秒级时间戳。让 iat/nbf/exp 判定完全可复现，
             * 避免用例因真实时间流逝而间歇性失败。
             *
             * @var int
             */
            private $ts;
            
            public function __construct(int $ts)
            {
                $this->ts = $ts;
            }
            
            public function now()
            {
                return $this->ts;
            }
        };
    }
    
    private function verifier(int $now = null, TokenRevocationStoreInterface $revocations = null)
    {
        return new JwtTokenVerifier(new ArrayKeyProvider($this->keys()), $this->clockAt($now ?? time()), $revocations);
    }
    
    private function verifyingProfile(array $tokenOverrides = [])
    {
        $config          = $this->inboundProfile();
        $config['token'] = array_merge($config['token'], $tokenOverrides);
        
        return \Tozo\Security\Profile::fromConfig('verifier', $config, new ArrayKeyProvider($this->keys()));
    }
    
    public function test_unknown_kid_is_rejected()
    {
        $profile = $this->issuingProfile([
            'signing_key_id' => 'jwt-private-2026-08',
            'driver'         => 'jwt_rs256',
        ]);
        
        // 用白名单之外的 kid 签发（模拟攻击者自选 kid）。
        $claims = [
            'iss'       => 'tozo-auth',
            'aud'       => ['order-api'],
            'sub'       => 'service:product-center',
            'client_id' => 'product-center',
            'iat'       => time(),
            'exp'       => 1700000900,
            'jti'       => 'x',
        ];
        $forged = JWT::encode($claims, $this->keyPair()['private'], 'RS256', 'attacker-kid');
        
        try {
            $this->verifier()->verify($forged, $this->verifyingProfile());
            $this->fail('Expected unknown_kid rejection');
        } catch (InvalidTokenException $e) {
            $this->assertSame('unknown_kid', $e->getReasonCode());
        }
    }
    
    public function test_algorithm_downgrade_hs256_token_is_rejected_against_rs256_profile()
    {
        // alg=none/HS256 混淆攻击：HS256 共享密钥伪造的 token 不得通过 RS256 Profile。
        $hsToken = JWT::encode(
            [
                'iss'       => 'tozo-auth',
                'aud'       => ['order-api'],
                'sub'       => 'service:product-center',
                'client_id' => 'product-center',
                'iat'       => time(),
                'exp'       => 1700000900,
            ],
            str_repeat('a', 32),
            'HS256'
        );
        
        try {
            $this->verifier()->verify($hsToken, $this->verifyingProfile());
            $this->fail('Expected algorithm downgrade rejection');
        } catch (InvalidTokenException $e) {
            $this->addToAssertionCount(1);
        }
    }
    
    public function test_expired_token_is_rejected()
    {
        // firebase 内部使用真实 time()；将签发时钟置于过去使 exp 相对当前时间已过期。
        $token = $this->issuer(time() - 2000)->issue($this->issuingProfile());
        
        $this->expectException(TokenExpiredException::class);
        $this->verifier()->verify($token, $this->verifyingProfile());
    }
    
    public function test_issuer_mismatch_is_rejected()
    {
        $token = $this->issuer()->issue($this->issuingProfile());
        
        $this->expectException(IssuerMismatchException::class);
        $this->verifier()->verify($token, $this->verifyingProfile(['issuer' => 'other-auth']));
    }
    
    public function test_client_binding_mismatch_is_rejected()
    {
        $token = $this->issuer()->issue($this->issuingProfile());
        
        $this->expectException(ClientIdMismatchException::class);
        $this->verifier()->verify($token, $this->verifyingProfile(['expected_client_id' => 'someone-else']));
    }
    
    public function test_scope_exceeding_profile_allowance_is_rejected()
    {
        $token = $this->issuer()->issue($this->issuingProfile());
        
        // 验证端白名单收窄到 order.read；token 携带的 order.write 超出即拒绝。
        $config                            = $this->inboundProfile();
        $config['scope']['allowed_scopes'] = ['order.read'];
        $profile                           = \Tozo\Security\Profile::fromConfig('v', $config, new ArrayKeyProvider($this->keys()));
        
        $this->expectException(ScopeMismatchException::class);
        $this->verifier()->verify($token, $profile);
    }
    
    public function test_revoked_jti_is_rejected()
    {
        $token = $this->issuer()->issue($this->issuingProfile());
        
        // 提取 jti 并吊销。
        [, $payloadB64] = explode('.', $token);
        $claims = json_decode(JWT::urlsafeB64Decode($payloadB64), true);
        
        $store = new \Tozo\Security\Storage\LaravelCacheTokenRevocationStore(
            new \Illuminate\Cache\Repository(new \Illuminate\Cache\ArrayStore())
        );
        $store->revoke($claims['jti'], 600);
        
        // 吊销检查仅在 Profile 显式启用时执行。
        $config                     = $this->inboundProfile();
        $config['token_revocation'] = ['enabled' => true, 'driver' => 'cache'];
        $profile                    = \Tozo\Security\Profile::fromConfig('v', $config, new ArrayKeyProvider($this->keys()));
        
        $this->expectException(TokenRevokedException::class);
        $this->verifier(time(), $store)->verify($token, $profile);
    }
    
    public function test_revocation_store_failure_fails_closed()
    {
        $token = $this->issuer()->issue($this->issuingProfile());
        
        $failing = new class implements TokenRevocationStoreInterface {
            public function revoke(string $tokenId, int $ttl = 86400)
            {
            }
            
            public function isRevoked(string $tokenId)
            {
                throw new \RuntimeException('redis down');
            }
            
            public function setTtl(int $ttl)
            {
            }
            
            public function getDriver()
            {
                return 'failing';
            }
        };
        
        $config                     = $this->inboundProfile();
        $config['token_revocation'] = ['enabled' => true, 'driver' => 'cache'];
        $profile                    = \Tozo\Security\Profile::fromConfig('v', $config, new ArrayKeyProvider($this->keys()));
        
        try {
            $this->verifier(time(), $failing)->verify($token, $profile);
            $this->fail('Expected fail-closed revocation');
        } catch (RevocationStoreUnavailableException $e) {
            $this->assertSame('revocation_store_unavailable', $e->getReasonCode());
        }
    }
    
    public function test_verifier_disabled_in_profile_fails_configuration()
    {
        $token = $this->issuer()->issue($this->issuingProfile());
        
        // signed_request 模式下 verify_enabled=false 是合法配置；此时调用验证器应被前置条件拒绝。
        $config                            = $this->inboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['token']['verify_enabled'] = false;
        $profile                           = \Tozo\Security\Profile::fromConfig('v', $config, new ArrayKeyProvider($this->keys()));
        
        $this->expectException(ConfigurationException::class);
        $this->verifier()->verify($token, $profile);
    }
}
