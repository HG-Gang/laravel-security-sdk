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
use Tozo\Security\Profile;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Authentication\AuthenticatorRouter;

/**
 * 验证多 Profile 场景按当前 Profile 的认证 driver 分派，而不是按注册顺序固定一种实现。
 */
class AuthenticatorRouterTest extends TestCase
{
    public function test_authentication_is_dispatched_by_profile_driver()
    {
        $jwtCalls  = 0;
        $hmacCalls = 0;
        $jwt       = $this->spyAuthenticator('jwt', $jwtCalls);
        $hmac      = $this->spyAuthenticator('hmac_bearer_sha256', $hmacCalls);
        $router    = new AuthenticatorRouter([$jwt, $hmac]);
        
        $jwtProfile = Profile::fromConfig(
            'jwt-inbound',
            $this->inboundProfile(),
            $this->keyProvider()
        );
        
        $hmacConfig                         = $this->inboundProfile();
        $hmacConfig['security_mode']        = 'token_only';
        $hmacConfig['signature']['enabled'] = false;
        $hmacConfig['authentication']       = [
            'driver' => 'hmac_bearer_sha256',
            'key_id' => self::HMAC_KEY,
        ];
        $hmacProfile                        = Profile::fromConfig('hmac-inbound', $hmacConfig, $this->keyProvider());
        
        $router->authenticate(new Payload([]), $jwtProfile);
        $router->authenticate(new Payload([]), $hmacProfile);
        
        $this->assertSame(1, $jwtCalls);
        $this->assertSame(1, $hmacCalls);
    }
    
    private function spyAuthenticator(string $driver, &$calls)
    {
        return new class($driver, $calls) implements AuthenticatorInterface {
            /**
             * 本替身声明的 driver 名，供 Router 建立分派映射。
             * 由构造参数注入而非硬编码，使同一个替身类能生成多个 driver 不同的实例——
             * 这是验证「Router 按 Profile 的 driver 精确分派」与
             * 「driver 重复时构造期即拒绝」两条行为的必要条件。
             *
             * @var string
             */
            private $driver;
            
            /**
             * 调用计数的外部引用。用于断言 Router 只调用了匹配 driver 的实现，
             * 而不是遍历全部认证器直到某个成功。
             *
             * @var int
             */
            private $calls;
            
            public function __construct(string $driver, &$calls)
            {
                $this->driver = $driver;
                $this->calls  =& $calls;
            }
            
            public function authenticate(Payload $payload, Profile $profile = null)
            {
                $this->calls++;
                return new Subject([
                    'sub'          => 'service:test',
                    'client_id'    => 'test',
                    'iss'          => 'test',
                    'aud'          => [],
                    'subject_type' => 'service',
                    'scope'        => [],
                ]);
            }
            
            public function getDriver()
            {
                return $this->driver;
            }
        };
    }
    
    private function keyProvider()
    {
        return new \Tozo\Security\Key\ArrayKeyProvider($this->defaultKeys());
    }
}
