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
use Tozo\Security\Contracts\ClockInterface;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Signature\HmacSha256Signer;
use Tozo\Security\Exceptions\ClockSkewException;
use Tozo\Security\Contracts\ReplayStoreInterface;
use Tozo\Security\Storage\LaravelCacheReplayStore;
use Tozo\Security\Exceptions\ReplayProtectionException;
use Tozo\Security\Exceptions\ReplayStoreUnavailableException;
use Tozo\Security\Exceptions\InvalidSignatureException;

class HmacSignerTest extends TestCase
{
    /**
     * 固定时钟的当前秒值。声明为 public 是为了让匿名 Clock 替身能直接读取，
     * 使用例可在断言之间推进时间以验证时间窗边界。
     * 用固定值而非 time()：签名过期、时钟偏差容忍这些边界必须可精确复现，
     * 依赖真实时间会让用例在窗口临界点间歇性失败。
     *
     * @var int
     */
    public $now = 1700000000;
    
    public function test_sign_then_verify_roundtrip_passes()
    {
        $signer  = $this->signer();
        $profile = $this->profile();
        
        $signed = $signer->sign($this->payload(), $profile);
        
        $this->assertSame(32, strlen((string)$signed->get('nonce')));
        $this->assertTrue($signer->verify($signed, $profile));
    }
    
    private function signer(ReplayStoreInterface $store = null)
    {
        $container = $this->makeContainer();
        
        return new HmacSha256Signer(
            $container->make(\Tozo\Security\Contracts\KeyProviderInterface::class),
            $store ?? new LaravelCacheReplayStore($container->make(\Illuminate\Contracts\Cache\Repository::class)),
            $this->fixedClock()
        );
    }
    
    private function fixedClock()
    {
        $holder = $this;
        
        return new class($holder) implements ClockInterface {
            /**
             * 持有测试用例实例，使时钟可读取用例内可变的当前时间，
             * 从而在同一个 Signer 上模拟时间推移（验证时间窗与重放）。
             *
             * @var object
             */
            private $holder;
            
            public function __construct($holder)
            {
                $this->holder = $holder;
            }
            
            public function now()
            {
                return $this->holder->now;
            }
        };
    }
    
    private function profile()
    {
        return \Tozo\Security\Profile::fromConfig(
            'svc_to_order',
            $this->outboundProfile(),
            new \Tozo\Security\Key\ArrayKeyProvider($this->defaultKeys())
        );
    }
    
    private function payload(string $body = '{"a":1}')
    {
        return new Payload([
            'method'         => 'POST',
            'path'           => '/api/orders',
            'query'          => ['b' => '2', 'a' => '1'],
            'content_type'   => 'application/json; charset=utf-8',
            'client_id'      => 'product-center',
            'target_service' => 'order-api',
            'body'           => $body,
        ]);
    }
    
    public function test_tampered_body_fails_signature()
    {
        $signer  = $this->signer();
        $profile = $this->profile();
        
        $signed = $signer->sign($this->payload(), $profile);
        $signed->set('body', '{"a":999}');
        
        $this->expectException(InvalidSignatureException::class);
        $signer->verify($signed, $profile);
    }
    
    public function test_key_id_must_match_profile_whitelist()
    {
        $signer  = $this->signer();
        $profile = $this->profile();
        
        $signed = $signer->sign($this->payload(), $profile);
        $signed->set('key_id', 'other-key');
        
        $this->expectException(InvalidSignatureException::class);
        $signer->verify($signed, $profile);
    }
    
    public function test_timestamp_outside_window_fails_closed()
    {
        $signer  = $this->signer();
        $profile = $this->profile();
        
        $signed = $signer->sign($this->payload(), $profile);
        
        // 超出 max_age + skew（300+60）窗口。
        $this->now += 361;
        
        $this->expectException(ClockSkewException::class);
        $signer->verify($signed, $profile);
    }
    
    public function test_replayed_nonce_is_rejected_after_first_use()
    {
        $signer  = $this->signer();
        $profile = $this->profile();
        
        $signed = $signer->sign($this->payload(), $profile);
        $this->assertTrue($signer->verify($signed, $profile));
        
        // 同一 Nonce 第二次验证必须拒绝。
        $this->expectException(ReplayProtectionException::class);
        $signer->verify($signed, $profile);
    }
    
    public function test_replay_store_failure_fails_closed()
    {
        $failing = new class implements ReplayStoreInterface {
            /**
             * 模拟存储不可用：任何登记尝试都抛底层异常，
             * 用于验证 Signer 必须 fail-closed 而不是降级为仅时间校验。
             *
             * @param string $key 防重放键（本替身不使用）。
             * @param int|null $ttl 本次保留时长（本替身不使用）。
             * @return bool 永不正常返回。
             */
            public function record(string $key, int $ttl = null)
            {
                throw new \RuntimeException('cache down');
            }
            
            /**
             * 模拟存储不可用：查询同样抛异常。
             *
             * @param string $key 防重放键（本替身不使用）。
             * @return bool 永不正常返回。
             */
            public function isReplayed(string $key)
            {
                throw new \RuntimeException('cache down');
            }
            
            /**
             * 空实现：本替身不保存实例级默认 TTL。
             *
             * @param int $ttl 默认保留时长（忽略）。
             * @return void
             */
            public function setTtl(int $ttl)
            {
            }
            
            /**
             * 返回替身标识，便于失败信息区分真实适配器。
             *
             * @return string 固定标识。
             */
            public function getDriver()
            {
                return 'failing';
            }
        };
        
        $signer  = $this->signer($failing);
        $profile = $this->profile();
        $signed  = $signer->sign($this->payload(), $profile);
        
        try {
            $signer->verify($signed, $profile);
            $this->fail('Expected ReplayStoreUnavailableException');
        } catch (ReplayStoreUnavailableException $e) {
            // fail-closed：存储故障不得降级为仅时间校验。
            $this->assertSame('replay_store_unavailable', $e->getReasonCode());
        }
    }
    
    public function test_replay_ttl_covers_full_acceptance_window()
    {
        // TTL 公式：max_age + 2*skew + margin = 300+120+5。
        $this->assertSame(425, $this->profile()->getReplayTtlSeconds());
    }
    
    public function test_canonical_request_is_deterministic()
    {
        $expected = implode("\n", [
            '1',
            'POST',
            '/api/orders',
            'a=1&b=2',
            'application/json',
            hash('sha256', '{"a":1}'),
            '1700000000',
            'nonce-1',
            'product-center',
            'order-api',
            'order-signing',
        ]);
        
        $actual = CanonicalRequest::build(
            'post',
            '/api/orders/',
            ['b' => '2', 'a' => '1'],
            'Application/JSON; charset=utf-8',
            '{"a":1}',
            1700000000,
            'nonce-1',
            'product-center',
            'order-api',
            'order-signing'
        );
        
        $this->assertSame($expected, $actual);
    }
}
