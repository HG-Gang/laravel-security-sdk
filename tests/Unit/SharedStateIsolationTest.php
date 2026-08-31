<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 共享实例状态隔离测试
 *
 * 文件功能：
 * - 固化「容器共享实例不得因可变状态产生跨调用方污染」这一要求
 * - 覆盖两处已确认可触发的污染点：ReplayStore 的 TTL 与 HttpClient 的默认 Profile
 *
 * 为什么必须固化：
 * - ReplayStore 按 singleton 注册且原实现用 setTtl()+record() 两步下发 TTL。
 *   两步之间若被其他 Profile 的调用插入（常驻进程并发或嵌套调用），
 *   长窗口 Profile 会拿到短 TTL —— 防重放窗口被静默缩短，且不会有任何报错。
 * - HttpClient 原按 singleton 注册且 setProfile() 修改实例状态。
 *   服务 B 切换 Profile 会覆盖服务 A 的目标，使 A 的请求被签往错误的目标服务。
 *
 * 安全边界：
 * - 用例只验证隔离性，不放宽任何既有校验
 */

namespace Tozo\Security\Tests\Unit;

use ReflectionProperty;
use Illuminate\Cache\ArrayStore;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Contracts\HttpClientInterface;
use Tozo\Security\Profile;
use Tozo\Security\Storage\LaravelCacheReplayStore;
use Illuminate\Cache\Repository as CacheRepository;

class SharedStateIsolationTest extends TestCase
{
    /**
     * record() 必须接受本次 TTL 参数，使"设定时长"与"原子写入"不可分割。
     */
    public function test_replay_store_accepts_per_call_ttl()
    {
        $store = new LaravelCacheReplayStore($this->cacheRepository());
        
        $this->assertTrue(
            method_exists($store, 'record'),
            'ReplayStore 必须提供 record 方法'
        );
        
        $method     = new \ReflectionMethod(LaravelCacheReplayStore::class, 'record');
        $parameters = $method->getParameters();
        
        $this->assertCount(2, $parameters, 'record() 必须接受 key 与 ttl 两个参数');
        $this->assertSame('ttl', $parameters[1]->getName());
        $this->assertTrue($parameters[1]->isOptional(), 'ttl 应可选以兼容既有调用方');
    }
    
    /**
     * 构造内存缓存仓储。
     *
     * @return CacheRepository 数组驱动的缓存实例。
     */
    private function cacheRepository()
    {
        return new CacheRepository(new ArrayStore());
    }
    
    /**
     * 传入的 TTL 必须真正生效，且不受实例上残留的 setTtl 值影响。
     */
    public function test_per_call_ttl_overrides_instance_state()
    {
        $cache = $this->cacheRepository();
        $store = new LaravelCacheReplayStore($cache);
        
        // 模拟并发污染：实例状态被另一个短窗口 Profile 设成 71。
        $store->setTtl(71);
        
        // 本次调用显式传入长窗口 425，必须以参数为准。
        $store->record('tozo_replay|a|nonce-a', 425);
        
        $ttlProperty = new ReflectionProperty(LaravelCacheReplayStore::class, 'ttl');
        $ttlProperty->setAccessible(true);
        
        // 参数不应回写实例状态——否则又变成共享可变状态。
        $this->assertSame(71, $ttlProperty->getValue($store), 'record() 的 ttl 参数不应污染实例状态');
        
        // 键确实已登记（第二次登记判定为重放）。
        $this->assertTrue($store->record('tozo_replay|a|nonce-a', 425));
    }
    
    /**
     * 非法 TTL 必须被拒绝，不能静默写入永不过期的记录。
     */
    public function test_non_positive_per_call_ttl_is_rejected()
    {
        $store = new LaravelCacheReplayStore($this->cacheRepository());
        
        $this->expectException(\Tozo\Security\Exceptions\ConfigurationException::class);
        $store->record('tozo_replay|a|nonce-b', 0);
    }
    
    /**
     * Signer 必须通过参数下发 TTL，而不是先 setTtl 再 record。
     *
     * 用一个记录调用顺序的替身验证：若实现仍走两步式，setTtl 会被调用。
     */
    public function test_signer_passes_ttl_as_argument_not_via_setter()
    {
        $keys = new ArrayKeyProvider([self::HMAC_KEY => str_repeat('a', 32)]);
        
        $spy = new class implements \Tozo\Security\Contracts\ReplayStoreInterface {
            /**
             * setTtl 被调用的次数，期望恒为 0。
     * 这是共享状态污染的探针：若 Signer 通过 setTtl 改变存储实例的 TTL，
     * 该实例被多个 Profile 共用时，后一个 Profile 的窗口会覆盖前一个的，
     * 使某些 Profile 的防重放窗口被静默改短。TTL 必须随 record 逐次传入而非预设。
             *
             * @var int
             */
            public $setTtlCalls = 0;
            
            /**
             * record 实际收到的 ttl 参数值，期望等于窗口公式 max_age + 2×skew + margin。
     * 断言它而非只断言「有值」的原因：TTL 必须覆盖完整接受窗口，
     * 短于窗口会在窗口尾部留出重放缝隙——那种缝隙只在特定时序下出现，
     * 靠功能测试几乎不可能撞到，只能靠这里的数值断言锁死。
     *
     * @var int|null
             *
             * @var int|null
             */
            public $recordedTtl = null;
            
            /**
             * 记录本次收到的 TTL 并报告首次登记成功。
             *
             * @param string $key 防重放键。
             * @param int|null $ttl 本次保留时长。
             * @return bool 恒为 false（首次登记）。
             */
            public function record(string $key, int $ttl = null)
            {
                $this->recordedTtl = $ttl;
                
                return false;
            }
            
            /**
             * 本替身不参与查询路径。
             *
             * @param string $key 防重放键。
             * @return bool 恒为 false。
             */
            public function isReplayed(string $key)
            {
                return false;
            }
            
            /**
             * 记录被调用次数，用于断言实现未走两步式下发。
             *
             * @param int $ttl 默认保留时长。
             * @return void
             */
            public function setTtl(int $ttl)
            {
                $this->setTtlCalls++;
            }
            
            /**
             * 返回替身标识。
             *
             * @return string 固定标识。
             */
            public function getDriver()
            {
                return 'spy';
            }
        };
        
        $signer = new \Tozo\Security\Signature\HmacSha256Signer(
            $keys,
            $spy,
            new \Tozo\Security\Clock\SystemClock()
        );
        
        $profile = Profile::fromConfig('sig', $this->signedOnlyProfile(), $keys);
        $signed  = $signer->sign($this->outboundPayload(), $profile);
        $signer->verify($signed, $profile);
        
        $this->assertSame(0, $spy->setTtlCalls, 'Signer 不应通过 setTtl 下发本次 TTL（共享状态会被并发覆盖）');
        $this->assertSame(425, $spy->recordedTtl, 'record() 应收到窗口公式结果 300+2×60+5=425');
    }
    
    /**
     * 构造仅签名的出站 Profile 配置（排除 Token 与加密以聚焦本测试关注点）。
     *
     * @return array Profile 配置数组。
     */
    private function signedOnlyProfile()
    {
        $config                            = $this->outboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['token']['attach_enabled'] = false;
        $config['encryption']['enabled']   = false;
        unset($config['response_integrity']);
        
        return $config;
    }
    
    /**
     * 构造出站签名所需的最小 Payload。
     *
     * @return \Tozo\Security\Payload 待签名负载。
     */
    private function outboundPayload()
    {
        return new \Tozo\Security\Payload([
            'method'         => 'POST',
            'path'           => '/api/orders',
            'query'          => '',
            'content_type'   => 'application/json',
            'client_id'      => 'product-center',
            'target_service' => 'order-api',
            'body'           => '{"sku":"A-1"}',
        ]);
    }
    
    /**
     * HttpClient 每次从容器解析必须是独立实例，避免 setProfile 跨服务污染。
     */
    public function test_http_client_resolves_to_isolated_instances()
    {
        $container = $this->makeContainer();
        
        $first  = $container->make(HttpClientInterface::class);
        $second = $container->make(HttpClientInterface::class);
        
        $this->assertNotSame(
            $first,
            $second,
            'HttpClient 持有可变的默认 Profile，不能注册为共享 singleton'
        );
    }
    
    /**
     * 一个消费方切换 Profile 不得影响另一个消费方的目标服务。
     */
    public function test_set_profile_does_not_leak_across_consumers()
    {
        $container = $this->makeContainer();
        
        $serviceA = $container->make(HttpClientInterface::class);
        $serviceB = $container->make(HttpClientInterface::class);
        
        $this->assertSame('svc_to_order', $serviceA->getProfile()->getName());
        
        $other = Profile::fromConfig(
            'other_target',
            $this->alternateOutboundProfile(),
            new ArrayKeyProvider($this->defaultKeys())
        );
        $serviceB->setProfile($other);
        
        $this->assertSame('other_target', $serviceB->getProfile()->getName());
        $this->assertSame(
            'svc_to_order',
            $serviceA->getProfile()->getName(),
            '服务 B 切换 Profile 污染了服务 A —— A 的请求会被签往错误的目标服务'
        );
    }
    
    /**
     * 构造一个目标不同的出站 Profile，用于验证跨消费方隔离。
     *
     * @return array Profile 配置数组。
     */
    private function alternateOutboundProfile()
    {
        $config                   = $this->signedOnlyProfile();
        $config['client_id']      = 'other-client';
        $config['target_service'] = 'other-api';
        
        return $config;
    }
    
    /**
     * withProfile() 必须返回新实例且不改动原实例，供多目标场景使用。
     */
    public function test_with_profile_returns_isolated_copy()
    {
        $container = $this->makeContainer();
        $client    = $container->make(HttpClientInterface::class);
        
        $other = Profile::fromConfig(
            'other_target',
            $this->alternateOutboundProfile(),
            new ArrayKeyProvider($this->defaultKeys())
        );
        
        $derived = $client->withProfile($other);
        
        $this->assertNotSame($client, $derived, 'withProfile 必须返回新实例');
        $this->assertSame('other_target', $derived->getProfile()->getName());
        $this->assertSame('svc_to_order', $client->getProfile()->getName(), '原实例不应被改动');
    }
}
