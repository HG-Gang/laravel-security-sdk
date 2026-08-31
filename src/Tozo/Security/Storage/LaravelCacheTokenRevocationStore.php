<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * LaravelCacheTokenRevocationStore
 *
 * 文件功能：
 * - TokenRevocationStoreInterface 的 Laravel Cache 适配器
 * - 吊销记录以 jti 为键，TTL 覆盖 exp + clock_skew 窗口
 *
 * 安全边界：
 * - fail-closed：查询故障、超时抛出 RevocationStoreUnavailableException，防止已吊销 Token 逃逸
 * - 与 ReplayStore 是两个独立契约，禁止混用同一条记录语义
 */

namespace Tozo\Security\Storage;

use Throwable;
use Tozo\Security\Contracts\TokenRevocationStoreInterface;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Tozo\Security\Exceptions\RevocationStoreUnavailableException;

class LaravelCacheTokenRevocationStore implements TokenRevocationStoreInterface
{
    /**
     * 缓存仓储。需为共享后端，使任一实例写入的吊销记录对全部实例立即可见；
     * 查询故障时上层 fail-closed 拒绝 Token，防止已吊销 Token 逃逸。
     *
     * @var CacheRepository
     */
    private $cache;
    
    /**
     * 默认吊销记录保留秒数（86400 = 24 小时）。
     * 仅在 revoke() 未传入正数 ttl 时作为回退值；
     * 调用方应按 exp + clock_skew 传入精确时长，避免记录早于 Token 过期被清除。
     *
     * @var int
     */
    private $ttl = 86400;
    
    /**
     * 构造吊销存储适配器并注入缓存仓储。
     *
     * 使用范围：ServiceProvider::registerStorageAdapters 注册 TokenRevocationStoreInterface 单例时实例化。
     * 适用场景：多实例部署共享 Redis 后端，为 jti 吊销记录提供读写通道。
     *
     * 函数逻辑：
     * 1. 接收 CacheRepository 实例赋给内部属性，供 revoke/isRevoked 共用。
     *
     * @param CacheRepository $cache 缓存仓储｜Laravel Cache 契约实现（Redis 等共享后端）。示例：$app->make(CacheRepository::class)
     * @return void 无返回值。
     */
    public function __construct(CacheRepository $cache)
    {
        $this->cache = $cache;
    }
    
    /**
     * 写入 jti 吊销记录。
     *
     * 使用范围：实现 TokenRevocationStoreInterface 契约；JwtTokenVerifier 经 isRevoked 消费同一批记录。
     * 适用场景：Token 泄露或用户登出后，已签发 JWT 需在 exp 前即时失效。
     *
     * 函数逻辑：
     * 1. 组合键 tozo_revocation|{jti} 定位记录。
     * 2. Cache::add 幂等写入（重复吊销无副作用）；入参 ttl 非正时回退默认保留期。
     * 3. 存储 Throwable 包装为 RevocationStoreUnavailableException（fail-closed）。
     *
     * @param string $tokenId Token ID｜JWT 的 jti 声明值。示例："9f8b7c6d5e4a3f21"
     * @param int $ttl 记录保留秒数｜需覆盖 exp + clock_skew 窗口；非正回退默认 86400。示例：90000
     * @return void 无返回值。
     * @throws RevocationStoreUnavailableException 存储故障 fail-closed。
     */
    public function revoke(string $tokenId, int $ttl = 86400)
    {
        try {
            // add() 保证幂等：重复吊销同一 jti 不产生副作用。
            $this->cache->add('tozo_revocation|' . $tokenId, true, $ttl > 0 ? $ttl : $this->ttl);
        } catch (Throwable $e) {
            throw new RevocationStoreUnavailableException('Revocation store unavailable', 503, $e);
        }
    }
    
    /**
     * 查询 jti 是否已吊销。
     *
     * 使用范围：JwtTokenVerifier.verify 在签名/时效校验通过后查询吊销状态。
     * 适用场景：已吊销 Token 即使签名合法也在验证阶段被拒绝（fail-closed）。
     *
     * 函数逻辑：
     * 1. 组合键 tozo_revocation|{jti} 执行 Cache::has 存在性检查。
     * 2. 存储 Throwable 包装为 RevocationStoreUnavailableException，防止已吊销 Token 逃逸。
     *
     * @param string $tokenId Token ID｜JWT 的 jti 声明值。示例："9f8b7c6d5e4a3f21"
     * @return bool true=已吊销（拒绝该 Token）；false=无吊销记录。示例：true
     * @throws RevocationStoreUnavailableException 存储故障 fail-closed。
     */
    public function isRevoked(string $tokenId)
    {
        try {
            return $this->cache->has('tozo_revocation|' . $tokenId) === true;
        } catch (Throwable $e) {
            throw new RevocationStoreUnavailableException('Revocation store unavailable', 503, $e);
        }
    }
    
    /**
     * 设置吊销记录默认保留时长（秒）。
     *
     * 使用范围：ServiceProvider 装配或调用方按 Token 最大有效期下发。
     * 适用场景：记录需覆盖 exp + clock_skew 窗口，避免提前清除导致已吊销 Token 误判有效。
     *
     * 函数逻辑：
     * 1. 校验 ttl 必须为正，否则抛 ConfigurationException。
     * 2. 赋值内部属性，作为 revoke() 入参 ttl 非正时的回退值。
     *
     * @param int $ttl 默认保留秒数｜不小于最长 Token 剩余寿命。示例：86400
     * @return void 无返回值。
     * @throws ConfigurationException ttl 非正数时拒绝配置。
     */
    public function setTtl(int $ttl)
    {
        if ($ttl <= 0) {
            throw new \Tozo\Security\Exceptions\ConfigurationException('Revocation TTL must be positive');
        }
        
        $this->ttl = $ttl;
    }
    
    /**
     * 返回吊销 driver 标识。
     *
     * 使用范围：运行期诊断与日志标注实际后端类型。
     * 适用场景：运维确认当前吊销后端为 Laravel Cache 实现。
     *
     * 函数逻辑：
     * 1. 直接返回固定字符串 'laravel_cache'。
     *
     * @return string driver 标识｜固定值。示例："laravel_cache"
     */
    public function getDriver()
    {
        return 'laravel_cache';
    }
}
