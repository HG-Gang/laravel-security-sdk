<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * LaravelCacheReplayStore
 *
 * 文件功能：
 * - ReplayStoreInterface 的 Laravel Cache 适配器（Redis/共享缓存）
 * - 使用 Cache::add() 等价于 SET NX EX 的原子“只写一次”语义
 *
 * 安全边界：
 * - fail-closed：存储故障、超时抛出 ReplayStoreUnavailableException，禁止降级为仅时间校验
 * - TTL 由 Signer 按 max_age + 2*clock_skew + margin 设置，覆盖完整接受窗口
 */

namespace Tozo\Security\Storage;

use Throwable;
use Tozo\Security\Contracts\ReplayStoreInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Tozo\Security\Exceptions\ReplayStoreUnavailableException;

class LaravelCacheReplayStore implements ReplayStoreInterface
{
	/**
	 * 缓存仓储。必须是所有服务实例共享的后端（Redis 等）：
	 * 进程内数组或单机文件无法提供跨实例的"只写一次"语义，多实例部署会漏放重放请求。
	 *
	 * @var CacheRepository
	 */
	private $cache;
	
	/**
	 * Nonce 保留秒数。默认 425 = 300 + 2×60 + 5（对应 SDK 默认时间窗）；
	 * 实际值由 Signer 在 record() 前按 Profile 的窗口公式覆盖，
	 * TTL 必须覆盖完整接受窗口，否则合法重试可能被误判或重放窗口出现空隙。
	 *
	 * @var int
	 */
	private $ttl = 425;
	
	/**
	 * 构造防重放存储适配器并注入缓存仓储。
	 *
	 * 使用范围：ServiceProvider::registerStorageAdapters 注册 ReplayStoreInterface 单例时实例化。
	 * 适用场景：多实例部署共享 Redis 后端，为 Nonce 原子登记提供存储通道。
	 *
	 * 函数逻辑：
	 * 1. 接收 CacheRepository 实例赋给内部属性，供 record/isReplayed 共用。
	 *
	 * @param CacheRepository $cache 缓存仓储｜Laravel Cache 契约实现（Redis 等共享后端）。示例：$app->make(CacheRepository::class)
	 * @return void 无返回值。
	 */
	public function __construct(CacheRepository $cache)
	{
		$this->cache = $cache;
	}
	
	/**
	 * 原子登记防重放键。
	 *
	 * 使用范围：HmacSha256Signer.verify 在签名常量时间比较通过后调用。
	 * 适用场景：多实例部署下同一请求被网关重发时，第二实例在此被拒绝。
	 *
	 * 函数逻辑：
	 * 1. setTtl 下发窗口公式时长。
	 * 2. Cache::add 原子写入（≙ SET NX EX）；已存在返回 false 判定为重放。
	 *
	 * @param string $key 防重放键｜client|nonce 组合键。示例："tozo_replay|pc|5f1c..."
	 * @param int|null $ttl 本次保留时长(秒)｜由 Signer 按窗口公式传入；null 回退实例默认值。示例：425
	 * @return bool true=已存在（重放）；false=首次登记成功。示例：true
	 * @throws ReplayStoreUnavailableException 存储故障 fail-closed。
	 * @throws ConfigurationException 显式传入的 ttl 非正数。
	 */
	public function record(string $key, int $ttl = null)
	{
		if ($ttl !== null && $ttl <= 0) {
			throw new ConfigurationException('Replay TTL must be positive');
		}
		
		// 本次 TTL 优先取参数：实例属性是共享状态，并发下可能已被其他 Profile 覆盖。
		$effectiveTtl = $ttl ?? $this->ttl;
		
		try {
			// add()：key 不存在时写入并返回 true；已存在返回 false（重放）。
			$added = $this->cache->add($key, true, $effectiveTtl);
			
			return $added !== true;
		} catch (Throwable $e) {
			throw new ReplayStoreUnavailableException('Replay store unavailable', 503, $e);
		}
	}
	
	/**
	 * 查询防重放键是否已登记。
	 *
	 * 使用范围：辅助诊断与测试断言的只读通道；verify 主链路经 record() 判定重放。
	 * 适用场景：排查疑似重放告警时确认某 Nonce 是否已被消费。
	 *
	 * 函数逻辑：
	 * 1. Cache::has 检查键存在性并返回布尔结果。
	 * 2. 存储 Throwable 包装为 ReplayStoreUnavailableException（fail-closed）。
	 *
	 * @param string $key 防重放键｜client|nonce 组合键。示例："tozo_replay|pc|5f1c..."
	 * @return bool true=键已存在（该 Nonce 已被使用）；false=未登记。示例：true
	 * @throws ReplayStoreUnavailableException 存储故障 fail-closed。
	 */
	public function isReplayed(string $key)
	{
		try {
			return $this->cache->has($key) === true;
		} catch (Throwable $e) {
			throw new ReplayStoreUnavailableException('Replay store unavailable', 503, $e);
		}
	}
	
	/**
	 * 设置 Nonce 保留时长（秒）。
	 *
	 * 使用范围：HmacSha256Signer.verify 在 record() 之前按窗口公式下发。
	 * 适用场景：TTL 需覆盖 max_age + 2×clock_skew + margin 的完整接受窗口。
	 *
	 * 函数逻辑：
	 * 1. 校验 ttl 必须为正，否则抛 ConfigurationException。
	 * 2. 赋值内部属性，供后续 Cache::add 作为过期时间使用。
	 *
	 * @param int $ttl 保留秒数｜Signer 窗口公式计算结果。示例：425
	 * @return void 无返回值。
	 * @throws ConfigurationException ttl 非正数时拒绝配置。
	 */
	public function setTtl(int $ttl)
	{
		if ($ttl <= 0) {
			throw new ConfigurationException('Replay TTL must be positive');
		}
		
		$this->ttl = $ttl;
	}
	
	/**
	 * 返回防重放 driver 标识。
	 *
	 * 使用范围：运行期诊断与日志标注实际后端类型。
	 * 适用场景：运维确认当前防重放后端为 Laravel Cache 实现。
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
