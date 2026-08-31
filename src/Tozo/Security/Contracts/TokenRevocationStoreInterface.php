<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenRevocationStoreInterface
 *
 * 文件功能：
 * - 定义 Token 吊销状态存储契约（与 ReplayStore 是两个独立契约，禁止混用）
 */

namespace Tozo\Security\Contracts;

interface TokenRevocationStoreInterface
{
	/**
	 * 写入吊销记录契约。
	 *
	 * 使用范围：签发/账号系统的登出、风控封禁流程调用。
	 * 适用场景：用户退出后按 jti 立即失效其未过期 Access Token。
	 *
	 * 函数逻辑：
	 * 1. 实现方以 tokenId 为键写入标记，TTL 覆盖 exp+clock_skew 窗口；幂等可重复调用。
	 *
	 * @param string $tokenId Token 唯一标识｜jti claim 值。示例："9f8b7c6d5e4f3210"
	 * @param int $ttl 存活时长(秒)｜保留时长。示例：86400
	 * @return void 无返回值。
	 */
	public function revoke(string $tokenId, int $ttl = 86400);
	
	/**
	 * 查询吊销状态契约。
	 *
	 * 使用范围：JwtTokenVerifier.assertNotRevoked 在 claims 绑定通过后调用。
	 * 适用场景：已吊销 jti 的 Token 在剩余有效期内也必须被拒绝。
	 *
	 * 函数逻辑：
	 * 1. 实现方查询标记是否存在；故障必须抛异常 fail-closed，防止已吊销 Token 逃逸。
	 *
	 * @param string $tokenId Token 唯一标识｜jti。示例："9f8b7c6d5e4f3210"
	 * @return bool true=已吊销。示例：true
	 * @throws \RuntimeException 存储不可用（由适配器包装为专用异常）。
	 */
	public function isRevoked(string $tokenId);
	
	/**
	 * 设置默认保留时长契约（秒）。
	 *
	 * 使用范围：容器装配或运维调整保留窗口时调用。
	 * 适用场景：记录需覆盖最长 Token 有效期+偏差。
	 *
	 * 函数逻辑：
	 * 1. 实现方保存 ttl；非法值应拒绝。
	 *
	 * @param int $ttl 存活时长(秒)｜正整数。示例：86400
	 * @return void 无返回值。
	 */
	public function setTtl(int $ttl);
	
	/**
	 * 返回吊销 driver 名称契约。
	 *
	 * 使用范围：日志标注与运行期后端可观测。
	 * 适用场景：确认当前为 laravel_cache/redis 等实现。
	 *
	 * 函数逻辑：
	 * 1. 返回实现方 driver 标识。
	 *
	 * @return string driver 标识。示例："laravel_cache"
	 */
	public function getDriver();
}
