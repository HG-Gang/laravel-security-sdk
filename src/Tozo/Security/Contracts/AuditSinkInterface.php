<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * AuditSinkInterface
 *
 * 文件功能：
 * - 定义安全审计存储契约
 * - 支持记录安全事件（签名、认证、加密等），支持脱敏与关联 ID
 */

namespace Tozo\Security\Contracts;

interface AuditSinkInterface
{
	/**
	 * 记录脱敏审计事件契约。
	 *
	 * 使用范围：HttpClient.audit 与入站中间件安全事件落盘。
	 * 适用场景：出站调用/入站拒绝留痕，供风控与排障检索。
	 *
	 * 函数逻辑：
	 * 1. 实现方先脱敏（剔除密钥/Token/Body 等敏感键）再持久化。
	 * 2. 写入失败必须抛异常（fail-closed），禁止静默丢弃。
	 *
	 * @param array $event 审计事件｜动作/目标/状态/client/profile/timestamp 等。示例：["id"=>"ab12","action"=>"POST","status"=>200]
	 * @return void 成功无返回值。
	 * @throws \RuntimeException 存储不可用时抛出。
	 */
	public function log(array $event);
	
	/**
	 * 设置审计保留时长契约（秒）。
	 *
	 * 使用范围：容器装配或运维调整保留窗口。
	 * 适用场景：容量与合规保留期平衡。
	 *
	 * 函数逻辑：
	 * 1. 实现方保存 ttl；非法值应拒绝。
	 *
	 * @param int $ttl 存活时长(秒)｜正整数。示例：86400
	 * @return void 无返回值。
	 */
	public function setTtl(int $ttl);
	
	/**
	 * 返回审计 driver 名称契约。
	 *
	 * 使用范围：日志标注与运行期后端可观测。
	 * 适用场景：确认当前为 laravel_cache/laravel_log 实现。
	 *
	 * 函数逻辑：
	 * 1. 返回实现方 driver 标识。
	 *
	 * @return string driver 标识。示例："laravel_cache"
	 */
	public function getDriver();
}
