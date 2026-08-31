<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ReplayStoreUnavailableException
 *
 * 文件功能：
 * - ReplayStore 连接故障、超时或原子能力不可确认时抛出
 *
 * 安全边界：
 * - fail-closed：存储不可用必须拒绝请求，禁止降级为仅时间校验
 */

namespace Tozo\Security\Exceptions;

class ReplayStoreUnavailableException extends SecurityException
{
	/**
	 * 构造防重放存储不可用异常。
	 *
	 * 使用范围：LaravelCacheReplayStore 存取故障时抛出；
	 * HmacSha256Signer / HmacBearerAuthenticator 将存储层 Throwable 包装后抛出（fail-closed）。
	 * 适用场景：缓存连接故障、超时或原子能力不可确认时拒绝请求，禁止降级为仅时间校验。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 503、前置异常与稳定原因码 replay_store_unavailable 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Replay store unavailable"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：503
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："replay_store_unavailable"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Replay store unavailable',
		int        $code = 503,
		\Throwable $previous = null,
		string     $reasonCode = 'replay_store_unavailable'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
