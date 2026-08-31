<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenVerificationException
 *
 * 文件功能：
 * - Token 验证前置条件不满足（功能关闭、kid 白名单缺失等）时抛出
 *
 * 安全边界：
 * - 底层密码学失败应保留原始类型（Expired/Revoked 等），不得统一包装吞掉语义
 */

namespace Tozo\Security\Exceptions;

class TokenVerificationException extends TokenException
{
	/**
	 * 构造 Token 验证失败异常。
	 *
	 * 使用范围：TokenVerifierInterface 契约引入的验证失败包装类型（当前实现中验证前置条件
	 * 以 ConfigurationException 表达，底层密码学失败保留 Expired/Revoked 等原始类型）。
	 * 适用场景：需要以单一类型归并 Token 验证链路失败时的语义出口，不得吞掉子类语义。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 token_verification_failed 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Token verification failed"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：401
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："token_verification_failed"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Token verification failed',
		int        $code = 401,
		\Throwable $previous = null,
		string     $reasonCode = 'token_verification_failed'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
