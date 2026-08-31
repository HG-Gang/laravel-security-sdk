<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenExpiredException
 *
 * 文件功能：
 * - Token exp 已过期时抛出（含 clock skew 判定）
 */

namespace Tozo\Security\Exceptions;

class TokenExpiredException extends AuthenticationException
{
	/**
	 * 构造 Token 已过期异常。
	 *
	 * 使用范围：JwtTokenVerifier.decode 中捕获 firebase ExpiredException 后转换抛出（含 leeway 判定）。
	 * 适用场景：exp 已过期的 Token 判定出口，客户端应走刷新流程而非重试原 Token。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 token_expired 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Token has expired"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：401
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："token_expired"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Token has expired',
		int        $code = 401,
		\Throwable $previous = null,
		string     $reasonCode = 'token_expired'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
