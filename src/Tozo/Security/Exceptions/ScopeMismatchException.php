<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ScopeMismatchException
 *
 * 文件功能：
 * - Token 携带的 Scope 超出 Profile allowed_scopes 白名单时抛出
 */

namespace Tozo\Security\Exceptions;

class ScopeMismatchException extends ScopeException
{
	/**
	 * 构造 Scope 超出白名单异常。
	 *
	 * 使用范围：JwtTokenVerifier.assertClaimsBoundToProfile 中 Token 携带 scope
	 * 超出 Profile allowed_scopes 白名单时抛出。
	 * 适用场景：Token 自行声明越权 scope 的判定出口，与授权判定（ScopeDenied）相区分。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 403、前置异常与稳定原因码 scope_denied 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Requested scope exceeds profile allowance"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：403
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："scope_denied"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Requested scope exceeds profile allowance',
		int        $code = 403,
		\Throwable $previous = null,
		string     $reasonCode = 'scope_denied'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
