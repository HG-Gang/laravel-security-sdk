<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * AudienceMismatchException
 *
 * 文件功能：
 * - Token aud 与 Profile 允许的 audience 无交集时抛出
 */

namespace Tozo\Security\Exceptions;

class AudienceMismatchException extends AuthenticationException
{
	/**
	 * 构造 Audience 不匹配异常。
	 *
	 * 使用范围：JwtTokenVerifier.assertClaimsBoundToProfile 中 Token aud 与 Profile 允许 audience 无交集时抛出。
	 * 适用场景：多受众服务间隔离，拒绝将签给其他服务的 Token 投入本 Profile 使用。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 audience_mismatch 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Audience mismatch"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：401
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："audience_mismatch"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Audience mismatch',
		int        $code = 401,
		\Throwable $previous = null,
		string     $reasonCode = 'audience_mismatch'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
