<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * InvalidTokenException
 *
 * 文件功能：
 * - Token 格式错误、解码失败或签名验证失败时抛出
 */

namespace Tozo\Security\Exceptions;

class InvalidTokenException extends AuthenticationException
{
	/**
	 * 构造无效 Token 异常。
	 *
	 * 使用范围：JwtTokenVerifier.decode 中签名失败/nbf 未生效/未知 kid 时抛出；
	 * assertClaimsBoundToProfile 对 sub 格式非法、assertNotRevoked 对启用吊销时 jti 缺失抛出。
	 * 适用场景：Token 内容本身不可信（非过期/非吊销）的统一判定出口。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 invalid_token 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Invalid token"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：401
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："invalid_token"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Invalid token',
		int        $code = 401,
		\Throwable $previous = null,
		string     $reasonCode = 'invalid_token'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
