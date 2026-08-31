<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenFormatException
 *
 * 文件功能：
 * - Token 结构不满足 JWT 紧凑序列化格式时抛出
 */

namespace Tozo\Security\Exceptions;

class TokenFormatException extends InvalidTokenException
{
	/**
	 * 构造 Token 格式非法异常。
	 *
	 * 使用范围：JwtTokenVerifier.decode 中捕获 UnexpectedValueException/DomainException（结构不满足
	 * JWT 紧凑序列化）时抛出；JwtAuthenticator.authenticate 对缺失/空字符串 Token 抛出。
	 * 适用场景：Token 结构层面不可解析的判定出口，与签名/语义层失败相区分。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 invalid_token_format 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Malformed token"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：401
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："invalid_token_format"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Malformed token',
		int        $code = 401,
		\Throwable $previous = null,
		string     $reasonCode = 'invalid_token_format'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
