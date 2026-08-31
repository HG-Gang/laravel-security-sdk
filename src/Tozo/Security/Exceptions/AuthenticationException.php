<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * AuthenticationException
 *
 * 文件功能：
 * - 认证相关异常基类（Token 验证、身份绑定失败等）
 *
 * 安全边界：
 * - 所有认证相关异常必须继承此异常或其子类
 * - 异常消息不得包含密钥、完整 Token 或预期值
 */

namespace Tozo\Security\Exceptions;

class AuthenticationException extends SecurityException
{
	/**
	 * 构造认证失败异常。
	 *
	 * 使用范围：HmacBearerAuthenticator.authenticate / JwtAuthenticator.authenticate 缺 Profile 或头部非法时抛出；
	 * InboundAuthenticatorMiddleware.resolveProfile 对无候选/多候选/未知绑定抛出（reason=invalid_request）。
	 * 适用场景：认证相关异常基类，Token 验证与身份绑定失败的公共语义出口。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 invalid_authentication 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Authentication failed"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：401
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："invalid_authentication"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Authentication failed',
		int        $code = 401,
		\Throwable $previous = null,
		string     $reasonCode = 'invalid_authentication'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
