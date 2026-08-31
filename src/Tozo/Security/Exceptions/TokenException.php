<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenException
 *
 * 文件功能：
 * - Token 签发/验证模块异常基类
 */

namespace Tozo\Security\Exceptions;

class TokenException extends SecurityException
{
	/**
	 * 构造 Token 处理异常基类实例。
	 *
	 * 使用范围：Token 签发/验证模块异常基类，无直接抛出点；
	 * 由 TokenIssuanceException / TokenVerificationException 继承承载实际抛出。
	 * 适用场景：Token 生命周期相关故障的公共语义出口。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 invalid_token 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Token processing failed"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：401
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："invalid_token"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Token processing failed',
		int        $code = 401,
		\Throwable $previous = null,
		string     $reasonCode = 'invalid_token'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
