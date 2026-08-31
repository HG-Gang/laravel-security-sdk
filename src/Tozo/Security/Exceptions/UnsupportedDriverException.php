<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * UnsupportedDriverException
 *
 * 文件功能：
 * - 配置引用了白名单之外的 driver 时抛出
 */

namespace Tozo\Security\Exceptions;

class UnsupportedDriverException extends ConfigurationException
{
	/**
	 * 构造驱动不支持异常。
	 *
	 * 使用范围：Profile.validate 对白名单之外的 signature/encryption/token/key provider driver 抛出；
	 * HmacSha256Signer.sign 在 Profile driver 非 hmac_sha256 时抛出。
	 * 适用场景：配置引用未实现驱动时的 fail-fast 出口，禁止静默回退默认实现。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 500、前置异常与稳定原因码 unsupported_driver 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Unsupported driver"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：500
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："unsupported_driver"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Unsupported driver',
		int        $code = 500,
		\Throwable $previous = null,
		string     $reasonCode = 'unsupported_driver'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
