<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * EncryptionException
 *
 * 文件功能：
 * - 加密方向异常基类（加密执行失败）
 */

namespace Tozo\Security\Exceptions;

class EncryptionException extends SecurityException
{
	/**
	 * 构造加密执行失败异常。
	 *
	 * 使用范围：AesGcmCipher.encryptString 中 openssl 底层加密返回 false 时抛出；
	 * PayloadCipherInterface 以 @param string $message 异常消息｜面向日志，禁止敏感值。示例："Encryption failed"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：500
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："encryption_failed"
	 * @return void 无返回值。
	 * @throws 声明该契约。
	 * 适用场景：加密方向底层故障（非密文内容问题）的统一出口。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 500、前置异常与稳定原因码 encryption_failed 传给父类。
	 *
	 */
	public function __construct(
		string     $message = 'Encryption failed',
		int        $code = 500,
		\Throwable $previous = null,
		string     $reasonCode = 'encryption_failed'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
