<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ResponseIntegrityException
 *
 * 文件功能：
 * - 响应完整性验证失败（未受保护响应、签名不符、解密失败）时抛出
 *
 * 安全边界：
 * - 客户端必须先验证响应完整性再把数据交给业务层
 */

namespace Tozo\Security\Exceptions;

class ResponseIntegrityException extends SecurityException
{
	/**
	 * 构造响应完整性验证失败异常。
	 *
	 * 使用范围：ResponseIntegrityChecker.decryptEncryptedResponse 对非法信封/解密失败、
	 * verifySignedResponse 对签名头缺失或签名比对不一致时抛出。
	 * 适用场景：客户端先验证响应完整性再把数据交给业务层的强制闸口。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 502、前置异常与稳定原因码 response_integrity_failed 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Response integrity verification failed"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：502
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："response_integrity_failed"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Response integrity verification failed',
		int        $code = 502,
		\Throwable $previous = null,
		string     $reasonCode = 'response_integrity_failed'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
