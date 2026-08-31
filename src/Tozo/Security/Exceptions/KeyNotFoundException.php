<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * KeyNotFoundException
 *
 * 文件功能：
 * - KeyProvider 按 key_id 查找密钥失败时抛出
 *
 * 安全边界：
 * - 异常消息只能包含 key_id 与来源描述，不得包含密钥内容
 */

namespace Tozo\Security\Exceptions;

class KeyNotFoundException extends SecurityException
{
	/**
	 * 构造密钥未找到异常。
	 *
	 * 使用范围：ArrayKeyProvider / EnvKeyProvider / FileKeyProvider 按 key_id 查找失败时抛出；
	 * KeyUsage 状态校验对非 active 密钥、DummyKeyProvider 结构校验阶段一律抛出。
	 * 适用场景：密钥解析链路 fail-fast 出口，禁止回退到默认密钥或空字符串密钥。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 500、前置异常与稳定原因码 unknown_key_id 传给父类。
	 *
	 * @param string $message 异常消息｜仅含 key_id 与来源描述，禁止密钥内容。示例："Key not found"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：500
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："unknown_key_id"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Key not found',
		int        $code = 500,
		\Throwable $previous = null,
		string     $reasonCode = 'unknown_key_id'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
