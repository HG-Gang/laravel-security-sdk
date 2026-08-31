<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ConfigurationException
 *
 * 文件功能：
 * - 配置结构非法、安全必填项缺失、显式 null 等配置错误时抛出
 *
 * 安全边界：
 * - 结构校验在启动/config:cache 阶段失败，不读取生产密钥、不连接外部依赖
 */

namespace Tozo\Security\Exceptions;

class ConfigurationException extends SecurityException
{
	/**
	 * 构造配置非法异常。
	 *
	 * 使用范围：Profile.validate / ServiceProvider 注册阶段对结构非法、必填项缺失、显式 null 抛出；
	 * AesGcmCipher / ResponseIntegrityChecker / TozoHttpClient / 各 Store 对运行期配置矛盾抛出。
	 * 适用场景：安全必填项缺失或取值不合法的 fail-fast 出口，启动 config:cache 阶段即应暴露。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 500、前置异常与稳定原因码 invalid_security_configuration 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Invalid security configuration"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：500
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："invalid_security_configuration"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Invalid security configuration',
		int        $code = 500,
		\Throwable $previous = null,
		string     $reasonCode = 'invalid_security_configuration'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
