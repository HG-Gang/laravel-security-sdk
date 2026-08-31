<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ScopeDeniedException
 *
 * 文件功能：
 * - required_scopes ⊄ granted_scopes 授权判定失败时抛出
 */

namespace Tozo\Security\Exceptions;

class ScopeDeniedException extends ScopeException
{
	/**
	 * 构造 Scope 授权拒绝异常。
	 *
	 * 使用范围：ScopeAuthorizer.authorize 中 required_scopes 未被 granted_scopes 覆盖时抛出。
	 * 适用场景：主体已通过认证但缺少访问所需权限的判定出口（403）。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 403、前置异常与稳定原因码 scope_denied 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Insufficient scope"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：403
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："scope_denied"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Insufficient scope',
		int        $code = 403,
		\Throwable $previous = null,
		string     $reasonCode = 'scope_denied'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
