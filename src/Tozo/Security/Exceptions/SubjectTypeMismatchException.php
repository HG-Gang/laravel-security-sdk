<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * SubjectTypeMismatchException
 *
 * 文件功能：
 * - Token 主体类型不在 Profile allowed_subject_types 白名单时抛出
 *
 * 安全边界：
 * - 属于“密码学主体与 Profile 绑定不一致”，对外映射为 profile_subject_mismatch 类别
 */

namespace Tozo\Security\Exceptions;

class SubjectTypeMismatchException extends AuthenticationException
{
	/**
	 * 构造主体类型不匹配异常。
	 *
	 * 使用范围：ScopeAuthorizer.authorize 与 JwtTokenVerifier.assertClaimsBoundToProfile 中
	 * Token 主体类型不在 Profile allowed_subject_types 白名单时抛出。
	 * 适用场景：“密码学主体与 Profile 绑定不一致”的判定出口，对外映射 profile_subject_mismatch 类别。
	 *
	 * 函数逻辑：
	 * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 profile_subject_mismatch 传给父类。
	 *
	 * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Subject type is not allowed for this profile"
	 * @param int $code HTTP 语义码｜响应状态基准。示例：401
	 * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
	 * @param string $reasonCode 内部原因码｜与该类默认一致。示例："profile_subject_mismatch"
	 * @return void 无返回值。
	 */
	public function __construct(
		string     $message = 'Subject type is not allowed for this profile',
		int        $code = 401,
		\Throwable $previous = null,
		string     $reasonCode = 'profile_subject_mismatch'
	)
	{
		parent::__construct($message, $code, $previous, $reasonCode);
	}
}
