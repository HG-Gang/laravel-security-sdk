<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ClientIdMismatchException
 *
 * 文件功能：
 * - Token 的 client_id/azp 与入站 Profile expected_client_id 不一致时抛出
 *
 * 安全边界：
 * - Header 中的客户端标识只能作为查找提示，最终以密码学验证结果绑定 Profile
 */

namespace Tozo\Security\Exceptions;

class ClientIdMismatchException extends AuthenticationException
{
    /**
     * 构造客户端身份不匹配异常。
     *
     * 使用范围：JwtTokenVerifier.assertClaimsBoundToProfile 中 Token client_id/azp
     * 与入站 Profile expected_client_id 不一致时抛出。
     * 适用场景：Header 客户端标识仅作查找提示，最终以密码学验证结果绑定 Profile 的判定出口。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 profile_subject_mismatch 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Client identity does not match this profile"
     * @param int $code HTTP 语义码｜响应状态基准。示例：401
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："profile_subject_mismatch"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Client identity does not match this profile',
        int        $code = 401,
        \Throwable $previous = null,
        string     $reasonCode = 'profile_subject_mismatch'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
