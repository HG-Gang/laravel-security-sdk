<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * IssuerMismatchException
 *
 * 文件功能：
 * - Token iss 与 Profile 允许的 issuer 不一致时抛出
 */

namespace Tozo\Security\Exceptions;

class IssuerMismatchException extends AuthenticationException
{
    /**
     * 构造签发方不匹配异常。
     *
     * 使用范围：JwtTokenVerifier.assertClaimsBoundToProfile 中 Token iss
     * 与 Profile 允许 issuer 不一致时抛出。
     * 适用场景：拒绝其他签发方 Token 的多租户/多服务隔离判定出口。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 issuer_mismatch 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Issuer mismatch"
     * @param int $code HTTP 语义码｜响应状态基准。示例：401
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："issuer_mismatch"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Issuer mismatch',
        int        $code = 401,
        \Throwable $previous = null,
        string     $reasonCode = 'issuer_mismatch'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
