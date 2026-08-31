<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TenantMismatchException
 *
 * 文件功能：
 * - Token 租户绑定不符异常（tenant_id 不在 Profile allowed_tenants 白名单）
 */

namespace Tozo\Security\Exceptions;

class TenantMismatchException extends AuthenticationException
{
    /**
     * 构造租户绑定不符异常。
     *
     * 使用范围：JwtTokenVerifier.assertClaimsBoundToProfile 中 Token tenant_id
     * 缺失或不在 Profile allowed_tenants 白名单时抛出。
     * 适用场景：多租户隔离校验，拒绝跨租户 Token 进入本 Profile 服务的判定出口。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 tenant_mismatch 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Token tenant does not match profile"
     * @param int $code HTTP 语义码｜响应状态基准。示例：401
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："tenant_mismatch"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Token tenant does not match profile',
        int        $code = 401,
        \Throwable $previous = null,
        string     $reasonCode = 'tenant_mismatch'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
