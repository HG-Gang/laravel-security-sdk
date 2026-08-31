<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenIssuanceException
 *
 * 文件功能：
 * - Token 签发失败（功能未启用、密钥缺失、编码失败）时抛出
 */

namespace Tozo\Security\Exceptions;

class TokenIssuanceException extends TokenException
{
    /**
     * 构造 Token 签发失败异常。
     *
     * 使用范围：JwtTokenIssuer.issue 中功能未启用、保护性 claim 被覆盖、JWT 编码失败时抛出；
     * TokenIssuerInterface 以 @param string $message 异常消息｜面向日志，禁止敏感值。示例："Token issuance failed"
     * @param int $code HTTP 语义码｜响应状态基准。示例：500
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："token_issue_failed"
     * @return void 无返回值。
     * @throws 声明该契约。
     * 适用场景：签发方向故障（未启用、密钥缺失、编码失败）的统一出口。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 500、前置异常与稳定原因码 token_issue_failed 传给父类。
     *
     */
    public function __construct(
        string     $message = 'Token issuance failed',
        int        $code = 500,
        \Throwable $previous = null,
        string     $reasonCode = 'token_issue_failed'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
