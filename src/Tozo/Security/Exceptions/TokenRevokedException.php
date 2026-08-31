<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenRevokedException
 *
 * 文件功能：
 * - Token jti 命中吊销记录时抛出
 */

namespace Tozo\Security\Exceptions;

class TokenRevokedException extends AuthenticationException
{
    /**
     * 构造已吊销 Token 异常。
     *
     * 使用范围：JwtTokenVerifier.assertNotRevoked 命中吊销记录时抛出。
     * 适用场景：用户退出/风控封禁后，未过期 Token 需立即失效的判定出口。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 token_revoked 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Token has been revoked"
     * @param int $code HTTP 语义码｜响应状态基准。示例：401
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："token_revoked"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Token has been revoked',
        int        $code = 401,
        \Throwable $previous = null,
        string     $reasonCode = 'token_revoked'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
