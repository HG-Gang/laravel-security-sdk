<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * RevocationStoreUnavailableException
 *
 * 文件功能：
 * - 吊销存储查询故障时抛出
 *
 * 安全边界：
 * - fail-closed：启用吊销后存储不可用必须拒绝 Token，防止已吊销 Token 逃逸
 */

namespace Tozo\Security\Exceptions;

class RevocationStoreUnavailableException extends SecurityException
{
    /**
     * 构造吊销存储不可用异常。
     *
     * 使用范围：LaravelCacheTokenRevocationStore 查询/写入故障时抛出；
     * JwtTokenVerifier.assertNotRevoked 对吊销存储绑定缺失或查询异常时抛出（fail-closed）。
     * 适用场景：启用吊销后存储不可用必须拒绝 Token，防止已吊销 Token 逃逸。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 503、前置异常与稳定原因码 revocation_store_unavailable 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Token revocation store unavailable"
     * @param int $code HTTP 语义码｜响应状态基准。示例：503
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："revocation_store_unavailable"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Token revocation store unavailable',
        int        $code = 503,
        \Throwable $previous = null,
        string     $reasonCode = 'revocation_store_unavailable'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
