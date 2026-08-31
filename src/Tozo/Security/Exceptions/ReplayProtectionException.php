<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ReplayProtectionException
 *
 * 文件功能：
 * - Nonce 在 ReplayStore 中已存在（重复请求）时抛出
 *
 * 安全边界：
 * - 仅在签名验证通过后才可能触发，避免无效请求污染防重放状态
 */

namespace Tozo\Security\Exceptions;

class ReplayProtectionException extends SignatureException
{
    /**
     * 构造重放攻击异常。
     *
     * 使用范围：HmacSha256Signer.registerNonce / HmacBearerAuthenticator.registerNonce 中
     * ReplayStore.record 返回 true（Nonce 已存在）时抛出。
     * 适用场景：签名验证通过后的重复请求判定出口，拦截重放流量。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 409、前置异常与稳定原因码 replay_detected 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Request has been replayed"
     * @param int $code HTTP 语义码｜响应状态基准。示例：409
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："replay_detected"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Request has been replayed',
        int        $code = 409,
        \Throwable $previous = null,
        string     $reasonCode = 'replay_detected'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
