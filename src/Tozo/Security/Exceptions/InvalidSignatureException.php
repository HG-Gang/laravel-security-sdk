<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * InvalidSignatureException
 *
 * 文件功能：
 * - 签名值与重算结果常量时间比较不一致时抛出
 */

namespace Tozo\Security\Exceptions;

class InvalidSignatureException extends SignatureException
{
    /**
     * 构造签名无效异常。
     *
     * 使用范围：HmacSha256Signer.verify / HmacBearerAuthenticator.authenticate 中必填元数据缺失、
     * key_id 不符或 hash_equals 常量时间比较不一致时抛出。
     * 适用场景：HMAC 验签失败的最终判定出口，防止篡改请求通过认证。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 invalid_signature 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Invalid signature"
     * @param int $code HTTP 语义码｜响应状态基准。示例：401
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："invalid_signature"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Invalid signature',
        int        $code = 401,
        \Throwable $previous = null,
        string     $reasonCode = 'invalid_signature'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
