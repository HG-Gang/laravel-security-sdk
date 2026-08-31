<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * SignatureException
 *
 * 文件功能：
 * - 请求/响应签名相关异常基类（验签失败、时钟偏差、重放）
 */

namespace Tozo\Security\Exceptions;

class SignatureException extends SecurityException
{
    /**
     * 构造签名异常基类实例。
     *
     * 使用范围：签名相关异常基类，无直接抛出点；SignerInterface / TozoHttpClient 以 @param string $message 异常消息｜面向日志，禁止敏感值。示例："Signature verification failed"
     * @param int $code HTTP 语义码｜响应状态基准。示例：401
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："invalid_signature"
     * @return void 无返回值。
     * @throws 声明契约，
     * InboundAuthenticatorMiddleware.securityFailureResponse 以 instanceof 归类映射；
     * 由 InvalidSignatureException / ClockSkewException / ReplayProtectionException 继承承载实际抛出。
     * 适用场景：请求/响应验签失败、时钟偏差、重放等场景的公共语义出口。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 invalid_signature 传给父类。
     *
     */
    public function __construct(
        string     $message = 'Signature verification failed',
        int        $code = 401,
        \Throwable $previous = null,
        string     $reasonCode = 'invalid_signature'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
