<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * DecryptionException
 *
 * 文件功能：
 * - 解密方向异常基类
 *
 * 安全边界：
 * - 对外统一表现为解密失败，不区分 tag/nonce/密文哪一项出错
 */

namespace Tozo\Security\Exceptions;

class DecryptionException extends EncryptionException
{
    /**
     * 构造解密失败异常。
     *
     * 使用范围：解密方向异常基类，无直接抛出点；由 InvalidCiphertextException 继承承载实际抛出，
     * InboundAuthenticatorMiddleware.securityFailureResponse 以 instanceof 归类映射对外类别。
     * 适用场景：解密方向故障的公共语义出口，对外不区分 tag/nonce/密文哪一项出错。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 400、前置异常与稳定原因码 decryption_failed 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Decryption failed"
     * @param int $code HTTP 语义码｜响应状态基准。示例：400
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："decryption_failed"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Decryption failed',
        int        $code = 400,
        \Throwable $previous = null,
        string     $reasonCode = 'decryption_failed'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
