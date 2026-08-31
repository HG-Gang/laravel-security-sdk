<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * InvalidCiphertextException
 *
 * 文件功能：
 * - 信封结构非法、tag/nonce 校验失败或 AEAD 解密失败时抛出
 */

namespace Tozo\Security\Exceptions;

use Tozo\Security\Exceptions\DecryptionException;

class InvalidCiphertextException extends DecryptionException
{
    /**
     * 构造密文非法异常。
     *
     * 使用范围：AesGcmCipher.decryptEnvelopeJson / decrypt 中信封缺失、JSON/版本/算法/key_id/
     * 字段长度校验失败或 AEAD 校验不一致时统一抛出；ResponseIntegrityChecker 捕获后转译。
     * 适用场景：解密方向所有内容级失败的归并出口，对外不区分具体失败项。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 400、前置异常与稳定原因码 decryption_failed 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Invalid ciphertext or envelope"
     * @param int $code HTTP 语义码｜响应状态基准。示例：400
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："decryption_failed"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Invalid ciphertext or envelope',
        int        $code = 400,
        \Throwable $previous = null,
        string     $reasonCode = 'decryption_failed'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
