<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ClockSkewException
 *
 * 文件功能：
 * - 签名时间戳超出 max_age + clock_skew 允许窗口时抛出
 */

namespace Tozo\Security\Exceptions;

class ClockSkewException extends SignatureException
{
    /**
     * 构造时钟偏差异常。
     *
     * 使用范围：HmacSha256Signer.verify / HmacBearerAuthenticator.authenticate 中
     * 签名时间戳超出 max_age + clock_skew 允许窗口时抛出。
     * 适用场景：双向时间窗校验失败（过期或未来时间戳）的判定出口，防重放前置闸口。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 401、前置异常与稳定原因码 clock_skew 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Signature timestamp outside allowed window"
     * @param int $code HTTP 语义码｜响应状态基准。示例：401
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："clock_skew"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Signature timestamp outside allowed window',
        int        $code = 401,
        \Throwable $previous = null,
        string     $reasonCode = 'clock_skew'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
