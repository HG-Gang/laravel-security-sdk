<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ProtocolException
 *
 * 文件功能：
 * - 协议版本不支持或协议必要字段缺失时抛出
 */

namespace Tozo\Security\Exceptions;

class ProtocolException extends SecurityException
{
    /**
     * 构造协议异常。
     *
     * 使用范围：ProtocolVersion.ensureSupported 对白名单外版本号抛出；
     * TozoHttpClient 将传输层任何 Throwable 包装为 ProtocolException(502) 后抛出。
     * 适用场景：协议版本不支持或协议必要环节失败的统一出口。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 400、前置异常与稳定原因码 unsupported_protocol_version 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Unsupported protocol"
     * @param int $code HTTP 语义码｜响应状态基准。示例：400
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："unsupported_protocol_version"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Unsupported protocol',
        int        $code = 400,
        \Throwable $previous = null,
        string     $reasonCode = 'unsupported_protocol_version'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
