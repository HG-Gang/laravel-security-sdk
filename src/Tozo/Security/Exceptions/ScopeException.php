<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ScopeException
 *
 * 文件功能：
 * - Scope 授权相关异常基类
 */

namespace Tozo\Security\Exceptions;

class ScopeException extends SecurityException
{
    /**
     * 构造 Scope 授权异常基类实例。
     *
     * 使用范围：Scope 授权异常基类，无直接抛出点；ScopeAuthorizerInterface 以 use 声明契约，
     * InboundAuthenticatorMiddleware.securityFailureResponse 以 instanceof 归类映射；
     * 由 ScopeDeniedException / ScopeMismatchException 继承承载实际抛出。
     * 适用场景：授权判定失败类场景的公共语义出口（403）。
     *
     * 函数逻辑：
     * 1. 将消息、HTTP 语义码 403、前置异常与稳定原因码 scope_denied 传给父类。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例："Scope authorization failed"
     * @param int $code HTTP 语义码｜响应状态基准。示例：403
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致。示例："scope_denied"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = 'Scope authorization failed',
        int        $code = 403,
        \Throwable $previous = null,
        string     $reasonCode = 'scope_denied'
    )
    {
        parent::__construct($message, $code, $previous, $reasonCode);
    }
}
