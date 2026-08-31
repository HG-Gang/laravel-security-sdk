<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * SecurityException
 *
 * 文件功能：
 * - SDK 所有安全异常的统一基类
 * - 携带稳定的内部原因码（reason code），用于日志与审计
 * - 对外响应只允许输出安全类别码，原因码不得直接透出给调用方
 *
 * 安全边界：
 * - 原因码属于内部信息，Middleware 层负责映射为对外安全错误类别
 */

namespace Tozo\Security\Exceptions;

class SecurityException extends \Exception
{
    /**
     * 稳定的内部原因码（如 replay_detected、unknown_key_id）。
     * 「稳定」意味着它是可被程序依赖的分类标识，重构时不得随意改名——
     * 审计检索与日志告警规则都按它匹配，改名会让既有告警静默失效。
     * 它属于**内部信息**：中间件负责把它映射为对外的粗粒度错误类别，
     * 直接返回给调用方会泄露服务端的验证细节，为攻击者提供逐项试探的反馈。
     *
     * @var string
     */
    protected $reasonCode;
    
    /**
     * 构造安全异常基类实例。
     *
     * 使用范围：LaravelCacheAuditSink / LaravelLogAuditSink 审计写入失败（audit_sink_unavailable）与
     * TozoHttpClient 审计 fail-closed 时直接抛出；同时作为 SDK 全部安全异常的统一根类型。
     * 适用场景：所有安全异常共享的消息 + HTTP 语义码 + 前置异常 + 稳定原因码承载结构。
     *
     * 函数逻辑：
     * 1. 调用父类构造保存消息、HTTP 语义码与前置异常链。
     * 2. 将稳定原因码 reasonCode 存入受保护属性，供 getReasonCode 读取。
     *
     * @param string $message 异常消息｜面向日志，禁止敏感值。示例：""
     * @param int $code HTTP 语义码｜响应状态基准。示例：0
     * @param \Throwable|null $previous 前置异常｜保留原链。示例：null
     * @param string $reasonCode 内部原因码｜与该类默认一致，不得透出给调用方。示例："internal_error"
     * @return void 无返回值。
     */
    public function __construct(
        string     $message = '',
        int        $code = 0,
        \Throwable $previous = null,
        string     $reasonCode = 'internal_error'
    )
    {
        parent::__construct($message, $code, $previous);
        $this->reasonCode = $reasonCode;
    }
    
    /**
     * 返回稳定的内部原因码。
     *
     * 使用范围：审计写入、日志记录与中间件的对外错误映射三处调用。
     * 适用场景：日志与审计需要机器可读的错误分类，而对外响应又不得泄露验证细节；
     *           用内部原因码加映射表同时满足这两个方向相反的要求。
     *
     * 函数逻辑：
     * 1. 返回构造时保存的原因码；未提供时为空串，调用方据此回退到通用错误分类。
     *
     * @return string 稳定内部原因码。示例："replay_detected"
     */
    public function getReasonCode()
    {
        return $this->reasonCode;
    }
}
