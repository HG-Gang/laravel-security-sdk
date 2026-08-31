<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * LaravelLogAuditSink
 *
 * 文件功能：
 * - AuditSinkInterface 的 Laravel Log 通道适配器（设计 §16“Laravel Log 审计适配器”）
 * - 经 AuditSanitizer 脱敏后写入配置的日志通道
 *
 * 安全边界：
 * - 写入前强制脱敏；日志内容不含密钥、完整 Token 与敏感 Body
 * - 日志通道不可用时抛出 SecurityException(audit_sink_unavailable)，不静默丢弃
 */

namespace Tozo\Security\Storage;

use Throwable;
use Psr\Log\LoggerInterface;
use Tozo\Security\Audit\AuditSanitizer;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Exceptions\SecurityException;
use Tozo\Security\Exceptions\ConfigurationException;

class LaravelLogAuditSink implements AuditSinkInterface
{
    /**
     * 日志器，审计事件的最终写入目标。
     * 选 log 后端而非 cache 的场景：宿主已有集中式日志采集，
     * 审计事件随之进入既有的检索与告警链路。
     * 事件在写入前已由 AuditSanitizer 脱敏，不含密钥与完整 Token；
     * 但日志的读取面通常比接口更宽，选择该后端时须确认通道权限收敛。
     *
     * @var LoggerInterface
     */
    private $logger;
    
    /**
     * 审计事件写入时使用的 PSR-3 级别。
     * 统一用同一级别而非按事件成败分级，是因为审计的用途是**完整留痕**而非告警——
     * 按级别过滤会让部分事件在日志聚合层被丢弃，留下无法解释的空档。
     * 安全告警应由日志平台按原因码规则触发，不依赖这里的级别。
     *
     * @var string
     */
    private $level;
    
    /**
     * 构造 Log 审计适配器。
     *
     * 使用范围：ServiceProvider 在 audit.driver=log 时注册 AuditSinkInterface 单例。
     * 适用场景：宿主已有日志体系（ELK 等），复用通道而非另建缓存存储。
     *
     * 函数逻辑：
     * 1. 保存日志器与统一 level。
     *
     * @param LoggerInterface $logger 日志器｜PSR-3 实例。示例：Log::channel('security')
     * @param string $level 日志级别｜PSR-3 level。示例："info"
     * @return void 无返回值。
     */
    public function __construct(LoggerInterface $logger, string $level = 'info')
    {
        $this->logger = $logger;
        $this->level  = $level;
    }
    
    /**
     * 脱敏后写入 Log 通道。
     *
     * 使用范围：HttpClient.audit 与入站安全事件落盘时调用。
     * 适用场景：复用宿主日志检索体系，同时保证不含密钥/完整 Token/敏感 Body。
     *
     * 函数逻辑：
     * 1. AuditSanitizer::sanitize 强制脱敏（硬性前置）。
     * 2. 以 audit_id 关联写入 context；任何 Throwable 包装为 SecurityException。
     *
     * @param array $event 审计事件｜原始键值对。示例：["id"=>"ab12","action"=>"POST","status"=>200]
     * @return void 无返回值。
     * @throws SecurityException 日志通道不可用（audit_sink_unavailable）。
     */
    public function log(array $event)
    {
        try {
            // 脱敏是硬性前置步骤，任何来源的事件都不得绕过。
            $sanitized = AuditSanitizer::sanitize($event);
            
            $eventId = isset($sanitized['id']) && is_string($sanitized['id']) && $sanitized['id'] !== ''
                ? $sanitized['id']
                : bin2hex(random_bytes(8));
            
            $this->logger->{$this->level}('tozo_security.audit', [
                'audit_id' => $eventId,
                'event'    => $sanitized,
            ]);
        } catch (Throwable $e) {
            throw new SecurityException('Audit sink unavailable', 503, $e, 'audit_sink_unavailable');
        }
    }
    
    /**
     * 兼容 TTL 接口。
     *
     * 使用范围：容器装配或契约调用方设置保留时长时。
     * 适用场景：Log 无过期概念，仅保持接口一致并拦截非法值。
     *
     * 函数逻辑：
     * 1. ttl≤0 抛 ConfigurationException；其余忽略。
     *
     * @param int $ttl 存活时长(秒)｜正整数。示例：86400
     * @return void 无返回值。
     * @throws ConfigurationException ttl 非正数。
     */
    public function setTtl(int $ttl)
    {
        if ($ttl <= 0) {
            throw new ConfigurationException('Audit TTL must be positive');
        }
    }
    
    /**
     * 返回审计 driver 名称。
     *
     * 使用范围：日志标注与运行期后端可观测。
     * 适用场景：确认当前为 laravel_log 后端。
     *
     * 函数逻辑：
     * 1. 返回常量标识。
     *
     * @return string driver 标识｜固定值。示例："laravel_log"
     */
    public function getDriver()
    {
        return 'laravel_log';
    }
}
