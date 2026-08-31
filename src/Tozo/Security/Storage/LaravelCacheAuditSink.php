<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * LaravelCacheAuditSink
 *
 * 文件功能：
 * - AuditSinkInterface 的 Laravel Cache 适配器
 * - 脱敏统一委托 Audit\AuditSanitizer（Audit 模块唯一事实来源）
 *
 * 安全边界：
 * - 审计事件不得包含密钥、完整 Token、Authorization Header、解密明文
 * - 写入失败抛出 SecurityException（audit_sink_unavailable），不静默丢弃
 */

namespace Tozo\Security\Storage;

use Throwable;
use Tozo\Security\Audit\AuditSanitizer;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Exceptions\SecurityException;
use Tozo\Security\Exceptions\ConfigurationException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;

class LaravelCacheAuditSink implements AuditSinkInterface
{
    /**
     * 缓存仓储。审计事件的写入目标；
     * 写入失败按安全存储故障处理并抛异常，不静默丢弃事件。
     *
     * @var CacheRepository
     */
    private $cache;
    
    /**
     * 审计记录保留秒数（86400 = 24 小时）。
     * 需按合规留存要求调整：缓存后端不适合长期留存，
     * 有长周期审计要求时应改用 log driver 接入集中日志体系。
     *
     * @var int
     */
    private $ttl = 86400;
    
    /**
     * 构造审计存储适配器并注入缓存仓储。
     *
     * 使用范围：ServiceProvider::registerStorageAdapters 按 audit driver=cache 注册 AuditSinkInterface 单例时实例化。
     * 适用场景：审计事件需要集中写入共享缓存后端以便检索与合规留存。
     *
     * 函数逻辑：
     * 1. 接收 CacheRepository 实例赋给内部属性，供 log 写入使用。
     *
     * @param CacheRepository $cache 缓存仓储｜Laravel Cache 契约实现（Redis 等共享后端）。示例：$app->make(CacheRepository::class)
     * @return void 无返回值。
     */
    public function __construct(CacheRepository $cache)
    {
        $this->cache = $cache;
    }
    
    /**
     * 脱敏后将审计事件写入缓存。
     *
     * 使用范围：TozoHttpClient 等安全组件经 AuditSinkInterface 契约调用。
     * 适用场景：签名失败、认证异常等安全事件需要可追溯且不含敏感值的持久化。
     *
     * 函数逻辑：
     * 1. AuditSanitizer::sanitize 硬性前置脱敏（剔除密钥/Token 等禁止字段）。
     * 2. 取脱敏结果中的 id 作事件标识；缺失时以 random_bytes 生成不可预测 id。
     * 3. Cache::put 写入 tozo_audit|{eventId}，保留期为内部 TTL。
     * 4. 任一环节 Throwable 包装为 SecurityException(audit_sink_unavailable)，不静默丢弃。
     *
     * @param array $event 审计事件｜结构化事件数组，敏感键将被剔除。示例：["event"=>"signature_failed","client_id"=>"pc"]
     * @return void 无返回值。
     * @throws SecurityException 审计写入失败 fail-closed（type=audit_sink_unavailable）。
     */
    public function log(array $event)
    {
        try {
            // 脱敏为硬性前置步骤；id 缺失时生成不可预测标识。
            $sanitized = AuditSanitizer::sanitize($event);
            
            $eventId = isset($sanitized['id']) && is_string($sanitized['id']) && $sanitized['id'] !== ''
                ? $sanitized['id']
                : bin2hex(random_bytes(8));
            
            $this->cache->put('tozo_audit|' . $eventId, $sanitized, $this->ttl);
        } catch (Throwable $e) {
            throw new SecurityException('Audit sink unavailable', 503, $e, 'audit_sink_unavailable');
        }
    }
    
    /**
     * 设置审计记录保留时长（秒）。
     *
     * 使用范围：ServiceProvider 装配或调用方按合规留存期下发。
     * 适用场景：在存储容量与审计合规保留要求之间取得平衡。
     *
     * 函数逻辑：
     * 1. 校验 ttl 必须为正，否则抛 ConfigurationException。
     * 2. 赋值内部属性，供后续 Cache::put 作为过期时间使用。
     *
     * @param int $ttl 保留秒数｜满足合规留存的最小时长。示例：86400
     * @return void 无返回值。
     * @throws ConfigurationException ttl 非正数时拒绝配置。
     */
    public function setTtl(int $ttl)
    {
        if ($ttl <= 0) {
            throw new ConfigurationException('Audit TTL must be positive');
        }
        
        $this->ttl = $ttl;
    }
    
    /**
     * 返回审计 driver 标识。
     *
     * 使用范围：运行期诊断与日志标注实际后端类型。
     * 适用场景：运维确认当前审计后端为 Laravel Cache 实现。
     *
     * 函数逻辑：
     * 1. 直接返回固定字符串 'laravel_cache'。
     *
     * @return string driver 标识｜固定值。示例："laravel_cache"
     */
    public function getDriver()
    {
        return 'laravel_cache';
    }
}
