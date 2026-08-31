<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * AuditSanitizer
 *
 * 文件功能：
 * - 审计事件统一脱敏器（Audit 模块唯一脱敏事实来源）
 * - 无论调用方传入什么，敏感键一律剔除后再落盘
 *
 * 安全边界：
 * - 禁止记录：密钥、secret、完整 Token/JWT、Authorization、原始 Body、解密明文、完整签名
 * - 新增审计字段时必须先确认不落入禁止清单
 */

namespace Tozo\Security\Audit;

class AuditSanitizer
{
    /**
     * 绝对禁止写入审计存储的字段名（大小写不敏感比对）。
     */
    public const FORBIDDEN_KEYS = [
        'signature',
        'jwt',
        'authorization',
        'token',
        'body',
        'plaintext',
        'secret',
        'password',
        'refresh_token',
        'id_token',
    ];
    
    /**
     * 对审计事件执行敏感键剔除并返回可直接持久化的数组。
     *
     * 使用范围：所有 AuditSink 适配器落盘前的强制前置步骤（Audit 模块唯一脱敏事实来源）。
     * 适用场景：事件数组可能携带 signature/token/body 等禁止字段时统一清洗。
     *
     * 函数逻辑：
     * 1. 双层遍历 FORBIDDEN_KEYS 与事件键名，strcasecmp 大小写不敏感命中即 unset。
     * 2. payload 为数组时额外剔除 body_hash（请求内容派生信息）。
     * 3. 返回剩余字段组成的数组，其余键值不做改写。
     *
     * @param array $event 原始审计事件｜调用方拼装的结构化数组。示例：["event"=>"verify_failed","token"=>"eyJ..."]
     * @return array 脱敏后的事件｜禁止清单字段与 body_hash 已移除。示例：["event"=>"verify_failed"]
     */
    public static function sanitize(array $event)
    {
        foreach (self::FORBIDDEN_KEYS as $forbidden) {
            foreach (array_keys($event) as $key) {
                if (strcasecmp((string)$key, $forbidden) === 0) {
                    unset($event[$key]);
                }
            }
        }
        
        // Body 哈希虽非明文，但属于请求内容派生信息，一并剔除。
        if (isset($event['payload']) && is_array($event['payload'])) {
            unset($event['payload']['body_hash']);
        }
        
        return $event;
    }
}
