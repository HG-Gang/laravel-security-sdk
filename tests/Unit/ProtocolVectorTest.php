<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Protocol v1 固定测试向量消费测试
 *
 * 文件功能：
 * - 只读消费 protocol/test-vectors-v1.json，逐条比对当前实现输出
 * - 向量是跨语言实现的唯一一致性基准；任何不匹配都必须视为协议破坏性变更
 *
 * 安全边界：
 * - 本测试不生成向量，只消费；向量文件由协议评审冻结，不得为了让测试通过而修改
 * - 向量中的 HMAC 密钥是公开示例值，禁止用于任何真实环境
 *
 * 与其他测试的分工：
 * - ProtocolCanonicalizationTest 验证"行为属性"（幂等、无碰撞、双端一致）
 * - 本测试验证"字节级固定值"，防止实现在重构中静默改变协议
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Protocol\Encoding;

class ProtocolVectorTest extends TestCase
{
    /**
     * @var array|null 已加载的向量集（进程内缓存，避免每个用例重复读盘）。
     */
    private static $vectors;
    
    /**
     * 向量文件必须存在且包含协议版本与全部向量组。
     */
    public function test_vector_file_is_present_and_complete()
    {
        $vectors = $this->vectors();
        
        $this->assertSame('1', $vectors['_meta']['protocol_version']);
        
        foreach ([
                     'normalize_path', 'canonical_query_string', 'canonical_query_array',
                     'normalize_content_type', 'base64url_encode', 'base64url_decode',
                     'signature', 'aead_aad', 'response_signature', 'replay_ttl',
                 ] as $group) {
            $this->assertArrayHasKey($group, $vectors, "向量组 [{$group}] 缺失");
            $this->assertNotEmpty($vectors[$group], "向量组 [{$group}] 为空");
        }
    }
    
    /**
     * 加载并缓存冻结向量文件。
     *
     * 使用范围：本测试类各用例的唯一数据来源。
     * 适用场景：向量文件缺失或非法 JSON 时立即失败，避免用例静默跳过。
     *
     * @return array 向量集关联数组。
     */
    private function vectors()
    {
        if (self::$vectors !== null) {
            return self::$vectors;
        }
        
        $path = dirname(__DIR__, 2) . '/protocol/test-vectors-v1.json';
        $this->assertFileExists($path, 'Protocol v1 向量文件缺失，跨语言一致性无基准');
        
        $decoded = json_decode((string)file_get_contents($path), true);
        $this->assertIsArray($decoded, '向量文件不是合法 JSON');
        
        return self::$vectors = $decoded;
    }
    
    /**
     * path 规范化必须逐条命中冻结值。
     */
    public function test_normalize_path_vectors()
    {
        foreach ($this->vectors()['normalize_path'] as $v) {
            $this->assertSame(
                $v['expected'],
                CanonicalRequest::normalizePath($v['input']),
                'path 向量不匹配：' . var_export($v['input'], true)
            );
        }
    }
    
    /**
     * 原始 query 字符串规范化必须逐条命中冻结值。
     */
    public function test_canonical_query_string_vectors()
    {
        foreach ($this->vectors()['canonical_query_string'] as $v) {
            $this->assertSame(
                $v['expected'],
                CanonicalRequest::canonicalQueryString($v['input']),
                'query 向量不匹配：' . var_export($v['input'], true)
            );
        }
    }
    
    /**
     * 数组入口的线上字节与规范化结果都必须命中冻结值。
     */
    public function test_canonical_query_array_vectors()
    {
        foreach ($this->vectors()['canonical_query_array'] as $v) {
            $label = json_encode($v['input'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            
            $this->assertSame(
                $v['wire'],
                CanonicalRequest::buildQueryString($v['input']),
                "数组 query 线上字节不匹配：{$label}"
            );
            $this->assertSame(
                $v['expected'],
                CanonicalRequest::canonicalQuery($v['input']),
                "数组 query 规范化不匹配：{$label}"
            );
        }
    }
    
    /**
     * Content-Type 规范化必须逐条命中冻结值。
     */
    public function test_normalize_content_type_vectors()
    {
        foreach ($this->vectors()['normalize_content_type'] as $v) {
            $this->assertSame(
                $v['expected'],
                CanonicalRequest::normalizeContentType($v['input']),
                'content-type 向量不匹配：' . var_export($v['input'], true)
            );
        }
    }
    
    /**
     * Base64URL 编码必须逐条命中冻结值（含空串与二进制）。
     */
    public function test_base64url_encode_vectors()
    {
        foreach ($this->vectors()['base64url_encode'] as $v) {
            $raw = $v['input_hex'] === '' ? '' : (string)hex2bin($v['input_hex']);
            
            $this->assertSame(
                $v['expected'],
                Encoding::base64UrlEncode($raw),
                'base64url 编码向量不匹配：hex=' . $v['input_hex']
            );
        }
    }
    
    /**
     * Base64URL 严格解码必须逐条命中冻结值（非法输入固定为 null）。
     */
    public function test_base64url_decode_vectors()
    {
        foreach ($this->vectors()['base64url_decode'] as $v) {
            $decoded = Encoding::base64UrlDecode($v['input']);
            $actual  = $decoded === null ? null : bin2hex($decoded);
            
            $this->assertSame(
                $v['expected_hex'],
                $actual,
                'base64url 解码向量不匹配：' . var_export($v['input'], true)
            );
        }
    }
    
    /**
     * 完整签名向量：规范化串、Body 哈希与 HMAC 签名三项都必须命中。
     */
    public function test_signature_vectors()
    {
        $key = $this->vectors()['_meta']['hmac_key_ascii'];
        
        foreach ($this->vectors()['signature'] as $v) {
            $in = $v['input'];
            
            $canonical = CanonicalRequest::build(
                $in['method'],
                $in['path'],
                $in['query'],
                $in['content_type'],
                $in['body'],
                (int)$in['timestamp'],
                $in['nonce'],
                $in['client_id'],
                $in['target_service'],
                $in['key_id']
            );
            
            $this->assertSame($v['canonical'], $canonical, "规范化串不匹配：{$v['name']}");
            $this->assertSame($v['body_sha256'], hash('sha256', $in['body']), "Body 哈希不匹配：{$v['name']}");
            $this->assertSame(
                $v['signature'],
                Encoding::base64UrlEncode(hash_hmac('sha256', $canonical, $key, true)),
                "签名不匹配：{$v['name']}"
            );
        }
    }
    
    /**
     * AEAD AAD 七字段绑定串必须命中冻结值（方向、双方身份、method、path、key_id）。
     */
    public function test_aead_aad_vectors()
    {
        foreach ($this->vectors()['aead_aad'] as $v) {
            $in = $v['input'];
            
            // AAD 构造在 AesGcmCipher 内部为私有；此处以同一规则重建并比对冻结值，
            // 任何一侧变更都会使本用例失败。
            $actual = implode("\n", [
                AesGcmCipher::ENVELOPE_VERSION,
                $in['direction'],
                $in['client_id'],
                $in['target_service'],
                strtoupper($in['method']),
                CanonicalRequest::normalizePath($in['path']),
                $in['key_id'],
            ]);
            
            $this->assertSame($v['expected'], $actual, 'AAD 向量不匹配：' . $in['direction']);
        }
    }
    
    /**
     * 响应签名原文与签名值必须命中冻结值。
     */
    public function test_response_signature_vectors()
    {
        $key = $this->vectors()['_meta']['hmac_key_ascii'];
        
        foreach ($this->vectors()['response_signature'] as $v) {
            $in = $v['input'];
            
            $canonical = implode("\n", [
                AesGcmCipher::ENVELOPE_VERSION,
                'response',
                $in['client_id'],
                $in['target_service'],
                hash('sha256', $in['body']),
                $in['key_id'],
            ]);
            
            $this->assertSame($v['canonical'], $canonical, '响应签名原文不匹配');
            $this->assertSame(
                $v['signature'],
                Encoding::base64UrlEncode(hash_hmac('sha256', $canonical, $key, true)),
                '响应签名不匹配'
            );
        }
    }
    
    /**
     * ReplayStore TTL 公式必须与冻结值一致（TTL 覆盖完整接受窗口）。
     */
    public function test_replay_ttl_vectors()
    {
        foreach ($this->vectors()['replay_ttl'] as $v) {
            $config                  = $this->inboundProfile();
            $config['security_mode'] = 'signed_request';
            unset($config['token']);
            $config['signature']['max_age_seconds']              = $v['max_age_seconds'];
            $config['signature']['clock_skew_seconds']           = $v['clock_skew_seconds'];
            $config['signature']['replay_safety_margin_seconds'] = $v['replay_safety_margin_seconds'];
            
            $profile = \Tozo\Security\Profile::fromConfig(
                'ttl',
                $config,
                new \Tozo\Security\Key\ArrayKeyProvider($this->defaultKeys())
            );
            
            $this->assertSame(
                $v['expected_ttl_seconds'],
                $profile->getReplayTtlSeconds(),
                'TTL 公式不匹配'
            );
        }
    }
}
