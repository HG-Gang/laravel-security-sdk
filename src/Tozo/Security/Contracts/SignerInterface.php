<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * SignerInterface
 *
 * 文件功能：
 * - 定义请求签名与验签契约（Protocol v1：规范化串 + HMAC + 时间窗口 + 防重放）
 * - sign() 面向调用端，verify() 面向服务端
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Payload;
use Tozo\Security\Profile;

interface SignerInterface
{
	/**
	 * 签名生成契约。
	 *
	 * 使用范围：HttpClient 出站第 3 步、OutboundSignerMiddleware 代理转发。
	 * 适用场景：对最终 wire Body（可能已加密）产出 HMAC 完整性证明。
	 *
	 * 函数逻辑：
	 * 1. 实现方校验 Profile 签名开启与 key_id 白名单。
	 * 2. 生成 timestamp/CSPRNG nonce/body_hash 并写入 Payload 后返回同一实例。
	 *
	 * @param Payload $payload 安全负载｜携带请求上下文。示例：new Payload(['method'=>'POST','path'=>'/api/orders','body'=>'{}'])
	 * @param Profile $profile 出站 Profile｜提供签名参数。示例：Profile::fromConfig(...)
	 * @return Payload 追加签名元数据后的同一实例。示例：同一 Payload 实例（含 signature/timestamp/nonce）
	 * @throws \Tozo\Security\Exceptions\ConfigurationException 未启用签名或配置非法。
	 * @throws \Tozo\Security\Exceptions\KeyNotFoundException 密钥缺失或状态非 active。
	 */
	public function sign(Payload $payload, Profile $profile);
	
	/**
	 * 验签并登记 Nonce 契约。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware 按 security_mode 分派调用。
	 * 适用场景：服务端防篡改与防重放的顺序正确性——先常量时间比对，后原子登记。
	 *
	 * 函数逻辑：
	 * 1. 实现方重建规范化串并 hash_equals 比对。
	 * 2. 时间窗校验；通过后按 TTL 公式原子登记 Nonce。
	 * 3. 任何失败抛类型化异常，禁止返回 false 表达失败。
	 *
	 * @param Payload $payload 待验证负载｜含 Header 元数据。示例：new Payload(['signature'=>'qE8f',...])
	 * @param Profile $profile 入站 Profile｜提供白名单与窗口参数。示例：Profile::fromConfig(...)
	 * @return bool 恒为 true；失败以异常表达。示例：true
	 * @throws \Tozo\Security\Exceptions\InvalidSignatureException 签名不一致或字段缺失。
	 * @throws \Tozo\Security\Exceptions\ClockSkewException 时间戳越窗。
	 * @throws \Tozo\Security\Exceptions\ReplayProtectionException Nonce 已使用。
	 * @throws \Tozo\Security\Exceptions\ReplayStoreUnavailableException 存储故障 fail-closed。
	 */
	public function verify(Payload $payload, Profile $profile);
	
	/**
	 * 返回签名 driver 名称契约。
	 *
	 * 使用范围：日志标注与 driver 白名单比对。
	 * 适用场景：确认当前为 hmac_sha256 实现。
	 *
	 * 函数逻辑：
	 * 1. 返回实现类常量 DRIVER。
	 *
	 * @return string driver 标识。示例："hmac_sha256"
	 */
	public function getDriver();
}
