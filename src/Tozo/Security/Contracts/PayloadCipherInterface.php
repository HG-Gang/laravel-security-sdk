<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * PayloadCipherInterface
 *
 * 文件功能：
 * - 定义统一请求/响应加解密契约（首版 AES-256-GCM）
 * - 信封协议：nonce + tag + ciphertext，版本化字段
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Payload;
use Tozo\Security\Profile;

interface PayloadCipherInterface
{
	/**
	 * 加密负载契约。
	 *
	 * 使用范围：HttpClient 出站第 2 步、OutboundSignerMiddleware 代理加密。
	 * 适用场景：敏感 Body 在签名前完成 AEAD 加密（Encrypt-then-Sign 的“先加密”半步）。
	 *
	 * 函数逻辑：
	 * 1. 实现方读取 Profile encryption 配置与 key_id。
	 * 2. CSPRNG 生成 nonce 执行认证加密，Body 替换为信封 JSON。
	 *
	 * @param Payload $payload 安全负载｜携带待加密 body。示例：new Payload(['body'=>'{"sku":"A-1"}'])
	 * @param Profile $profile 出站 Profile｜提供 encryption.key_id。示例：Profile::fromConfig(...)
	 * @return Payload Body 已替换为信封 JSON 的同一实例。示例：同一 Payload 实例（Body=信封 JSON）
	 * @throws \Tozo\Security\Exceptions\ConfigurationException 未启用或配置非法。
	 * @throws \Tozo\Security\Exceptions\EncryptionException 加密执行失败。
	 */
	public function encrypt(Payload $payload, Profile $profile);
	
	/**
	 * 解密负载契约。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware 验签通过后按需调用。
	 * 适用场景：接收端按白名单严格还原明文；失败不部分输出。
	 *
	 * 函数逻辑：
	 * 1. 实现方校验信封 version/algorithm/key_id/iv/tag 后 AEAD 解密。
	 * 2. 成功替换 Body 为明文；失败抛统一解密异常。
	 *
	 * @param Payload $payload 入站负载｜Body 为信封 JSON。示例：new Payload(['body'=>'{"version":"1",...}'])
	 * @param Profile $profile 入站 Profile｜提供 key_id 白名单基准。示例：Profile::fromConfig(...)
	 * @return Payload Body 已还原为明文的同一实例。示例：同一 Payload 实例（Body=明文）
	 * @throws \Tozo\Security\Exceptions\InvalidCiphertextException 任一校验失败。
	 */
	public function decrypt(Payload $payload, Profile $profile);
	
	/**
	 * 返回加密 driver 名称契约。
	 *
	 * 使用范围：日志标注与信封 algorithm 字段比对。
	 * 适用场景：确认当前为 aes_256_gcm 实现。
	 *
	 * 函数逻辑：
	 * 1. 返回实现类常量 DRIVER。
	 *
	 * @return string driver 标识。示例："aes_256_gcm"
	 */
	public function getDriver();
}
