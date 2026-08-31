<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ResponseIntegrityInterface
 *
 * 文件功能：
 * - 定义响应完整性的「生成」与「验证」两侧契约，构成同一条链路的闭环：
 *   · 服务端（被调用方）用 protectEncryptedResponse/protectSignedResponse 生成保护
 *   · 调用端用 decryptEncryptedResponse/verifySignedResponse 在交给业务前完成验证
 * - 两种固定模式：encrypted（AEAD 加密，GCM tag 即完整性证明）
 *   或 signed（方向绑定 direction=response 的应用层 HMAC 签名）
 *
 * 安全边界：
 * - 生成与验证必须使用同一 Profile 声明的固定 mode 与同一独立用途响应密钥
 * - 生成侧使用写方向密钥状态（active），验证侧接受迁移期读方向状态
 * - 未受保护的响应在验证侧一律拒绝，不得交给业务
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Profile;
use Tozo\Security\Exceptions\ResponseIntegrityException;

interface ResponseIntegrityInterface
{
	/**
	 * 生成 encrypted 模式响应信封契约（服务端侧）。
	 *
	 * 使用范围：ResponseIntegrityMiddleware 在业务返回响应后、写出前调用。
	 * 适用场景：被调用方需要让调用端既拿到机密性又拿到完整性证明时，
	 *           用响应专用密钥加密最终 Body，AAD 绑定 direction=response。
	 *
	 * 函数逻辑：
	 * 1. 实现方断言 Profile 固定 mode=encrypted 且 required=true。
	 * 2. 以 direction=response 生成六字段版本化信封 JSON。
	 *
	 * @param string $body 最终响应 Body｜序列化后的原始字节。示例：'{"ok":true}'
	 * @param Profile $profile 入站 Profile｜提供响应专用 key_id 与 client/target 绑定值。示例：Profile::fromConfig('order_inbound', ...)
	 * @return string 信封 JSON｜作为新的响应 Body 写出。示例：{"version":"1","algorithm":"aes_256_gcm",...}
	 * @throws ResponseIntegrityException 生成失败（配置或底层加密错误）。
	 */
	public function protectEncryptedResponse(string $body, Profile $profile);
	
	/**
	 * 生成 signed 模式响应签名契约（服务端侧）。
	 *
	 * 使用范围：ResponseIntegrityMiddleware 在业务返回响应后、写出前调用。
	 * 适用场景：响应无需加密但必须防篡改——对最终 Body 生成方向为 response 的 HMAC，
	 *           由调用端先验证后再交给业务。
	 *
	 * 函数逻辑：
	 * 1. 实现方断言 Profile 固定 mode=signed 并读取独立响应签名 key_id。
	 * 2. 以与验证侧完全相同的原文构造规则生成 Base64URL 签名值。
	 *
	 * @param string $body 最终响应 Body｜原始字节，哈希后参与签名原文。示例：'{"ok":true}'
	 * @param Profile $profile 入站 Profile｜提供 mode=signed 与响应签名 key_id。示例：Profile::fromConfig(...)
	 * @return string Base64URL 签名值｜写入 X-Tozo-Response-Signature 头。示例："qE8f2w"
	 * @throws ResponseIntegrityException 生成失败（配置或密钥状态错误）。
	 */
	public function protectSignedResponse(string $body, Profile $profile);
	
	/**
	 * 返回承载响应签名的 Header 名称。
	 *
	 * 使用范围：生成侧写入 Header、验证侧读取 Header 时共用同一常量来源。
	 * 适用场景：避免两侧各自硬编码字符串导致大小写或拼写漂移。
	 *
	 * 函数逻辑：
	 * 1. 实现方返回固定 Header 名常量，不随配置或请求内容变化——
	 *    两端头名不一致会让调用端把已受保护的响应判为「未受保护」并整体拒收。
	 *
	 * @return string Header 名称。示例："X-Tozo-Response-Signature"
	 */
	public function getSignatureHeaderName();
	
	/**
	 * 解密 encrypted 模式响应契约。
	 *
	 * 使用范围：HttpClient.verifyResponse 在 mode=encrypted 时调用。
	 * 适用场景：敏感响应借 GCM tag 同时获得机密性与完整性证明。
	 *
	 * 函数逻辑：
	 * 1. 实现方断言 Profile 固定 mode=encrypted。
	 * 2. 以 direction=response 解密信封；失败统一抛 ResponseIntegrityException。
	 *
	 * @param string $envelopeJson 信封 JSON｜响应 Body。示例：{"version":"1",...}
	 * @param Profile $profile 出站 Profile｜提供响应专用 key_id。示例：Profile::fromConfig(...)
	 * @return string 明文 Body 字节。示例：'{"ok":true}'
	 * @throws ResponseIntegrityException 任一校验失败。
	 */
	public function decryptEncryptedResponse(string $envelopeJson, Profile $profile);
	
	/**
	 * 校验 signed 模式响应签名契约。
	 *
	 * 使用范围：HttpClient.verifyResponse 在 mode=signed 时调用。
	 * 适用场景：明文响应的方向绑定 HMAC 防篡改证明。
	 *
	 * 函数逻辑：
	 * 1. 实现方断言固定 mode=signed 并读取独立响应签名 key_id。
	 * 2. 提取 X-Tozo-Response-Signature 头，重建原文常量时间比对；缺失/不符即抛异常。
	 *
	 * @param string $body 最终响应 Body｜原始字节。示例：'{"ok":true}'
	 * @param array $headers 响应 Header 数组｜名称=>值。示例：["X-Tozo-Response-Signature"=>"qE8f"]
	 * @param Profile $profile 出站 Profile｜提供 mode 与 key_id。示例：Profile::fromConfig(...)
	 * @return void 通过无返回值。
	 * @throws ResponseIntegrityException 缺少签名头或比较不一致。
	 */
	public function verifySignedResponse(string $body, array $headers, Profile $profile);
}
