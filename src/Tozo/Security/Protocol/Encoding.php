<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Encoding
 *
 * 文件功能：
 * - Protocol v1 统一 Base64URL 编解码工具（无 padding，RFC 4648 §5）
 * - 严格模式解码：非法字符或长度不合法时返回 null，由调用方失败关闭
 */

namespace Tozo\Security\Protocol;

class Encoding
{
	/**
	 * Base64URL 编码。
	 *
	 * 使用范围：签名值、信封 iv/ciphertext/tag、HMAC-Bearer proof 输出。
	 * 适用场景：二进制材料进入 Header/JSON 场景——+//= 不安全，统一转 -_ 并去 padding。
	 *
	 * 函数逻辑：
	 * 1. base64_encode 后 strtr('+/','-_')，rtrim 去除 '='。
	 *
	 * @param string $raw 原始字节｜待编码二进制内容。示例：hash_hmac(...,true) 的二进制结果
	 * @return string Base64URL 文本（无 padding）。示例："qE8f2w"
	 */
	public static function base64UrlEncode(string $raw)
	{
		return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
	}
	
	/**
	 * 严格 Base64URL 解码。
	 *
	 * 使用范围：验签与信封解密前还原二进制字段。
	 * 适用场景：攻击者注入非法字符时返回 null 而非宽松解出错误字节，避免后续校验失真。
	 *
	 * 函数逻辑：
	 * 1. 空串或含 [A-Za-z0-9-_] 之外字符 → null。
	 * 2. 补齐 '=' 到 4 的倍数，strtr 回标准表后 base64_decode(strict)。
	 *
	 * @param string $encoded Base64URL 串｜待解码文本。示例："qE8f2w"
	 * @return string|null 解码后的原始字节；非法输入返回 null。示例："qE8f2w" 解出的二进制原文
	 */
	public static function base64UrlDecode(string $encoded)
	{
		if ($encoded === '' || preg_match('/^[A-Za-z0-9\-_]+$/', $encoded) !== 1) {
			return null;
		}
		
		$padded  = $encoded . str_repeat('=', (4 - strlen($encoded) % 4) % 4);
		$decoded = base64_decode(strtr($padded, '-_', '+/'), true);
		
		return $decoded === false ? null : $decoded;
	}
}
