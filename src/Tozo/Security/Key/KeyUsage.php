<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * KeyUsage
 *
 * 文件功能：
 * - 密钥轮换状态机（设计 §15）：pending → active → verify_only/decrypt_only → retired
 * - 按用途断言状态可用性：
 *   · 签发/请求签名/加密（写方向）：仅 active
 *   · 验签/解密（读方向）：active + 对应迁移期旧版本
 * - 未知 key_id、retired 或状态不符一律明确报错，不尝试其他候选
 */

namespace Tozo\Security\Key;

use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\KeyNotFoundException;
use Tozo\Security\Contracts\KeyStateProviderInterface;

final class KeyUsage
{
	/**
	 * 轮换状态：已生成但尚未启用。任何用途都不可用——
	 * 存在的意义是让新密钥先完成分发，双方就绪后再切换为 active。
	 */
	public const STATE_PENDING = 'pending';
	
	/**
	 * 轮换状态：当前主用密钥。读写两个方向的全部用途都允许。
	 */
	public const STATE_ACTIVE = 'active';
	
	/**
	 * 轮换状态：只读迁移期（签名类）。可用于验签，但绝不可再生成新签名。
	 * 用于 HMAC 共享密钥或 JWT 公钥的短迁移窗口。
	 */
	public const STATE_VERIFY_ONLY = 'verify_only';
	
	/**
	 * 轮换状态：只读迁移期（加密类）。可用于解密历史密文，但不可再加密。
	 * 保留时长由仍需读取的存量密文决定。
	 */
	public const STATE_DECRYPT_ONLY = 'decrypt_only';
	
	/**
	 * 轮换状态：已退役。任何用途都必须拒绝，不允许任何"兼容性"例外。
	 */
	public const STATE_RETIRED = 'retired';
	
	/**
	 * 用途：生成请求或响应签名（写方向）。仅 active 状态允许。
	 * 写方向必须收紧到 active 的原因：用一把已进入退役流程的密钥生成新签名，
	 * 会让该密钥的有效期被无限延长，轮换永远无法真正完成。
	 * 与 USAGE_VERIFY 的区别正在此——验证可接受迁移期状态，生成不可以。
	 */
	public const USAGE_SIGN = 'sign';
	
	/**
	 * 用途：加密请求或响应载荷（写方向）。仅 active 状态允许。
	 * 与 USAGE_SIGN 同理：用退役中的密钥产出新密文，会让对端在完成轮换后
	 * 无法解密新数据。与 USAGE_DECRYPT 成对，后者接受 decrypt_only 以便读取历史密文。
	 */
	public const USAGE_ENCRYPT = 'encrypt';
	
	/**
	 * 用途：签发 Token（写方向）。仅 active 允许；私钥只存在于授权签发方。
	 */
	public const USAGE_ISSUE = 'issue';
	
	/**
	 * 用途：验证签名或 Token（读方向）。允许 active 与 verify_only 两种状态。
	 * 接受 verify_only 是轮换能够平滑进行的前提：切换期内对端可能仍在用旧密钥签名，
	 * 若验证侧立即拒绝旧密钥，轮换就必须停机完成。
	 * verify_only 表示「只收不发」，配合写方向仅接受 active，形成安全的单向迁移窗口。
	 */
	public const USAGE_VERIFY = 'verify';
	
	/**
	 * 用途：解密请求或响应载荷（读方向）。允许 active 与 decrypt_only 两种状态。
	 * decrypt_only 用于历史密文的读取窗口：密钥已不再用于加密新数据，
	 * 但存量密文仍需可解。与 verify_only 的区别只在作用的算法族（AEAD 与 HMAC/JWT），
	 * 状态机语义完全一致。
	 */
	public const USAGE_DECRYPT = 'decrypt';
	
	/**
	 * 禁止实例化。
	 *
	 * 使用范围：不被任何代码调用——private 构造器的存在本身就是约束。
	 * 适用场景：本类只提供无状态的静态断言方法，实例化没有任何意义；
	 *           把构造器设为 private 可让误用在编译期而非运行期暴露。
	 *
	 * 函数逻辑：
	 * 1. 空实现，仅用于阻断 new KeyUsage()。
	 *
	 * @return void 无返回值。
	 */
	private function __construct()
	{
		// 纯静态工具类，禁止实例化。
	}
	
	/**
	 * 按用途断言密钥轮换状态可用。
	 *
	 * 使用范围：HmacSha256Signer、AesGcmCipher、JwtTokenIssuer、JwtTokenVerifier 在检索密钥前调用。
	 * 适用场景：旧版本密钥标记 verify_only 后仍可验签但绝不能再签名；retired 密钥任何用途都拒绝。
	 *
	 * 函数逻辑：
	 * 1. 提供器未实现状态接口 → 视为全部 active 直接放行。
	 * 2. 读取 key_id 状态；按用途查允许集合：
	 *    sign/encrypt/issue=[active]；verify=[active,verify_only]；decrypt=[active,decrypt_only]。
	 * 3. 状态不在允许集 → KeyNotFoundException(reason=unknown_key_id)，消息含 key_id 与状态（非敏感）。
	 *
	 * @param KeyProviderInterface $provider 密钥提供器｜被检查的实例；无状态能力时跳过。示例：new ArrayKeyProvider([], ["old"=>"verify_only"])
	 * @param string $keyId 密钥标识｜用途密钥唯一标识。示例："order-signing"
	 * @param string $usage 用途常量｜KeyUsage::USAGE_* 之一。示例：KeyUsage::USAGE_SIGN
	 * @return void 无返回值。
	 * @throws KeyNotFoundException 状态不允许该用途（含 retired）。
	 */
	public static function assertUsable(KeyProviderInterface $provider, string $keyId, string $usage)
	{
		if (!$provider instanceof KeyStateProviderInterface) {
			// 无状态元数据的实现（Env/File）默认全部 active。
			return;
		}
		
		$state = $provider->getKeyState($keyId);
		
		switch ($usage) {
			case self::USAGE_SIGN:
			case self::USAGE_ENCRYPT:
			case self::USAGE_ISSUE:
				$allowed = [self::STATE_ACTIVE];
				break;
			
			case self::USAGE_VERIFY:
				$allowed = [self::STATE_ACTIVE, self::STATE_VERIFY_ONLY];
				break;
			
			case self::USAGE_DECRYPT:
				$allowed = [self::STATE_ACTIVE, self::STATE_DECRYPT_ONLY];
				break;
			
			default:
				$allowed = [];
				break;
		}
		
		if (!in_array($state, $allowed, true)) {
			// 消息只含 key_id 与状态，不含密钥内容。
			throw new KeyNotFoundException(
				"Key [{$keyId}] state [{$state}] is not usable for [{$usage}]",
				0,
				null,
				'unknown_key_id'
			);
		}
	}
}
