<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ArrayKeyProvider
 *
 * 文件功能：
 * - KeyProviderInterface 的内存数组实现
 * - 可选携带轮换状态映射，用于测试轮换状态机（设计 §15）
 * - 仅用于测试环境与本地开发，生产环境必须使用 Env/File/Vault/KMS 实现
 *
 * 安全边界：
 * - 设计文档明确该实现不得用于生产部署
 */

namespace Tozo\Security\Key;

use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\KeyNotFoundException;
use Tozo\Security\Contracts\KeyStateProviderInterface;

class ArrayKeyProvider implements KeyProviderInterface, KeyStateProviderInterface
{
	/**
	 * key_id 到密钥内容的内存映射。
	 * 仅供测试使用：内容随进程存在，进程重启即丢失，且明文驻留内存。
	 * production 环境下 ServiceProvider 直接拒绝该 driver，
	 * 防止测试密钥随代码路径泄漏到生产。
	 *
	 * @var array<string,string>
	 */
	private $keys;
	
	/**
	 * key_id 到轮换状态的映射，未声明的 key_id 视为 active。
	 * 只有本实现支持注入状态，env/file 两个 provider 不带状态元数据（全部视为 active）——
	 * 因此轮换状态机的用例只能靠本实现驱动。
	 * 默认视为 active 而非拒绝，是为了让不关心轮换的用例无需声明状态。
	 *
	 * @var array<string,string>
	 */
	private $states;
	
	/**
	 * 初始化内存密钥映射与可选状态。
	 *
	 * 使用范围：测试 harness 与 ServiceProvider array driver 装配时调用。
	 * 适用场景：测试需要确定性密钥与 verify_only/retired 等轮换场景模拟。
	 *
	 * 函数逻辑：
	 * 1. 保存 keys 与 states 两个映射。
	 *
	 * @param array $keys 密钥映射｜key_id=>内容。示例：['order-signing'=>str_repeat('a',32)]
	 * @param array $states 状态映射｜key_id=>状态。示例：['old-sign'=>'verify_only']
	 * @return void 无返回值。
	 */
	public function __construct(array $keys = [], array $states = [])
	{
		$this->keys   = $keys;
		$this->states = $states;
	}
	
	/**
	 * 从内存映射读取密钥。
	 *
	 * 使用范围：各安全模块检索密钥时调用（仅测试环境）。
	 * 适用场景：无需外部依赖即可注入确定性强钥。
	 *
	 * 函数逻辑：
	 * 1. 键不存在/非字符串/空串抛 KeyNotFoundException。
	 *
	 * @param string $keyId 密钥标识｜待检索项。示例："order-signing"
	 * @return string 密钥内容。示例："aaaaaaaa..."
	 * @throws KeyNotFoundException 缺失或为空。
	 */
	public function getKey(string $keyId)
	{
		if (!isset($this->keys[$keyId]) || !is_string($this->keys[$keyId]) || $this->keys[$keyId] === '') {
			throw new KeyNotFoundException("Key not found in array provider for key_id: {$keyId}");
		}
		
		return $this->keys[$keyId];
	}
	
	/**
	 * 判断密钥存在。
	 *
	 * 使用范围：ConfigChecker runtime 探测与测试预检。
	 * 适用场景：不触发异常路径的存在性判断。
	 *
	 * 函数逻辑：
	 * 1. isset 且为非空字符串即 true。
	 *
	 * @param string $keyId 密钥标识｜待检查项。示例："order-signing"
	 * @return bool true=存在且可用。示例：true
	 */
	public function hasKey(string $keyId)
	{
		return isset($this->keys[$keyId]) && is_string($this->keys[$keyId]) && $this->keys[$keyId] !== '';
	}
	
	/**
	 * 返回声明轮换状态。
	 *
	 * 使用范围：KeyUsage.assertUsable 状态断言。
	 * 适用场景：模拟 verify_only/decrypt_only/retired 迁移场景。
	 *
	 * 函数逻辑：
	 * 1. 未声明返回 active；否则返回声明值。
	 *
	 * @param string $keyId 密钥标识｜待查询项。示例："old-sign"
	 * @return string 状态枚举值。示例："verify_only"
	 */
	public function getKeyState(string $keyId)
	{
		// 未显式声明状态的密钥默认 active。
		return isset($this->states[$keyId]) && is_string($this->states[$keyId])
			? $this->states[$keyId]
			: KeyUsage::STATE_ACTIVE;
	}
}
