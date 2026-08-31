<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * DummyKeyProvider
 *
 * 文件功能：
 * - ConfigChecker 结构校验阶段的占位密钥提供器
 * - 结构级不读取真实密钥：任何 getKey 调用都抛异常以暴露越权读取路径
 *
 * 安全边界：
 * - 仅用于结构体检；运行时探测必须传入真实 KeyProvider
 */

namespace Tozo\Security\Support;

use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\KeyNotFoundException;

class DummyKeyProvider implements KeyProviderInterface
{
	/**
	 * 结构校验占位：拒绝读取真实密钥。
	 *
	 * 使用范围：ConfigChecker.check 构造后传入 Profile::fromConfig 做纯结构校验。
	 * 适用场景：体检阶段任何代码路径试图读取真实密钥时立即暴露越权读取。
	 *
	 * 函数逻辑：
	 * 1. 无条件抛出 KeyNotFoundException，阻断对真实密钥的访问。
	 *
	 * @param string $keyId 密钥标识｜仅用于异常上下文，不参与查找。示例："order-signing"
	 * @return string 无返回｜该方法永不正常返回。示例：无（恒抛 KeyNotFoundException）
	 * @throws KeyNotFoundException 结构校验阶段禁止读取真实密钥。
	 */
	public function getKey(string $keyId)
	{
		throw new KeyNotFoundException('Structural check must not read real keys');
	}
	
	/**
	 * 结构校验占位：一律报告密钥不存在。
	 *
	 * 使用范围：作为 KeyProviderInterface 占位实现注入 Profile::fromConfig（ConfigChecker 结构链路）。
	 * 适用场景：保证结构体检不触发真实密钥源访问；runtime 存在性探测须换真实 KeyProvider。
	 *
	 * 函数逻辑：
	 * 1. 无条件返回 false，表示占位提供器不含任何密钥。
	 *
	 * @param string $keyId 密钥标识｜仅满足接口签名。示例："order-signing"
	 * @return bool 恒为 false｜占位器永远“不存在”。示例：false
	 */
	public function hasKey(string $keyId)
	{
		return false;
	}
}
