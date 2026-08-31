<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * KeyStateProviderInterface
 *
 * 文件功能：
 * - 可选能力接口：声明密钥轮换状态（设计 §15 状态机）
 * - KeyUsage 依据该接口决定写方向/读方向可用性；未实现的提供器视为全部 active
 */

namespace Tozo\Security\Contracts;

interface KeyStateProviderInterface
{
	/**
	 * 返回密钥轮换状态契约。
	 *
	 * 使用范围：KeyUsage.assertUsable 在写/读方向断言前调用。
	 * 适用场景：旧版本公钥标记 verify_only 后仍可验签但禁止再签名；retired 全拒。
	 *
	 * 函数逻辑：
	 * 1. 实现方返回 pending/active/verify_only/decrypt_only/retired 之一；未声明默认 active。
	 *
	 * @param string $keyId 密钥标识｜待查询项。示例："old-signing-key"
	 * @return string 轮换状态枚举值。示例："verify_only"
	 */
	public function getKeyState(string $keyId);
}
