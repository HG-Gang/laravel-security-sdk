<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * KeyProviderInterface
 *
 * 文件功能：
 * - 定义按 key_id 读取真实密钥的统一契约
 * - 实现方负责从环境变量、受控文件、Vault/KMS 等来源获取密钥
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Exceptions\KeyNotFoundException;

interface KeyProviderInterface
{
	/**
	 * 检索真实密钥契约。
	 *
	 * 使用范围：Signer/Cipher/Issuer/Verifier 在轮换状态断言通过后调用。
	 * 适用场景：实现方从 Env/File/Vault 取回密钥材料，调用方不感知来源。
	 *
	 * 函数逻辑：
	 * 1. 实现方按 keyId 定位密钥。
	 * 2. 缺失或空值必须抛 KeyNotFoundException，禁止返回默认密钥或空串。
	 *
	 * @param string $keyId 密钥标识｜用途密钥唯一标识。示例："order-api-signing"
	 * @return string 密钥原始内容｜HMAC 字节或 PEM 文本。示例："32字节随机串" 或 PEM 文本
	 * @throws KeyNotFoundException 缺失/为空/读取失败。
	 */
	public function getKey(string $keyId);
	
	/**
	 * 存在性预检契约。
	 *
	 * 使用范围：ConfigChecker runtime 探测与启动期预检。
	 * 适用场景：不触发异常路径、不泄露内容地确认密钥可解析。
	 *
	 * 函数逻辑：
	 * 1. 实现方返回 keyId 是否存在且非空。
	 *
	 * @param string $keyId 密钥标识｜待检查项。示例："order-api-signing"
	 * @return bool true=存在且可用。示例：true
	 */
	public function hasKey(string $keyId);
}
