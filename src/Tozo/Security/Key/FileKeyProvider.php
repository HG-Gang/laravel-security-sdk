<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * FileKeyProvider
 *
 * 文件功能：
 * - KeyProviderInterface 的受控文件实现，适合 RSA PEM 等较大密钥
 * - 从受控目录按 {key_id}.key 读取密钥内容
 *
 * 安全边界：
 * - 目录必须由部署方控制权限；SDK 不创建目录、不生成密钥
 * - 拒绝目录穿越：解析后的真实路径必须仍位于受控目录内
 * - 文件缺失、不可读或内容为空一律抛出 KeyNotFoundException
 */

namespace Tozo\Security\Key;

use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\KeyNotFoundException;
use Tozo\Security\Exceptions\ConfigurationException;

class FileKeyProvider implements KeyProviderInterface
{
	/**
	 * @var string 受控密钥目录（构造时给定的原始路径，未做 realpath 规范化）。
	 */
	private $keyDir;
	
	/**
	 * 构造并记录受控目录。
	 *
	 * 使用范围：ServiceProvider 创建 file driver 单例时调用。
	 * 适用场景：RSA PEM 等大密钥经环境变量传递不便，改由运维管控的目录下发。
	 *
	 * 函数逻辑：
	 * 1. dir 为空时 Laravel 下回退 storage_path('app/tozo/keys')；非 Laravel 抛配置异常。
	 * 2. 只记录路径，不校验目录是否存在。
	 *
	 * 为什么不在此校验目录存在性：
	 * 本类由 ServiceProvider 在构建 Profile 注册表时解析，而密钥目录是由
	 * tozo:security:install 命令创建的。若构造期就要求目录存在，全新安装将陷入死锁——
	 * artisan 因目录缺失而无法启动，于是那条创建目录的命令永远跑不起来。
	 * 目录缺失改由 getKey 在检索期报 KeyNotFoundException，
	 * 使 check-config --runtime 能列出干净的错误清单而不是直接崩掉。
	 *
	 * @param string|null $keyDir 密钥目录｜受控绝对路径；null 走 Laravel 默认。示例："C:\\secrets\\tozo-keys"
	 * @return void 无返回值。
	 * @throws ConfigurationException 非 Laravel 环境且未提供目录。
	 */
	public function __construct(string $keyDir = null)
	{
		if ($keyDir === null || $keyDir === '') {
			if (function_exists('storage_path')) {
				$keyDir = storage_path('app/tozo/keys');
			} else {
				throw new ConfigurationException('FileKeyProvider requires an explicit key directory outside Laravel');
			}
		}
		
		$this->keyDir = $keyDir;
	}
	
	/**
	 * 判断密钥文件是否存在且可读。
	 *
	 * 使用范围：ConfigChecker runtime 探测与启动期预检。
	 * 适用场景：静默预检不泄露路径细节以外的信息。
	 *
	 * 函数逻辑：
	 * 1. try getKey；捕获 KeyNotFound 返回 false。
	 *
	 * @param string $keyId 密钥标识｜待检查项。示例："jwt-public-2026-08"
	 * @return bool true=可读且非空。示例：true
	 */
	public function hasKey(string $keyId)
	{
		try {
			$this->getKey($keyId);
			
			return true;
		} catch (KeyNotFoundException $e) {
			return false;
		}
	}
	
	/**
	 * 受控目录内读取 {key_id}.key。
	 *
	 * 使用范围：Signer/Cipher/Verifier 检索 PEM 或对称密钥时调用。
	 * 适用场景：JWT RS256 公私钥以文件下发，内容含换行需剥离行尾。
	 *
	 * 函数逻辑：
	 * 1. key_id 必须匹配安全字符白名单（防穿越）。
	 * 2. realpath 后必须仍位于受控目录前缀下。
	 * 3. 可读性检查后读取；rtrim 行尾；空内容视为缺失抛异常。
	 *
	 * @param string $keyId 密钥标识｜对应文件名（不含 .key）。示例："jwt-public-2026-08"
	 * @return string 密钥内容｜已去除行尾换行。示例："-----BEGIN PUBLIC KEY-----..."
	 * @throws KeyNotFoundException 非法 id/文件缺失/不可读/内容为空。
	 */
	public function getKey(string $keyId)
	{
		// key_id 仅允许安全字符，防止拼接出穿越路径。
		if (!preg_match('/^[A-Za-z0-9._-]+$/', $keyId)) {
			throw new KeyNotFoundException("Illegal key_id format: {$keyId}");
		}
		
		// 受控目录在此规范化：前缀比较的两侧必须同为 realpath 结果，
		// 否则分隔符或符号链接差异会让合法密钥被误判为穿越攻击。
		$baseDir = realpath($this->keyDir);
		if ($baseDir === false || !is_dir($baseDir)) {
			throw new KeyNotFoundException("Key directory does not exist: {$this->keyDir}");
		}
		
		$realPath = realpath($baseDir . DIRECTORY_SEPARATOR . $keyId . '.key');
		
		// 目录穿越防护：realpath 必须仍在受控目录前缀之下。
		if ($realPath === false || strpos($realPath, $baseDir . DIRECTORY_SEPARATOR) !== 0) {
			throw new KeyNotFoundException("Key file not found for key_id: {$keyId}");
		}
		
		if (!is_readable($realPath)) {
			throw new KeyNotFoundException("Key file not readable for key_id: {$keyId}");
		}
		
		$content = file_get_contents($realPath);
		if ($content === false) {
			throw new KeyNotFoundException("Key file read failed for key_id: {$keyId}");
		}
		
		// 去除编辑器引入的行尾换行；空内容视为密钥缺失而非空密钥。
		$content = rtrim($content, "\r\n");
		if ($content === '') {
			throw new KeyNotFoundException("Key file is empty for key_id: {$keyId}");
		}
		
		return $content;
	}
}
