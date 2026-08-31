<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * EnvKeyProvider
 *
 * 文件功能：
 * - KeyProviderInterface 的环境变量实现
 * - 按 key_id 映射环境变量：{prefix}{KEY_ID 大写下划线形式}
 *   例：key_id=product-center-signing → TOZO_SECURITY_KEY_PRODUCT_CENTER_SIGNING
 *
 * 安全边界：
 * - 生产密钥必须通过环境变量注入，禁止写入配置文件或代码
 * - 变量缺失或为空字符串一律抛出 KeyNotFoundException，不回退默认值
 * - 异常消息只包含环境变量名（非敏感），绝不包含密钥内容
 */

namespace Tozo\Security\Key;

use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\KeyNotFoundException;

class EnvKeyProvider implements KeyProviderInterface
{
	/**
	 * 密钥环境变量统一前缀；与 key_id 类环境变量（*_KEY_ID）隔离，避免误用。
	 */
	public const DEFAULT_PREFIX = 'TOZO_SECURITY_KEY_';
	
	/**
	 * 环境变量名前缀。与 *_KEY_ID 这类「标识」变量隔离，
	 * 使「密钥值」与「密钥标识」在变量命名空间上不会混淆。
	 * 完整变量名 = 前缀 + key_id 大写下划线化，该推导规则是 SDK 与部署方之间的契约：
	 * 手工推导错误的表现是「配了但读不到」的 KeyNotFoundException。
	 *
	 * @var string
	 */
	private $prefix;
	
	/**
	 * 构造并指定变量前缀。
	 *
	 * 使用范围：ServiceProvider 创建 env driver 单例、测试定制前缀时调用。
	 * 适用场景：多套环境（测试/生产）使用不同前缀隔离密钥空间。
	 *
	 * 函数逻辑：
	 * 1. 保存前缀；缺省 TOZO_SECURITY_KEY_。
	 *
	 * @param string $prefix 环境变量前缀｜统一前缀。示例："TOZO_SECURITY_KEY_"
	 * @return void 无返回值。
	 */
	public function __construct(string $prefix = self::DEFAULT_PREFIX)
	{
		$this->prefix = $prefix;
	}
	
	/**
	 * 判断环境变量是否存在。
	 *
	 * 使用范围：ConfigChecker runtime 探测与启动期预检。
	 * 适用场景：不泄露内容地确认密钥可解析。
	 *
	 * 函数逻辑：
	 * 1. try getKey；捕获 KeyNotFound 返回 false。
	 *
	 * @param string $keyId 密钥标识｜待检查项。示例："order-api-signing"
	 * @return bool true=存在且非空。示例：true
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
	 * 按前缀+规范化 key_id 读取环境变量密钥。
	 *
	 * 使用范围：Signer/Cipher/Issuer 检索密钥材料时调用。
	 * 适用场景：生产密钥经部署环境注入，缺失或空串立即失败不回退。
	 *
	 * 函数逻辑：
	 * 1. envName 规范化生成变量名。
	 * 2. env() 读取；null/'' 抛 KeyNotFoundException（消息仅含变量名，不含值）。
	 *
	 * @param string $keyId 密钥标识｜用途密钥唯一标识。示例："order-api-signing"
	 * @return string 密钥原始内容。示例："32字节随机串"
	 * @throws KeyNotFoundException 变量缺失或为空。
	 */
	public function getKey(string $keyId)
	{
		$envName = $this->envName($keyId);
		// env() 由 illuminate/support 提供；null 表示未定义，'' 表示显式置空，两者都视为密钥缺失。
		$value = function_exists('env') ? env($envName) : getenv($envName);
		
		if ($value === false || $value === null || $value === '') {
			throw new KeyNotFoundException("Environment key [{$envName}] for key_id [{$keyId}] is missing or empty");
		}
		
		return (string)$value;
	}
	
	/**
	 * 将 key_id 规范化为环境变量名。
	 *
	 * 使用范围：getKey 内部调用。
	 * 适用场景：特殊字符统一转下划线并大写，保证变量名合法。
	 *
	 * 函数逻辑：
	 * 1. 非字母数字替换为 '_' 后 strtoupper，拼接到前缀之后。
	 *
	 * @param string $keyId 密钥标识｜原始 id。示例："order.api-signing"
	 * @return string 完整环境变量名。示例："TOZO_SECURITY_KEY_ORDER_API_SIGNING"
	 */
	private function envName(string $keyId)
	{
		return $this->prefix . strtoupper((string)preg_replace('/[^A-Za-z0-9]/', '_', $keyId));
	}
}
