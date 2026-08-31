<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * SecurityMakeKeyCommand
 *
 * 文件功能：
 * - artisan tozo:security:make-key：生成符合各用途长度要求的随机密钥
 * - 同时输出对应的环境变量名，消除 key_id 到变量名的手工推导错误
 *
 * 安全边界：
 * - 只生成并打印到标准输出；不写入 .env、不写入任何文件、不落日志
 * - 使用 random_bytes（CSPRNG）；不提供可预测的种子参数
 * - 不生成 RSA 密钥对：JWT 私钥必须由运维在受控环境用 openssl 生成，
 *   避免私钥经由应用进程与终端历史留下副本
 */

namespace Tozo\Security\Laravel\Command;

use Illuminate\Console\Command;
use Tozo\Security\Key\EnvKeyProvider;
use Tozo\Security\Encryption\AesGcmCipher;

class SecurityMakeKeyCommand extends Command
{
	/**
	 * 命令签名与选项定义。
	 *
	 * 三个选项各自解决一类误配：--usage 区分 hmac 与 aes 的长度约束（AES 必须恰好 32 字节）；
	 * --key-id 顺带输出对应环境变量名，消除手工推导错误；
	 * --bytes 允许 HMAC 加长但不允许短于 32。
	 * 与 tozo:security:install 的分工：本命令只生成单个密钥且不写盘，
	 * 适合轮换或临时补齐；批量生成走 install。
	 *
	 * @var string
	 */
	protected $signature = 'tozo:security:make-key
                            {--usage=hmac : 密钥用途：hmac（签名/认证）或 aes（AES-256-GCM 加密）}
                            {--key-id= : 目标 key_id，用于同时输出对应环境变量名}
                            {--bytes= : 覆盖默认长度（字节）；hmac 默认 32，aes 固定 32}';
	
	/**
	 * 命令描述。出现在 artisan list 中。
	 * 「不写入任何文件」必须写进描述里：它是本命令与 install 的核心差异，
	 * 也是运维判断能否在生产终端安全执行的依据——本命令只打印到标准输出，
	 * 因此密钥会留在终端历史里，需要执行者自行清理。
	 *
	 * @var string
	 */
	protected $description = 'Tozo Security 密钥生成：输出 CSPRNG 随机密钥与对应环境变量名（不写入任何文件）';
	
	/**
	 * 生成密钥并输出，附带环境变量名与安全提示。
	 *
	 * 使用范围：首次接入或密钥轮换时由运维手工执行。
	 * 适用场景：避免各系统自行用弱随机源（如 md5(time())）或长度不足的密钥。
	 *
	 * 函数逻辑：
	 * 1. 解析 usage 决定长度约束：aes 强制 32 字节；hmac 默认 32、允许显式加长。
	 * 2. random_bytes 生成后按 Base64 输出（可安全放入 .env 单行）。
	 * 3. 若提供 key-id，按 EnvKeyProvider 的推导规则打印变量名。
	 * 4. 打印不落盘、不复用、按用途隔离三条硬性提示。
	 *
	 * @return int 进程退出码｜0 成功，1 参数非法。示例：0
	 */
	public function handle()
	{
		$usage = strtolower((string)$this->option('usage'));
		
		if ($usage !== 'hmac' && $usage !== 'aes') {
			$this->error('--usage 只能是 hmac 或 aes');
			
			return 1;
		}
		
		$bytes = $this->resolveBytes($usage);
		if ($bytes === null) {
			return 1;
		}
		
		$key = $this->generateKey($bytes);
		
		$this->line('');
		$this->info("已生成 {$bytes} 字节随机密钥（字符串长度即字节长度，可直接写入 .env）：");
		$this->line('');
		$this->line('  ' . $key);
		$this->line('');
		
		$keyId = (string)$this->option('key-id');
		if ($keyId !== '') {
			$this->info('写入 .env（变量名已按 key_id 推导，无需手工转换）：');
			$this->line('');
			$this->line('  ' . $this->envName($keyId) . '=' . $key);
			$this->line('');
		} else {
			$this->comment('提示：加 --key-id=<你的 key_id> 可同时输出对应的环境变量名。');
			$this->line('');
		}
		
		$this->warn('安全要求：');
		$this->line('  1. 本命令不写入任何文件；请自行粘贴到部署环境的密钥管理中。');
		$this->line('  2. 请求签名、响应签名、请求加密、响应加密、Token 签发必须使用不同密钥。');
		$this->line('  3. 测试、预发布、生产环境必须使用不同密钥。');
		$this->line('  4. JWT RS256 私钥不由本命令生成，请用 openssl 在受控环境生成后经文件下发。');
		$this->line('');
		
		return 0;
	}
	
	/**
	 * 按用途解析并校验密钥长度。
	 *
	 * 使用范围：handle 内部调用。
	 * 适用场景：AES-256-GCM 要求恰好 32 字节，误配短密钥会在运行期才被 Cipher 拒绝；
	 *           这里提前拦住，避免生成出一个注定不可用的密钥。
	 *
	 * 函数逻辑：
	 * 1. aes：忽略并拒绝任何非 32 的显式长度。
	 * 2. hmac：默认 32；允许显式加长，但不允许短于 32（低于 HMAC-SHA256 输出长度即削弱强度）。
	 *
	 * @param string $usage 用途｜hmac 或 aes。示例："aes"
	 * @return int|null 字节长度；参数非法时返回 null（调用方据此返回 1）。示例：32
	 */
	private function resolveBytes(string $usage)
	{
		$override = $this->option('bytes');
		
		if ($usage === 'aes') {
			if ($override !== null && (int)$override !== AesGcmCipher::KEY_BYTES) {
				$this->error('AES-256-GCM 密钥必须恰好 ' . AesGcmCipher::KEY_BYTES . ' 字节，不接受 --bytes 覆盖');
				
				return null;
			}
			
			return AesGcmCipher::KEY_BYTES;
		}
		
		if ($override === null) {
			return 32;
		}
		
		$bytes = (int)$override;
		if ($bytes < 32) {
			$this->error('HMAC 密钥不得短于 32 字节');
			
			return null;
		}
		
		return $bytes;
	}
	
	/**
	 * 生成指定字节长度的随机密钥字符串。
	 *
	 * 使用范围：handle 在长度校验通过后调用。
	 * 适用场景：KeyProvider 返回的是环境变量的**字符串原文**，
	 *           AesGcmCipher 要求 strlen(key) === 32。因此不能输出
	 *           base64_encode(random_bytes(32))——那是 44 字符，会被解密器拒绝。
	 *           这里保证「字符串长度 == 目标字节长度」，写入 .env 后可直接使用。
	 *
	 * 函数逻辑：
	 * 1. 取足量随机字节做 Base64URL 编码（每字符承载 6 bit）。
	 * 2. 截断到恰好 $bytes 个字符；截断不引入偏置，熵为 6×$bytes bit。
	 * 3. 字符集限定 [A-Za-z0-9-_]，无引号、空格与 = 号，可安全放入 .env 单行。
	 *
	 * @param int $bytes 目标字节长度｜同时也是输出字符串的字符数。示例：32
	 * @return string 密钥字符串｜长度恰为 $bytes。示例："xK3p_Qm7..."（32 字符）
	 */
	private function generateKey(int $bytes)
	{
		// 每个 Base64 字符编码 6 bit，向上取整所需原始字节数后再截断。
		$raw     = random_bytes((int)ceil($bytes * 6 / 8) + 1);
		$encoded = rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
		
		return substr($encoded, 0, $bytes);
	}
	
	/**
	 * 按 EnvKeyProvider 的规则把 key_id 推导为环境变量名。
	 *
	 * 使用范围：handle 在提供 --key-id 时调用。
	 * 适用场景：手工推导容易漏掉大写或连字符转下划线，导致密钥"配了但读不到"。
	 *
	 * 函数逻辑：
	 * 1. 非字母数字字符替换为下划线后转大写，拼接 EnvKeyProvider 的统一前缀。
	 *
	 * @param string $keyId 密钥标识｜Profile 中引用的 key_id。示例："tozo-service-signing"
	 * @return string 完整环境变量名。示例："TOZO_SECURITY_KEY_TOZO_SERVICE_SIGNING"
	 */
	private function envName(string $keyId)
	{
		return EnvKeyProvider::DEFAULT_PREFIX
			. strtoupper((string)preg_replace('/[^A-Za-z0-9]/', '_', $keyId));
	}
}
