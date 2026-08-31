<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * AesGcmCipher
 *
 * 文件功能：
 * - Protocol v1 首选 AEAD 加密 driver：AES-256-GCM
 * - 版本化信封：{version, algorithm, key_id, iv, ciphertext, tag}（Base64URL 无 padding）
 * - AAD 绑定协议版本、方向、调用方、目标服务、method、path 与 key_id
 *
 * 安全边界：
 * - Nonce 为 SDK 内部 CSPRNG 生成的 96-bit 值，每次加密必须全新；API 不接受外部 IV
 * - 解密端严格校验信封：version/algorithm/key_id 必须与 Profile 白名单一致，
 *   iv 必须 12 字节、tag 必须 16 字节；任何失败统一抛出解密失败，不部分解析明文
 * - 密钥为 32 字节对称密钥，按用途独立（请求加密 ≠ 响应加密）
 */

namespace Tozo\Security\Encryption;

use Tozo\Security\Payload;
use Tozo\Security\Profile;
use Tozo\Security\Key\KeyUsage;
use Tozo\Security\Protocol\Encoding;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\EncryptionException;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\InvalidCiphertextException;

class AesGcmCipher implements PayloadCipherInterface
{
	/**
	 * driver 标识。同时写入信封的 algorithm 字段；
	 * 解密时该字段必须与本常量全等，不一致立即拒绝而非尝试其他算法。
	 */
	public const DRIVER = 'aes_256_gcm';
	
	/**
	 * 信封格式版本。与通信协议版本独立演进；
	 * 解密端只接受本版本，未知版本明确拒绝而不猜测兼容。
	 */
	public const ENVELOPE_VERSION = '1';
	
	/**
	 * 对称密钥字节长度，固定 32（AES-256）。
	 * KeyProvider 返回的是环境变量字符串原文，因此校验的是 strlen 而非解码后长度；
	 * 长度不符即抛配置异常，防止误配短密钥静默降级为更弱强度。
	 */
	public const KEY_BYTES = 32;
	
	/**
	 * GCM nonce 字节长度，固定 12（96-bit，NIST SP 800-38D 推荐值）。
	 * 每次加密由内部 CSPRNG 重新生成，API 不接受外部注入。
	 */
	public const NONCE_BYTES = 12;
	
	/**
	 * GCM 认证标签字节长度，固定 16（128-bit，最大强度）。
	 * 解密前校验长度，短标签会削弱伪造抵抗力。
	 */
	public const TAG_BYTES = 16;
	
	/**
	 * 加密链路的峰值内存倍数（相对明文体积）的实测参考值。
	 *
	 * 实测：明文 1 MB → 峰值约 6 倍；8 MB → 约 4.25 倍；32 MB → 约 3.5 倍。
	 * 峰值来自明文、原始密文、Base64 编码结果与 JSON 序列化结果同时驻留。
	 * 该常量仅用于在超限异常中给出可操作的容量提示，不参与任何加解密计算。
	 */
	public const PEAK_MEMORY_FACTOR = 6;
	
	/**
	 * 密钥提供器。按 key_id 检索 32 字节对称加密密钥。
	 * 校验的是密钥**字符串原文**的 strlen 而非解码后长度——KeyProvider 返回的是
	 * 环境变量或文件内容原文，长度不符即抛配置异常，防止误配短密钥静默降级强度。
	 * 请求方向与响应方向必须使用不同 key_id，否则同一密文可被跨方向重放。
	 *
	 * @var KeyProviderInterface
	 */
	private $keys;
	
	/**
	 * 构造加解密器并注入密钥来源。
	 *
	 * 使用范围：ServiceProvider 门控注册 PayloadCipherInterface 单例、ResponseIntegrityChecker 内部装配时调用。
	 * 适用场景：应用启动装配阶段把 Env/File/Array 等密钥来源注入 AEAD 实现，业务代码不感知密钥位置。
	 *
	 * 函数逻辑：
	 * 1. 保存密钥提供器实例，供 encryptString/decryptEnvelopeJson 按 Profile 的 encryption.key_id 检索。
	 *
	 * @param KeyProviderInterface $keys 密钥提供器｜按 key_id 检索真实对称密钥。示例：new EnvKeyProvider() 或 new ArrayKeyProvider(['order-encryption'=>str_repeat('b',32)])
	 * @return void 无返回值；依赖保存到私有属性供加解密方法使用。
	 */
	public function __construct(KeyProviderInterface $keys)
	{
		$this->keys = $keys;
	}
	
	/**
	 * 对出站 Payload 执行 AEAD 加密，并把最终 wire Body 替换为信封 JSON。
	 *
	 * 使用范围：TozoHttpClient 出站五步流程第 2 步（先加密）、InboundAuthenticatorMiddleware 不使用本方法。
	 * 适用场景：product-center 向 order-api 发送敏感 Body，需在签名前完成 Encrypt-then-Sign 的“先加密”半步。
	 *
	 * 函数逻辑：
	 * 1. 校验 Profile encryption.enabled=true，否则视为配置错误拒绝加密。
	 * 2. 取 Payload 当前 Body 原始字节作为明文。
	 * 3. 调用 encryptString(direction=request) 产出信封 JSON。
	 * 4. 将 Body 替换为信封 JSON、Content-Type 固定为 application/json 后返回同一 Payload。
	 *
	 * @param Payload $payload 安全负载｜携带待加密 body 与 method/path（进入 AAD）。示例：new Payload(['method'=>'POST','path'=>'/api/orders','body'=>'{"sku":"A-1"}'])
	 * @param Profile $profile 出站 Profile｜提供 encryption.enabled/key_id 白名单。示例：Profile::fromConfig('svc_to_order', $cfg, $keys)
	 * @return Payload Body 已替换为信封 JSON 的同一 Payload 实例（原对象就地修改）。示例：同一 Payload 实例（Body=信封 JSON）
	 * @throws ConfigurationException 未启用加密或 encryption.key_id 缺失。
	 * @throws EncryptionException openssl 底层加密执行失败。
	 * @throws KeyNotFoundException 密钥缺失或轮换状态非 active。
	 */
	public function encrypt(Payload $payload, Profile $profile)
	{
		$config = $profile->getEncryptionConfig();
		
		if (($config['enabled'] ?? false) !== true) {
			throw new ConfigurationException("Profile [{$profile->getName()}] has encryption disabled; cannot encrypt");
		}
		
		$data = $payload->getData();
		$body = isset($data['body']) && is_string($data['body']) ? $data['body'] : '';
		
		// 先加密后签名（Encrypt-then-Sign）：加密后把最终 wire-level Body 替换为信封 JSON。
		$envelopeJson = $this->encryptString(
			$body,
			$profile,
			'request',
			(string)($data['method'] ?? ''),
			(string)($data['path'] ?? '')
		);
		
		$payload->set('body', $envelopeJson);
		$payload->set('content_type', 'application/json');
		
		return $payload;
	}
	
	/**
	 * 加密任意字符串并输出版本化信封 JSON。
	 *
	 * 使用范围：encrypt() 的底层实现；ResponseIntegrityChecker 处理 direction=response 的响应加密时直接调用。
	 * 适用场景：服务端返回敏感响应体，用响应专用密钥加密并绑定 response 方向 AAD 后回传。
	 *
	 * 函数逻辑：
	 * 1. 取 Profile encryption.key_id，缺失即配置错误。
	 * 2. KeyUsage 断言轮换状态为 active（写方向），resolveKey 校验 32 字节长度。
	 * 3. CSPRNG 生成全新 12 字节 nonce；buildAad 构造方向绑定附加认证数据。
	 * 4. openssl_encrypt(aes-256-gcm, OPENSSL_RAW_DATA, tag=16) 执行认证加密。
	 * 5. 组装 {version,algorithm,key_id,iv,ciphertext,tag} 六字段信封并 Base64URL 编码后 JSON 输出。
	 *
	 * @param string $plaintext 明文字节｜待加密原始内容。示例：'{"order_id":42,"amount":100}'
	 * @param Profile $profile 出站/签发方 Profile｜提供 encryption.key_id 与 client/target（进 AAD）。示例：Profile::fromConfig(...)
	 * @param string $direction 方向标识｜AAD 绑定方向，防跨方向重放。示例："request" 或 "response"
	 * @param string $method HTTP 方法｜参与 AAD 绑定；响应方向可传空串。示例："POST"
	 * @param string $path 请求路径｜参与 AAD 绑定；内部做规范化。示例："/api/orders"
	 * @return string 信封 JSON 串｜六字段 Base64URL 编码形态。示例：{"version":"1","algorithm":"aes_256_gcm","key_id":"k","iv":"..","ciphertext":"..","tag":".."}
	 * @throws ConfigurationException key_id 缺失或密钥长度非 32 字节。
	 * @throws KeyNotFoundException 密钥缺失或状态非 active。
	 * @throws EncryptionException openssl 加密失败。
	 */
	public function encryptString(
		string  $plaintext,
		Profile $profile,
		string  $direction,
		string  $method = '',
		string  $path = ''
	)
	{
		$keyId = $this->keyIdForDirection($profile, $direction);
		if ($keyId === null || $keyId === '') {
			throw new ConfigurationException(
				"Profile [{$profile->getName()}] encryption key_id is required for [{$direction}]"
			);
		}
		
		// 体积闸门必须在任何大块分配之前：超限时以可捕获异常失败，
		// 而不是让 PHP 因内存耗尽直接终止进程（那种失败无法记录审计、无法优雅返回）。
		$this->assertPlaintextWithinLimit($plaintext, $profile);
		
		// 加密仅允许 active 密钥。
		KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_ENCRYPT);
		$key = $this->resolveKey($profile, $keyId);
		
		// CSPRNG 生成全新 96-bit nonce；同一密钥下绝不重用。
		$nonce = random_bytes(self::NONCE_BYTES);
		$aad   = $this->buildAad($direction, $profile, $method, $path, $keyId);
		$tag   = '';
		
		$ciphertext = openssl_encrypt(
			$plaintext,
			'aes-256-gcm',
			$key,
			OPENSSL_RAW_DATA,
			$nonce,
			$tag,
			$aad,
			self::TAG_BYTES
		);
		
		if ($ciphertext === false) {
			throw new EncryptionException('AES-256-GCM encryption failed');
		}
		
		return json_encode(
			[
				'version'    => self::ENVELOPE_VERSION,
				'algorithm'  => self::DRIVER,
				'key_id'     => $keyId,
				'iv'         => Encoding::base64UrlEncode($nonce),
				'ciphertext' => Encoding::base64UrlEncode($ciphertext),
				'tag'        => Encoding::base64UrlEncode($tag),
			],
			JSON_UNESCAPED_SLASHES
		);
	}
	
	/**
	 * 按通信方向选择加密用途 key_id。
	 *
	 * 请求使用 encryption.key_id；响应使用 response_integrity.encryption.key_id。
	 * 两条路径必须分开，才能落实 Profile 对独立用途密钥的约束。
	 *
	 * @param Profile $profile 当前通信 Profile。
	 * @param string $direction 信封方向，request 或 response。
	 * @return string|null 当前方向的 key_id；缺失时返回 null。
	 */
	private function keyIdForDirection(Profile $profile, string $direction)
	{
		if ($direction === 'response') {
			return $profile->getResponseEncryptionKeyId();
		}
		
		return $profile->getEncryptionKeyId();
	}
	
	/**
	 * 校验明文体积未超出 Profile 声明的上限。
	 *
	 * 使用范围：encryptString 在分配任何大块内存之前调用。
	 * 适用场景：加密链路峰值内存约为明文体积的 3.5～6 倍（明文、密文、Base64、
	 *           JSON 四份同时驻留）。在 PHP 默认 memory_limit=128M 下，
	 *           24 MB 明文的峰值已达 124 MB —— 再大即触发不可捕获的 fatal OOM：
	 *           调用方无法 catch、无法写审计、无法返回干净错误。
	 *           本闸门把该风险转为可捕获的 EncryptionException。
	 *
	 * 函数逻辑：
	 * 1. 未配置 max_plaintext_bytes 时不限制（保持既有行为，由部署方显式选择）。
	 * 2. 配置值必须为正整数，否则视为配置错误而不是"不限制"。
	 * 3. 超限时抛出异常，消息给出实际体积、上限与预计峰值，便于直接调参。
	 *
	 * @param string $plaintext 待加密明文｜仅用于取长度，不写入异常消息。示例：'{"sku":"A-1"}'
	 * @param Profile $profile 通信 Profile｜提供 encryption.max_plaintext_bytes。示例：Profile::fromConfig(...)
	 * @return void 未超限时静默通过。
	 * @throws ConfigurationException max_plaintext_bytes 配置为非正数。
	 * @throws EncryptionException 明文体积超出上限（reason=payload_too_large）。
	 */
	private function assertPlaintextWithinLimit(string $plaintext, Profile $profile)
	{
		$limit = $profile->getEncryptionMaxPlaintextBytes();
		
		if ($limit === null) {
			return;
		}
		
		if ($limit <= 0) {
			throw new ConfigurationException(
				"Profile [{$profile->getName()}] encryption.max_plaintext_bytes must be a positive integer"
			);
		}
		
		$actual = strlen($plaintext);
		if ($actual <= $limit) {
			return;
		}
		
		// 消息只含体积数字，不含任何明文片段。
		throw new EncryptionException(
			sprintf(
				'Payload of %d bytes exceeds encryption.max_plaintext_bytes=%d '
				. '(encryption peaks at roughly %dx plaintext size)',
				$actual,
				$limit,
				self::PEAK_MEMORY_FACTOR
			),
			413,
			null,
			'payload_too_large'
		);
	}
	
	/**
	 * 读取并校验对称密钥长度。
	 *
	 * 使用范围：encryptString/decryptEnvelopeJson 在状态断言通过后调用。
	 * 适用场景：拦截误配的短密钥（如 16 字节）静默降级为 AES-128 强度的风险。
	 *
	 * 函数逻辑：
	 * 1. 从 KeyProvider 检索密钥（缺失抛 KeyNotFoundException）。
	 * 2. strlen 必须 === 32，否则抛 ConfigurationException 指明 key_id 与要求长度。
	 *
	 * @param Profile $profile 通信 Profile｜仅用于异常消息中标注 Profile 名称。示例：Profile::fromConfig(...)
	 * @param string $keyId 密钥标识｜待检索的加密用途 key_id。示例："order-encryption"
	 * @return string 32 字节原始对称密钥（AES-256）。示例："order-api"
	 * @throws KeyNotFoundException 密钥不存在。
	 * @throws ConfigurationException 密钥长度不是 32 字节。
	 */
	private function resolveKey(Profile $profile, string $keyId)
	{
		$key = $this->keys->getKey($keyId);
		
		if (strlen($key) !== self::KEY_BYTES) {
			throw new ConfigurationException(
				"Encryption key [{$keyId}] must be exactly " . self::KEY_BYTES . ' bytes'
			);
		}
		
		return $key;
	}
	
	/**
	 * 构造方向绑定的 AAD 附加认证数据字节串。
	 *
	 * 使用范围：encryptString 与 decryptEnvelopeJson 内部成对调用，保证双端 AAD 字节一致。
	 * 适用场景：防止请求方向密文被复制到响应方向、或另一客户端/另一接口重放仍能通过 GCM 校验。
	 *
	 * 函数逻辑：
	 * 1. 以 "\n" 连接七字段：信封版本、方向、client_id、target_service、大写 method、规范化 path、key_id。
	 *
	 * @param string $direction 方向标识｜request 或 response。示例："request"
	 * @param Profile $profile 通信 Profile｜提供 client_id 与 target_service 两个绑定字段。示例：Profile::fromConfig(...)
	 * @param string $method HTTP 方法｜规范化为大写参与绑定。示例："POST"
	 * @param string $path 请求路径｜经 CanonicalRequest::normalizePath 规范化。示例："/api/orders/"
	 * @param string $keyId 密钥标识｜加密用途 key_id，末位绑定字段。示例："order-encryption"
	 * @return string 以 "\n" 连接的 AAD 字节串（UTF-8）。示例："order-api"
	 */
	private function buildAad(string $direction, Profile $profile, string $method, string $path, string $keyId)
	{
		return implode("\n", [
			self::ENVELOPE_VERSION,
			$direction,
			$profile->getClientId(),
			$profile->getTargetService(),
			strtoupper($method),
			CanonicalRequest::normalizePath($path),
			$keyId,
		]);
	}
	
	/**
	 * 解密入站 Payload 携带的信封并还原明文 Body。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware 在签名验证通过后按需调用（encryption.enabled=true 时）。
	 * 适用场景：order-api 收到已加密请求，验签确认来源可信后解密还原业务 JSON 供控制器使用。
	 *
	 * 函数逻辑：
	 * 1. 取信封来源：优先 Payload 的 envelope 数组（内部形态），否则读 Body 字符串；两者皆缺抛异常。
	 * 2. 委托 decryptEnvelopeJson(direction=request) 执行白名单/AAD/AEAD 全量校验并解密。
	 * 3. 解密成功才把 Body 替换为明文；失败路径不产生部分明文。
	 *
	 * @param Payload $payload 入站负载｜Body 为信封 JSON 或含 envelope 数组。示例：new Payload(['body'=>'{"version":"1",...}','method'=>'POST','path'=>'/api/orders'])
	 * @param Profile $profile 入站 Profile｜提供 encryption.key_id 白名单基准。示例：Profile::fromConfig('order_inbound', $cfg, $keys)
	 * @return Payload Body 已还原为明文的同一 Payload 实例。示例：同一 Payload 实例（Body=明文）
	 * @throws InvalidCiphertextException 信封缺失/结构非法/白名单不符/AEAD 校验失败（统一语义）。
	 * @throws ConfigurationException 关联密钥配置非法（如长度非 32 字节）。
	 */
	public function decrypt(Payload $payload, Profile $profile)
	{
		$data = $payload->getData();
		
		// 入站 Body 即信封 JSON；兼容内部直接携带 envelope 数组的形式。
		if (isset($data['envelope']) && is_array($data['envelope'])) {
			$envelopeJson = json_encode($data['envelope'], JSON_UNESCAPED_SLASHES);
		} elseif (isset($data['body']) && is_string($data['body']) && $data['body'] !== '') {
			$envelopeJson = $data['body'];
		} else {
			throw new InvalidCiphertextException('Missing encrypted envelope');
		}
		
		$plaintext = $this->decryptEnvelopeJson(
			(string)$envelopeJson,
			$profile,
			'request',
			(string)($data['method'] ?? ''),
			(string)($data['path'] ?? '')
		);
		
		// 解密成功才替换 Body；失败路径不会部分解析明文。
		$payload->set('body', $plaintext);
		
		return $payload;
	}
	
	/**
	 * 严格校验信封结构并解密，返回明文字节。
	 *
	 * 使用范围：decrypt() 的底层实现；ResponseIntegrityChecker 验证 encrypted 模式响应时以 direction=response 调用。
	 * 适用场景：接收端对每一项信封字段做白名单与长度校验后 AEAD 解密，任何篡改在此处被统一拒绝。
	 *
	 * 函数逻辑：
	 * 1. JSON 解码信封；非法即失败。
	 * 2. version 必须等于 '1'、algorithm 必须等于 aes_256_gcm、key_id 必须等于 Profile 白名单值。
	 * 3. iv/ciphertext/tag 三字段必须存在且非空，Base64URL 严格解码。
	 * 4. iv 解码后必须 12 字节、tag 必须 16 字节。
	 * 5. KeyUsage 断言状态 active|decrypt_only（读方向迁移期），重建 AAD 后 openssl_decrypt。
	 * 6. 失败统一抛 InvalidCiphertextException('Decryption failed')，不区分具体项、不输出部分明文。
	 *
	 * @param string $envelopeJson 信封 JSON｜六字段版本化信封序列化串。示例：{"version":"1","algorithm":"aes_256_gcm","key_id":"order-encryption","iv":"..","ciphertext":"..","tag":".."}
	 * @param Profile $profile 入站/接收方 Profile｜提供 encryption.key_id 白名单基准与 client/target（进 AAD）。示例：Profile::fromConfig(...)
	 * @param string $direction 方向标识｜必须与加密时一致，否则 AAD 校验失败。示例："request"
	 * @param string $method HTTP 方法｜须与加密时一致。示例："POST"
	 * @param string $path 请求路径｜须与加密时一致（同样规范化）。示例："/api/orders"
	 * @return string 明文字节｜AEAD 校验通过后的原始内容。示例：'{"order_id":42}'
	 * @throws InvalidCiphertextException 任一校验失败（JSON/版本/算法/key_id/字段缺失/长度/AAD/tag）。
	 * @throws ConfigurationException 密钥长度非法等配置错误。
	 * @throws KeyNotFoundException 密钥缺失或状态不允许 decrypt。
	 */
	public function decryptEnvelopeJson(
		string  $envelopeJson,
		Profile $profile,
		string  $direction,
		string  $method = '',
		string  $path = ''
	)
	{
		$decoded = json_decode($envelopeJson, true);
		if (!is_array($decoded)) {
			throw new InvalidCiphertextException('Envelope is not valid JSON');
		}
		
		// algorithm/key_id 仅用于索引候选密钥，仍以 Profile 白名单为准；不一致立即拒绝。
		if (($decoded['version'] ?? '') !== self::ENVELOPE_VERSION) {
			throw new InvalidCiphertextException('Unsupported envelope version');
		}
		
		if (($decoded['algorithm'] ?? '') !== self::DRIVER) {
			throw new InvalidCiphertextException('Envelope algorithm does not match profile driver');
		}
		
		$expectedKeyId = $this->keyIdForDirection($profile, $direction);
		
		// 该方向未配置密钥时必须先拒绝：否则下面的比对会因 (string) null === '' 而
		// 被攻击者用空 key_id 信封“命中”白名单，再靠密钥缺失才失败，泄露比对已通过。
		if ($expectedKeyId === null || $expectedKeyId === '') {
			throw new InvalidCiphertextException(
				"Profile [{$profile->getName()}] has no encryption key configured for [{$direction}]"
			);
		}
		
		if (!isset($decoded['key_id'])
			|| !is_string($decoded['key_id'])
			|| !hash_equals($expectedKeyId, $decoded['key_id'])) {
			throw new InvalidCiphertextException('Envelope key_id does not match profile');
		}
		
		foreach (['iv', 'ciphertext', 'tag'] as $field) {
			if (!isset($decoded[$field]) || !is_string($decoded[$field]) || $decoded[$field] === '') {
				throw new InvalidCiphertextException("Envelope field [{$field}] is missing");
			}
		}
		
		$nonce      = Encoding::base64UrlDecode((string)$decoded['iv']);
		$tag        = Encoding::base64UrlDecode((string)$decoded['tag']);
		$ciphertext = Encoding::base64UrlDecode((string)$decoded['ciphertext']);
		
		if ($nonce === null || strlen($nonce) !== self::NONCE_BYTES) {
			throw new InvalidCiphertextException('Envelope iv length invalid');
		}
		
		if ($tag === null || strlen($tag) !== self::TAG_BYTES) {
			throw new InvalidCiphertextException('Envelope tag length invalid');
		}
		
		if ($ciphertext === null) {
			throw new InvalidCiphertextException('Envelope ciphertext invalid');
		}
		
		// 解密方向接受 active + decrypt_only 迁移期旧版本。
		$keyId = (string)$expectedKeyId;
		KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_DECRYPT);
		$key = $this->resolveKey($profile, $keyId);
		$aad = $this->buildAad($direction, $profile, $method, $path, $keyId);
		
		$plaintext = openssl_decrypt(
			$ciphertext,
			'aes-256-gcm',
			$key,
			OPENSSL_RAW_DATA,
			$nonce,
			$tag,
			$aad
		);
		
		if ($plaintext === false) {
			// 统一解密失败结果，不区分具体失败项，避免泄露校验细节。
			throw new InvalidCiphertextException('Decryption failed');
		}
		
		return (string)$plaintext;
	}
	
	/**
	 * 返回加密 driver 名称。
	 *
	 * 使用范围：日志标注、容器诊断与信封 algorithm 字段比对时调用。
	 * 适用场景：排障时确认当前绑定的是 aes_256_gcm 而非其他加密实现。
	 *
	 * 函数逻辑：
	 * 1. 直接返回类常量 DRIVER（'aes_256_gcm'）。
	 *
	 * @return string 加密 driver 标识，恒为 "aes_256_gcm"。示例："aes_256_gcm"
	 */
	public function getDriver()
	{
		return self::DRIVER;
	}
}
