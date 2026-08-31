<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * HmacSha256Signer
 *
 * 文件功能：
 * - Protocol v1 首选请求签名 driver：HMAC-SHA256
 * - sign()：生成时间戳、CSPRNG Nonce、Body Hash 与签名，写入 Payload
 * - verify()：常量时间比较验签 → 时间窗口校验 → ReplayStore 原子登记 Nonce
 *
 * 处理顺序（设计 §11 固定）：
 *   解析 Profile → 时间窗口 → 验证签名 → ReplayStore 登记
 *   只有通过密码学验证的 Nonce 才会进入防重放状态。
 *
 * 安全边界：
 * - 使用 hash_equals 常量时间比较
 * - ReplayStore TTL = max_age + 2*clock_skew + safety_margin（默认 ≥425s），覆盖完整接受窗口
 * - 存储故障、超时一律抛出 ReplayStoreUnavailableException，禁止降级为仅时间校验
 */

namespace Tozo\Security\Signature;

use Throwable;
use Tozo\Security\Payload;
use Tozo\Security\Profile;
use Tozo\Security\Key\KeyUsage;
use Tozo\Security\Protocol\Encoding;
use Tozo\Security\Contracts\ClockInterface;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Exceptions\ClockSkewException;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Contracts\ReplayStoreInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\ReplayProtectionException;
use Tozo\Security\Exceptions\InvalidSignatureException;
use Tozo\Security\Exceptions\UnsupportedDriverException;
use Tozo\Security\Exceptions\ReplayStoreUnavailableException;

class HmacSha256Signer implements SignerInterface
{
	/**
	 * 签名 driver 标识。sign/verify 均校验 Profile 的 signature.driver 与此全等，
	 * 防止把为其他算法配置的 Profile 误用于本实现。
	 */
	public const DRIVER = 'hmac_sha256';
	
	/**
	 * 密钥提供器。按 Profile 的 signature.key_id 检索真实 HMAC 密钥。
	 * 本类不缓存密钥，每次签名与验签都重新检索，使轮换与吊销能立即生效。
	 * 请求方向与响应方向使用不同 key_id，由 Profile 校验期强制。
	 *
	 * @var KeyProviderInterface
	 */
	private $keys;
	
	/**
	 * 防重放存储。Nonce 原子登记的后端，是「同一签名只能用一次」的唯一保障。
	 * 必须是多实例共享的后端：进程内数组无法提供跨实例的只写一次语义，
	 * 多实例部署下同一 Nonce 会在各实例分别被放行，防重放形同失效且无任何报错。
	 * 存储不可用时一律拒绝请求（fail-closed），不以可用性优先为由放行。
	 *
	 * @var ReplayStoreInterface
	 */
	private $replayStore;
	
	/**
	 * 时钟。提供签名时间窗判定的当前时刻基准。
	 * 注入而非直接调用 time()：时间窗边界（刚好过期、刚好落在 skew 容忍内）
	 * 必须能被用例精确复现，靠真实时间流逝既慢又会让用例间歇性失败。
	 * 生产使用 SystemClock，测试注入固定时间戳的替身。
	 *
	 * @var ClockInterface
	 */
	private $clock;
	
	/**
	 * 构造签名器并注入三大协作依赖。
	 *
	 * 使用范围：ServiceProvider 门控注册 SignerInterface 单例时调用一次。
	 * 适用场景：应用启动装配阶段把密钥来源、共享缓存与可注入时钟组装成无状态签名服务。
	 *
	 * 函数逻辑：
	 * 1. 保存密钥提供器（后续按 Profile 的 signature.key_id 检索密钥）。
	 * 2. 保存防重放存储（verify 通过后原子登记 Nonce）。
	 * 3. 保存时钟（sign 取当前时间、verify 计算窗口偏差）。
	 *
	 * @param KeyProviderInterface $keys 密钥提供器｜按 key_id 检索真实密钥材料。示例：new EnvKeyProvider() 或 new ArrayKeyProvider(['order-signing'=>str_repeat('a',32)])
	 * @param ReplayStoreInterface $replayStore 防重放存储｜具备原子 add（SET NX EX）语义的共享后端。示例：new LaravelCacheReplayStore($cacheRepository)
	 * @param ClockInterface $clock 时钟接口｜生产传 SystemClock，测试传固定时钟。示例：new SystemClock()
	 * @return void 无返回值；依赖保存到私有属性供 sign/verify 使用。
	 */
	public function __construct(
		KeyProviderInterface $keys,
		ReplayStoreInterface $replayStore,
		ClockInterface       $clock
	)
	{
		$this->keys        = $keys;
		$this->replayStore = $replayStore;
		$this->clock       = $clock;
	}
	
	/**
	 * 为出站请求生成完整签名元数据并写回 Payload。
	 *
	 * 使用范围：TozoHttpClient 出站五步流程第 3 步、OutboundSignerMiddleware 代理转发签名时调用。
	 * 适用场景：product-center 调用 order-api 前，对最终 wire Body（可能已加密为信封 JSON）产出 HMAC-SHA256 完整性证明。
	 *
	 * 函数逻辑：
	 * 1. 校验 Profile signature.enabled=true 且 driver=hmac_sha256，取用途 key_id。
	 * 2. KeyUsage 断言密钥轮换状态为 active，再从 KeyProvider 读取真实密钥。
	 * 3. 从注入时钟取 timestamp，CSPRNG 生成 16 字节 Nonce（32 hex 字符）。
	 * 4. canonicalFor() 构造 11 字段规范化串，hash_hmac(raw) 后 Base64URL 编码。
	 * 5. 将 protocol_version/timestamp/nonce/body_hash/signature/key_id 写回 Payload 返回。
	 *
	 * @param Payload $payload 安全负载｜携带 method/path/query/content_type/body/client_id/target_service 上下文。示例：new Payload(['method'=>'POST','path'=>'/api/orders','body'=>'{"sku":"A-1"}'])
	 * @param Profile $profile 出站 Profile｜提供签名开关、key_id、时间窗与防重放参数。示例：Profile::fromConfig('svc_to_order', $cfg, $keys)
	 * @return Payload 追加签名元数据后的同一 Payload 实例（原对象就地修改，便于链式复用）。示例：同一 Payload 实例（含 signature/timestamp/nonce）
	 * @throws ConfigurationException Profile 未启用签名或 signature.key_id 缺失。
	 * @throws UnsupportedDriverException driver 不在 hmac_sha256 白名单。
	 * @throws KeyNotFoundException 密钥缺失或轮换状态非 active。
	 */
	public function sign(Payload $payload, Profile $profile)
	{
		$config = $profile->getSignatureConfig();
		
		if (($config['enabled'] ?? false) !== true) {
			throw new ConfigurationException("Profile [{$profile->getName()}] has signature disabled; cannot sign");
		}
		
		$driver = $config['driver'] ?? Profile::DEFAULT_SIGNATURE_DRIVER;
		if ($driver !== self::DRIVER) {
			throw new UnsupportedDriverException(
				"Unsupported signature driver [{$driver}] for HmacSha256Signer"
			);
		}
		
		$keyId = $profile->getSignatureKeyId();
		if ($keyId === null || $keyId === '') {
			throw new ConfigurationException("Profile [{$profile->getName()}] signature.key_id is required");
		}
		
		// 轮换状态断言：签名仅允许 active；随后读取密钥，缺失立即失败。
		KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_SIGN);
		$secret = $this->keys->getKey($keyId);
		
		$data = $payload->getData();
		$body = isset($data['body']) && is_string($data['body']) ? $data['body'] : '';
		
		// 每次签名使用全新 CSPRNG Nonce（16 字节 → 32 hex 字符）。
		$timestamp = $this->clock->now();
		$nonce     = bin2hex(random_bytes(16));
		
		$canonical = $this->canonicalFor($data, $body, $timestamp, $nonce, $profile, $keyId);
		$signature = Encoding::base64UrlEncode(hash_hmac('sha256', $canonical, $secret, true));
		
		$payload->set('protocol_version', CanonicalRequest::PROTOCOL_VERSION);
		$payload->set('timestamp', $timestamp);
		$payload->set('nonce', $nonce);
		$payload->set('body_hash', hash('sha256', $body));
		$payload->set('signature', $signature);
		$payload->set('key_id', $keyId);
		
		return $payload;
	}
	
	/**
	 * 按当前 Payload 上下文构造 Protocol v1 规范化串。
	 *
	 * 使用范围：sign() 与 verify() 内部共用，保证双端签名原文字节一致。
	 * 适用场景：签发端用请求上下文生成原文；验证端用同一函数从 Header 元数据重建原文比对。
	 *
	 * 函数逻辑：
	 * 1. 从 Payload 数据提取 method/path/query/content_type，缺省回退 Profile 的 client/target。
	 * 2. query 支持字符串（线上原始字节，入站首选）与数组（调用方数组入口）两种形态。
	 * 3. 连同 body/timestamp/nonce/keyId 交给 CanonicalRequest::build 输出 "\n" 连接的规范化串。
	 *
	 * @param array $data 负载数据｜Payload::getData() 的关联数组。示例：['method'=>'POST','path'=>'/api/orders','query'=>'a=1','client_id'=>'product-center']
	 * @param string $body 最终 wire Body｜参与 SHA-256 的原始字节（加密场景为信封 JSON）。示例：'{"sku":"A-1"}'
	 * @param int $timestamp 时间戳(秒)｜Unix 秒级签名时间。示例：1700000000
	 * @param string $nonce 一次性随机串｜32 位十六进制 CSPRNG 输出。示例："5f1c9e2a77b34d01ae95c8d012b64f7a"
	 * @param Profile $profile 出入站 Profile｜提供 client_id/target_service 缺省回退值。示例：Profile::fromConfig(...)
	 * @param string $keyId 密钥标识｜签名用途 key_id，规范化串末字段。示例："order-signing"
	 * @return string 以 "\n" 连接的 11 字段规范化串（UTF-8 字节）。示例：规范化串字节
	 */
	private function canonicalFor(
		array   $data,
		string  $body,
		int     $timestamp,
		string  $nonce,
		Profile $profile,
		string  $keyId
	)
	{
		// query 允许字符串或数组：两种入口在 CanonicalRequest 内部归一为同一规范化串。
		$query = isset($data['query']) && (is_array($data['query']) || is_string($data['query']))
			? $data['query']
			: [];
		
		return CanonicalRequest::build(
			(string)($data['method'] ?? ''),
			(string)($data['path'] ?? ''),
			$query,
			isset($data['content_type']) ? (string)$data['content_type'] : '',
			$body,
			$timestamp,
			$nonce,
			(string)($data['client_id'] ?? $profile->getClientId()),
			(string)($data['target_service'] ?? $profile->getTargetService()),
			$keyId
		);
	}
	
	/**
	 * 服务端验证入站请求签名，并在密码学验证通过后原子登记 Nonce。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware 按 security_mode 分派验签步骤时调用。
	 * 适用场景：order-api 收到 product-center 请求，先确认 Body 未被篡改且非重放，再进入 Token 验证与业务。
	 *
	 * 函数逻辑：
	 * 1. 校验 Profile 签名开启；Header 元数据（signature/timestamp/nonce/key_id）必须齐全。
	 * 2. 双向时间窗校验：|now - ts| ≤ max_age + skew，越窗抛 ClockSkewException。
	 * 3. key_id 必须等于 Profile 白名单值（不尝试其他候选），断言状态 active|verify_only 后取密钥。
	 * 4. 重算规范化串 HMAC，hash_equals 常量时间比较；不一致抛 InvalidSignatureException。
	 * 5. replay_protection 开启时按 TTL 公式原子登记 Nonce；重复即重放、故障即 fail-closed。
	 *
	 * @param Payload $payload 待验证负载｜由中间件从 HTTP 请求构建，含 Header 提供的签名元数据与原始 Body。示例：new Payload(['signature'=>'qE8f','timestamp'=>'1700000000','nonce'=>'5f1c...','key_id'=>'order-signing','body'=>'{}'])
	 * @param Profile $profile 入站 Profile｜提供白名单 key_id、max_age/skew/margin 与防重放开关。示例：Profile::fromConfig('order_inbound', $cfg, $keys)
	 * @return bool 恒返回 true；任何失败直接抛异常而非返回 false。示例：true
	 * @throws InvalidSignatureException 元数据缺失、key_id 不符或签名比较不一致。
	 * @throws ClockSkewException 时间戳超出 max_age+skew 允许窗口。
	 * @throws KeyNotFoundException 密钥缺失或状态不允许 verify。
	 * @throws ReplayProtectionException Nonce 已被使用（重放）。
	 * @throws ReplayStoreUnavailableException 防重放存储不可用（fail-closed，禁止降级）。
	 */
	public function verify(Payload $payload, Profile $profile)
	{
		$config = $profile->getSignatureConfig();
		
		if (($config['enabled'] ?? false) !== true) {
			throw new ConfigurationException(
				"Profile [{$profile->getName()}] has signature disabled; unexpected signed request"
			);
		}
		
		$data = $payload->getData();
		
		// Header 提供的签名元数据必须完整；缺失属于无效请求而非配置错误。
		foreach (['signature', 'nonce', 'key_id'] as $required) {
			if (!isset($data[$required]) || !is_string($data[$required]) || $data[$required] === '') {
				throw new InvalidSignatureException("Missing signature field [{$required}]");
			}
		}
		
		if (!isset($data['timestamp']) || !is_numeric($data['timestamp'])) {
			throw new InvalidSignatureException('Missing signature field [timestamp]');
		}
		
		$maxAge = (int)($config['max_age_seconds'] ?? 300);
		$skew   = (int)($config['clock_skew_seconds'] ?? 60);
		$margin = (int)($config['replay_safety_margin_seconds'] ?? 5);
		
		// 时间窗口：|now - ts| <= max_age + skew，双向限制防止未来时间戳长期有效。
		$timestamp = (int)$data['timestamp'];
		$now       = $this->clock->now();
		if (abs($now - $timestamp) > $maxAge + $skew) {
			throw new ClockSkewException('Signature timestamp outside allowed window');
		}
		
		$keyId = (string)$data['key_id'];
		if ($keyId !== (string)$profile->getSignatureKeyId()) {
			// key_id 必须与 Profile 白名单一致，不得尝试其他候选密钥。
			throw new InvalidSignatureException('Signature key_id does not match profile');
		}
		
		// 验签方向接受 active + verify_only 迁移期旧版本。
		KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_VERIFY);
		$secret = $this->keys->getKey($keyId);
		$body   = isset($data['body']) && is_string($data['body']) ? $data['body'] : '';
		
		$expected = hash_hmac(
			'sha256',
			$this->canonicalFor($data, $body, $timestamp, (string)$data['nonce'], $profile, $keyId),
			$secret,
			true
		);
		
		$provided = Encoding::base64UrlDecode((string)$data['signature']);
		if ($provided === null || !hash_equals($expected, $provided)) {
			throw new InvalidSignatureException('Invalid request signature');
		}
		
		// 防重放仅在密码学验证通过后执行，避免无效请求污染共享状态。
		if ($profile->getReplayProtectionEnabled()) {
			$ttl = $maxAge + 2 * $skew + $margin;
			$this->registerNonce($profile, (string)$data['nonce'], $ttl);
		}
		
		return true;
	}
	
	/**
	 * 原子登记已验签 Nonce 到共享防重放存储。
	 *
	 * 使用范围：verify() 第 5 步，仅在签名常量时间比较通过后调用。
	 * 适用场景：多实例部署下同一请求被网关重发时，第二实例必须在此处被拒绝。
	 *
	 * 函数逻辑：
	 * 1. 组合键 tozo_replay|{clientId}|{nonce} 定位记录。
	 * 2. TTL 随 record() 参数传入并原子写入（Cache::add ≙ SET NX EX）。
	 *    不使用 setTtl()：ReplayStore 按 singleton 注册，先设后写的两步之间
	 *    若被其他 Profile 的调用插入，本次会拿到对方的短 TTL，静默缩短防重放窗口。
	 * 3. record 返回 true 表示键已存在 → 抛 ReplayProtectionException。
	 * 4. 其余 Throwable 统一包装为 ReplayStoreUnavailableException（fail-closed，保留原链）。
	 *
	 * @param Profile $profile 入站 Profile｜提供 clientId 组合防重放键命名空间。示例：Profile::fromConfig('order_inbound', ...)
	 * @param string $nonce 一次性随机串｜已通过验签的 32 位十六进制串。示例："5f1c9e2a77b34d01ae95c8d012b64f7a"
	 * @param int $ttl 存活时长(秒)｜max_age+2×skew+margin 公式结果，覆盖完整接受窗口。示例：425
	 * @return void 无返回值；首次登记成功静默完成。
	 * @throws ReplayProtectionException 同一 Nonce 已存在（判定为重放攻击）。
	 * @throws ReplayStoreUnavailableException 存储连接/超时/格式异常，拒绝请求不降级。
	 */
	private function registerNonce(Profile $profile, string $nonce, int $ttl)
	{
		$key = 'tozo_replay|' . $profile->getClientId() . '|' . $nonce;
		
		try {
			// TTL 随本次调用传入，使"设定时长"与"原子写入"成为不可分割的一步。
			$alreadyUsed = $this->replayStore->record($key, $ttl);
		} catch (ReplayProtectionException $e) {
			throw $e;
		} catch (Throwable $e) {
			// 下游状态未知时不伪造成功；统一转成存储不可用并保留原异常链。
			throw new ReplayStoreUnavailableException('Replay store unavailable', 503, $e);
		}
		
		if ($alreadyUsed) {
			throw new ReplayProtectionException();
		}
	}
	
	/**
	 * 返回签名 driver 名称。
	 *
	 * 使用范围：日志标注、容器诊断与 driver 白名单比对时调用。
	 * 适用场景：排障时确认当前绑定的是 hmac_sha256 而非其他签名实现。
	 *
	 * 函数逻辑：
	 * 1. 直接返回类常量 DRIVER（'hmac_sha256'）。
	 *
	 * @return string 签名 driver 标识，恒为 "hmac_sha256"。示例："hmac_sha256"
	 */
	public function getDriver()
	{
		return self::DRIVER;
	}
}
