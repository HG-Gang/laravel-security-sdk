<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * HmacBearerAuthenticator
 *
 * 文件功能：
 * - API 认证策略（driver=hmac_bearer_sha256）：以 HMAC 持钥证明替代 JWT 的轻量认证
 * - Authorization 头形态：HMAC-Bearer key_id="..", timestamp="..", nonce="..", signature=".."
 * - 证明原文：protocol_version \n timestamp \n nonce \n METHOD \n path \n sha256(body)
 *
 * 安全边界：
 * - 常量时间比较；时间窗与防重放参数复用 Profile 签名段配置
 * - Nonce 仅在证明验证通过后原子登记（fail-closed），避免无效请求污染共享状态
 * - 认证通过仅代表持钥身份，Scope 授权仍由 ScopeAuthorizer 单独判定
 */

namespace Tozo\Security\Authentication;

use Throwable;
use Tozo\Security\Payload;
use Tozo\Security\Profile;
use Tozo\Security\Key\KeyUsage;
use Tozo\Security\Identity\Subject;
use Tozo\Security\Protocol\Encoding;
use Tozo\Security\Contracts\ClockInterface;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Exceptions\ClockSkewException;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Contracts\ReplayStoreInterface;
use Tozo\Security\Exceptions\KeyNotFoundException;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Exceptions\AuthenticationException;
use Tozo\Security\Exceptions\ReplayProtectionException;
use Tozo\Security\Exceptions\InvalidSignatureException;
use Tozo\Security\Exceptions\ReplayStoreUnavailableException;

class HmacBearerAuthenticator implements AuthenticatorInterface
{
	/**
	 * 认证 driver 标识。AuthenticatorRouter 以此为键分派，
	 * 同时用于识别 Authorization 头的 scheme（大小写不敏感）。
	 */
	public const DRIVER = 'hmac_bearer_sha256';
	
	/**
	 * 密钥提供器。按 Profile 的 authentication.key_id 检索双方共享的 HMAC 密钥。
	 * 该密钥的归属即认证主体——持有它就能证明身份，因此必须与请求签名密钥严格分开：
	 * 复用会让一次请求签名被改造成一张持钥证明。
	 * 每次认证都重新检索而不缓存，使密钥轮换与吊销能立即生效。
	 *
	 * @var KeyProviderInterface
	 */
	private $keys;
	
	/**
	 * 防重放存储。HMAC-Bearer 证明本身可被完整复制，必须靠 Nonce 一次性登记阻止重放——
	 * 没有它，攻击者截获一次 Authorization 头即可无限重复调用。
	 * 后端必须多实例共享且登记操作原子；存储不可用时一律拒绝请求（fail-closed），
	 * 不以可用性优先为由放行。
	 *
	 * @var ReplayStoreInterface
	 */
	private $replayStore;
	
	/**
	 * 时钟。提供判定持钥证明时间窗的当前时刻基准。
	 * 注入而非直接调用 time() 的原因：时间窗边界（刚好过期、刚好在容忍范围内）
	 * 必须能被用例精确复现，靠真实时间流逝测试既慢又会间歇性失败。
	 *
	 * @var ClockInterface
	 */
	private $clock;
	
	/**
	 * 构造 HMAC-Bearer 认证器并注入依赖。
	 *
	 * 使用范围：ServiceProvider 按 Profile authentication.driver=hmac_bearer_sha256 注册时调用。
	 * 适用场景：低风险幂等接口（token_only 变体）用共享密钥证明身份，不引入 JWT 体系。
	 *
	 * 函数逻辑：
	 * 1. 保存密钥提供器、防重放存储与时钟。
	 *
	 * @param KeyProviderInterface $keys 密钥提供器｜检索认证共享密钥。示例：new EnvKeyProvider()
	 * @param ReplayStoreInterface $replayStore 防重放存储｜Nonce 只写一次后端。示例：new LaravelCacheReplayStore($cache)
	 * @param ClockInterface $clock 时钟接口｜窗口判定时间源。示例：new SystemClock()
	 * @return void 无返回值。
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
	 * 校验 HMAC-Bearer 持钥证明并返回主体。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware.authenticateByMode 在认证 driver 为本策略时调用。
	 * 适用场景：合作方以共享密钥调用查询类接口——证明 Body 未篡改且非重放，即认定为其 client 身份。
	 *
	 * 函数逻辑：
	 * 1. 解析 Authorization 头（parseAuthorization），形态非法抛 AuthenticationException。
	 * 2. key_id 必须等于 Profile authentication.key_id 白名单值。
	 * 3. 双向时间窗校验（max_age/skew 取签名段配置，缺省 300/60）。
	 * 4. 重算证明 HMAC 并 hash_equals 比较；失败抛 InvalidSignatureException。
	 * 5. 防重放开启时按 TTL 公式原子登记认证 Nonce；重复/故障按重放/不可用拒绝。
	 * 6. 返回 Subject：sub=subject_type:client_id，iss=hmac_bearer:{key_id}，scope 空（授权另判）。
	 *
	 * @param Payload $payload 可信负载｜需含 authorization 原始头、method/path/body。示例：new Payload(['authorization'=>'HMAC-Bearer key_id="k", ...','body'=>'{}'])
	 * @param Profile|null $profile 入站 Profile｜提供 authentication.key_id、时间窗与防重放配置。示例：Profile::fromConfig(...)
	 * @return Subject 认证成功后的持钥主体｜scope 为空数组，由授权层另行判定。示例：Subject(sub="service:product-center")
	 * @throws AuthenticationException Profile 缺失或头形态非法。
	 * @throws InvalidSignatureException key_id 不符或签名比较失败。
	 * @throws ClockSkewException 时间戳越窗。
	 * @throws KeyNotFoundException 密钥缺失或状态不允许。
	 * @throws ReplayProtectionException 认证 Nonce 重复。
	 * @throws ReplayStoreUnavailableException 防重放存储不可用（fail-closed）。
	 */
	public function authenticate(Payload $payload, Profile $profile = null)
	{
		if ($profile === null) {
			throw new AuthenticationException('Profile is required for HMAC-Bearer authentication');
		}
		
		$data = $payload->getData();
		$raw  = isset($data['authorization']) && is_string($data['authorization'])
			? $data['authorization']
			: '';
		
		$parsed = $this->parseAuthorization($raw);
		if ($parsed === null) {
			throw new AuthenticationException('Malformed HMAC-Bearer authorization header');
		}
		
		$keyId = $profile->getAuthenticationKeyId();
		if ($keyId === null || !hash_equals($keyId, $parsed['key_id'])) {
			// key_id 必须与 Profile 白名单一致，不得尝试其他候选密钥。
			throw new InvalidSignatureException('Authorization key_id does not match profile');
		}
		
		$config = $profile->getSignatureConfig();
		$maxAge = (int)($config['max_age_seconds'] ?? 300);
		$skew   = (int)($config['clock_skew_seconds'] ?? 60);
		$margin = (int)($config['replay_safety_margin_seconds'] ?? 5);
		
		// 与 HmacSha256Signer::verify 保持同一口径：非数字时间戳属于无效证明，
		// 不能靠 (int) 强转成 0 再依赖窗口比较间接失败。
		if (!is_numeric($parsed['timestamp'])) {
			throw new InvalidSignatureException('Authorization timestamp is not numeric');
		}
		
		// 双向时间窗：防止过期与未来时间戳长期有效两种形态。
		$timestamp = (int)$parsed['timestamp'];
		if (abs($this->clock->now() - $timestamp) > $maxAge + $skew) {
			throw new ClockSkewException('Authorization timestamp outside allowed window');
		}
		
		// 服务端重算证明等同验签方向：接受 active + verify_only 迁移期共享密钥。
		KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_VERIFY);
		
		$secret   = $this->keys->getKey($keyId);
		$body     = isset($data['body']) && is_string($data['body']) ? $data['body'] : '';
		$bodyHash = hash('sha256', $body);
		
		$canonical = implode("\n", [
			CanonicalRequest::PROTOCOL_VERSION,
			(string)$timestamp,
			$parsed['nonce'],
			strtoupper((string)($data['method'] ?? '')),
			CanonicalRequest::normalizePath((string)($data['path'] ?? '')),
			$bodyHash,
		]);
		
		$expected = hash_hmac('sha256', $canonical, $secret, true);
		$provided = Encoding::base64UrlDecode($parsed['signature']);
		
		if ($provided === null || !hash_equals($expected, $provided)) {
			throw new InvalidSignatureException('Invalid HMAC-Bearer proof');
		}
		
		// 防重放仅在证明验证通过后执行。
		if ($profile->getReplayProtectionEnabled()) {
			$this->registerNonce($profile, $parsed['nonce'], $maxAge + 2 * $skew + $margin);
		}
		
		return new Subject([
			'sub'          => $profile->getSubjectType() . ':' . $profile->getClientId(),
			'client_id'    => $profile->getClientId(),
			'iss'          => 'hmac_bearer:' . $keyId,
			'aud'          => [$profile->getTargetService()],
			'subject_type' => $profile->getSubjectType(),
			'scope'        => [],
		]);
	}
	
	/**
	 * 解析 HMAC-Bearer Authorization 头。
	 *
	 * 使用范围：authenticate 第 1 步内部调用。
	 * 适用场景：容忍参数顺序、引号可选与 scheme 大小写差异，输出四个必需字段。
	 *
	 * 函数逻辑：
	 * 1. 按首个空格拆分 scheme 与参数串；scheme 大小写不敏感须为 HMAC-Bearer。
	 * 2. 逗号拆分 k=v（v 可带双引号），收集 key_id/timestamp/nonce/signature。
	 * 3. 四字段任一缺失返回 null。
	 *
	 * @param string $raw Authorization 原始头｜完整头值。示例：'HMAC-Bearer key_id="order-signing", timestamp="1700000000", nonce="5f1c..", signature="qE8f"'
	 * @return array{key_id:string,timestamp:string,nonce:string,signature:string}|null 解析结果；非法返回 null。示例：["key_id"=>"k","timestamp"=>"1700000000","nonce"=>"..","signature"=>".."] 或 null
	 */
	private function parseAuthorization(string $raw)
	{
		$space = strpos($raw, ' ');
		if ($space === false) {
			return null;
		}
		
		if (strcasecmp(substr($raw, 0, $space), self::DRIVER) !== 0
			&& strcasecmp(substr($raw, 0, $space), 'hmac-bearer') !== 0) {
			return null;
		}
		
		$fields = ['key_id' => '', 'timestamp' => '', 'nonce' => '', 'signature' => ''];
		foreach (explode(',', substr($raw, $space + 1)) as $pair) {
			$pair = trim($pair);
			$eq   = strpos($pair, '=');
			if ($eq === false) {
				continue;
			}
			$k = trim(substr($pair, 0, $eq));
			$v = trim(substr($pair, $eq + 1));
			$v = trim($v, '"');
			if (array_key_exists($k, $fields)) {
				$fields[$k] = $v;
			}
		}
		
		foreach ($fields as $v) {
			if ($v === '') {
				return null;
			}
		}
		
		return $fields;
	}
	
	/**
	 * 原子登记认证 Nonce（fail-closed）。
	 *
	 * 使用范围：authenticate 第 5 步内部调用。
	 * 适用场景：同一证明串被二次提交时在此处被拒绝，存储故障时不降级放行。
	 *
	 * 函数逻辑：
	 * 1. 组合键 tozo_replay_auth|{clientId}|{nonce}。
	 * 2. TTL 随 record() 参数传入并原子写入；true 即重放抛异常；
	 *    其余 Throwable 包装为存储不可用。不使用 setTtl()，避免共享单例上的状态被并发覆盖。
	 *
	 * @param Profile $profile 入站 Profile｜提供 clientId 命名空间。示例：Profile::fromConfig(...)
	 * @param string $nonce 一次性随机串｜已通过验证的十六进制串。示例："5f1c9e2a77b34d01ae95c8d012b64f7a"
	 * @param int $ttl 存活时长(秒)｜窗口公式结果。示例：425
	 * @return void 首次登记静默完成。
	 * @throws ReplayProtectionException Nonce 已存在。
	 * @throws ReplayStoreUnavailableException 存储故障。
	 */
	private function registerNonce(Profile $profile, string $nonce, int $ttl)
	{
		$key = 'tozo_replay_auth|' . $profile->getClientId() . '|' . $nonce;
		
		try {
			// TTL 随本次调用传入，避免与其他 Profile 的登记操作互相覆盖。
			$alreadyUsed = $this->replayStore->record($key, $ttl);
		} catch (ReplayProtectionException $e) {
			throw $e;
		} catch (Throwable $e) {
			throw new ReplayStoreUnavailableException('Replay store unavailable', 503, $e);
		}
		
		if ($alreadyUsed) {
			throw new ReplayProtectionException();
		}
	}
	
	/**
	 * 返回认证 driver 名称。
	 *
	 * 使用范围：日志标注与容器诊断时调用。
	 * 适用场景：排障确认当前认证策略为 hmac_bearer_sha256。
	 *
	 * 函数逻辑：
	 * 1. 直接返回类常量 DRIVER。
	 *
	 * @return string 认证 driver 标识，恒为 "hmac_bearer_sha256"。示例："hmac_bearer_sha256"
	 */
	public function getDriver()
	{
		return self::DRIVER;
	}
}
