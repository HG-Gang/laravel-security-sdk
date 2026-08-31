<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/29
 * Time: 10:20
 */

/**
 * ConfigNormalizer
 *
 * 文件功能：
 * - 把极简配置形态（service + environment + peers）展开为 SDK 内部完整配置形态
 * - 每个 peer 展开为一对 Profile：outbound_to_{peer} 与 inbound_from_{peer}
 * - features 段由 Profile 实际引用自动推导，用户无需声明
 *
 * 为什么需要展开器：
 * - 四系统实测 48 个 Profile 中 19 个字段取值完全相同（协议、算法、时间窗、存储驱动），
 *   真变量只有 direction / client_id / target_service / 两个 key_id
 * - 展开器把这些恒定值固化为内置常量，使配置文件从 548 行降到约 20 行
 *
 * 安全边界：
 * - 只做结构展开，不放宽任何校验；展开结果仍交由 Profile::validate 全量校验
 * - 不持有也不生成任何密钥，只推导 key_id 标识
 * - 已是完整形态的配置原样返回，保证旧配置继续可用
 */

namespace Tozo\Security\Support;

use Tozo\Security\Profile;
use Tozo\Security\Exceptions\ConfigurationException;

class ConfigNormalizer
{
	/**
	 * 协议版本。与 protocol/test-vectors-v1.json 冻结的版本一致，参与签名原文绑定。
	 */
	public const PROTOCOL_VERSION = '1';
	
	/**
	 * 签名最大年龄（秒）。四系统实测 48/48 取值一致，固化为内置常量。
	 */
	public const SIGNATURE_MAX_AGE_SECONDS = 300;
	
	/**
	 * 时钟偏差容忍（秒）。四系统实测 48/48 取值一致，固化为内置常量。
	 * 它与 SIGNATURE_MAX_AGE_SECONDS 共同决定签名的接受窗口：
	 * 请求时间戳落在 [now - max_age - skew, now + skew] 之外即拒绝。
	 * 取 60 是因为生产机普遍启用 NTP，偏差通常在秒级；
	 * 放大该值会同比放大重放窗口，缩小则会让偶发时钟抖动误伤合法请求。
	 */
	public const CLOCK_SKEW_SECONDS = 60;
	
	/**
	 * 防重放记录的 TTL 安全余量（秒）。完整公式 TTL = max_age + 2×skew + margin，
	 * 按内置常量计算为 300 + 120 + 5 = 425 秒。
	 * 两倍 skew 覆盖双端各自偏移的最坏情况；margin 再补一点余量，
	 * 因为 Nonce 登记与签名校验之间存在网络与处理耗时。
	 * TTL 必须覆盖完整接受窗口——短于窗口会在窗口尾部留出重放缝隙，
	 * 那种缝隙只在高并发下偶发，排查极难。
	 */
	public const REPLAY_SAFETY_MARGIN_SECONDS = 5;
	
	/**
	 * 加密明文体积上限（字节）。约为 memory_limit=128M 的 1/16，
	 * 把不可捕获的 fatal OOM 转为可捕获的 EncryptionException。
	 */
	public const MAX_PLAINTEXT_BYTES = 8388608;
	
	/**
	 * 出站 HTTP 读取超时（秒）。取自原 tozo_services.php 的实际部署值。
	 * 超时后 SDK 抛 ProtocolException 而非返回空响应——下游状态未知时
	 * 伪造成功会让业务把未完成的调用当作已完成。
	 * 内部系统互调的正常响应在百毫秒级，10 秒足以覆盖偶发抖动；
	 * 需要更长时间的批量接口应在 Profile 级用 http.timeout 单独放宽。
	 */
	public const HTTP_TIMEOUT = 10;
	
	/**
	 * 出站 TCP 连接超时（秒）。与读取超时分开设置的原因：
	 * 连接失败通常意味着对端不可达或网络分区，属于应当快速失败的情形；
	 * 而读取慢可能只是对端处理耗时，值得多等一会儿。
	 * 若合并为单一超时，要么连接阶段等太久，要么读取阶段被过早切断。
	 */
	public const HTTP_CONNECT_TIMEOUT = 3;
	
	/**
	 * 最低 TLS 版本。TLS 1.0/1.1 已被主流浏览器与合规基线弃用，
	 * 存在已知的密码套件与降级攻击面，因此下限定在 1.2。
	 * 该值由负载均衡器与 PHP TLS 栈共同执行，SDK 自身不强制握手版本——
	 * 因此它是**声明性约束**，真实生效与否须在部署环境验证，不能只看配置。
	 */
	public const TLS_MIN_VERSION = 'TLSv1.2';
	
	/**
	 * 把极简配置展开为内部完整形态。
	 *
	 * 使用范围：ServiceProvider::register 早期、ConfigChecker::check 入口。
	 * 适用场景：用户只声明 service/environment/peers，由本方法生成全部 Profile 与 features。
	 *
	 * 函数逻辑：
	 * 1. 非极简形态原样返回（旧配置继续可用）。
	 * 2. 校验 service 与 peers 结构，逐个 peer 展开为 outbound/inbound 两个 Profile。
	 * 3. 由展开结果推导 features，合并可选覆盖段后返回。
	 *
	 * @param array $config 配置树｜极简或完整形态。示例：["service"=>"tozo-app-api","peers"=>["pos-api"=>"https://..."]]
	 * @return array 内部完整形态配置。示例：["protocol_version"=>"1","profiles"=>[...],"features"=>[...]]
	 * @throws ConfigurationException service 缺失、peer 结构非法或 peer 与自身同名。
	 */
	public static function normalize(array $config)
	{
		if (!self::isCompact($config)) {
			return $config;
		}
		
		$service     = (string)$config['service'];
		$environment = isset($config['environment']) && is_string($config['environment'])
			? (string)$config['environment']
			: '';
		
		if ($environment === '') {
			throw new ConfigurationException('tozo_security.environment is required in compact configuration');
		}
		
		$profiles = [];
		$peers    = [];
		
		foreach ($config['peers'] as $peer => $peerConfig) {
			$peerName = (string)$peer;
			$options  = self::normalizePeerOptions($peerName, $peerConfig);
			
			if ($peerName === $service) {
				throw new ConfigurationException(
					"tozo_security.peers [{$peerName}] must not equal the local service identifier"
				);
			}
			
			$peers[$peerName] = $options;
			
			$outboundName = self::profileName($service, 'outbound_to', $peerName);
			$inboundName  = self::profileName($service, 'inbound_from', $peerName);
			
			$profiles[$outboundName] = self::buildProfile(
				Profile::DIRECTION_OUTBOUND,
				$service,
				$peerName,
				$environment,
				$options
			);
			
			$profiles[$inboundName] = self::buildProfile(
				Profile::DIRECTION_INBOUND,
				$peerName,
				$service,
				$environment,
				$options
			);
		}
		
		$normalized = [
			'service'          => $service,
			'environment'      => $environment,
			'protocol_version' => self::PROTOCOL_VERSION,
			'peers'            => $peers,
			'profiles'         => $profiles,
			'features'         => self::deriveFeatures($profiles),
			'key_providers'    => self::resolveKeyProviders($config),
			'logging'          => self::resolveLogging($config),
			'http'             => self::resolveHttp($config),
		];
		
		// default_profile 保持可选：未声明时由 HttpClient 按目标服务选路，无需绑定默认值。
		if (isset($config['default_profile']) && is_string($config['default_profile'])) {
			$normalized['default_profile'] = (string)$config['default_profile'];
		}
		
		return $normalized;
	}
	
	/**
	 * 判断配置是否为极简形态。
	 *
	 * 使用范围：normalize 入口分派、ServiceProvider 决定是否展开。
	 * 适用场景：极简形态与完整形态并存期，两者都必须可用。
	 *
	 * 函数逻辑：
	 * 1. 存在 service 与 peers 且 peers 为数组即视为极简形态。
	 *
	 * @param array $config 配置树｜tozo_security 完整配置。示例：["service"=>"tozo-app-api","peers"=>[...]]
	 * @return bool true=极简形态需要展开。示例：true
	 */
	public static function isCompact(array $config)
	{
		return isset($config['service'])
			&& is_string($config['service'])
			&& $config['service'] !== ''
			&& isset($config['peers'])
			&& is_array($config['peers']);
	}
	
	/**
	 * 归一化单个 peer 的声明形态。
	 *
	 * 使用范围：normalize 遍历 peers 时调用。
	 * 适用场景：字符串简写（仅 base_uri）与数组完整形态并存。
	 *
	 * 函数逻辑：
	 * 1. 字符串值视为 base_uri 简写。
	 * 2. 数组值读取 base_uri / security_mode / encryption 三项可选覆盖。
	 * 3. base_uri 必填且必须为非空字符串。
	 *
	 * @param string $peer peer 标识｜对端服务名。示例："app-admin-api"
	 * @param mixed $peerConfig peer 声明｜字符串或数组。示例："https://app-admin-api.example.com"
	 * @return array 归一化后的 peer 选项。示例：["base_uri"=>"https://...","security_mode"=>"signed_request","encryption"=>false]
	 * @throws ConfigurationException base_uri 缺失或声明形态非法。
	 */
	private static function normalizePeerOptions(string $peer, $peerConfig)
	{
		if (is_string($peerConfig)) {
			$peerConfig = ['base_uri' => $peerConfig];
		}
		
		if (!is_array($peerConfig)) {
			throw new ConfigurationException(
				"tozo_security.peers [{$peer}] must be a base URI string or an options array"
			);
		}
		
		$baseUri = isset($peerConfig['base_uri']) ? $peerConfig['base_uri'] : null;
		
		if (!is_string($baseUri) || $baseUri === '') {
			throw new ConfigurationException("tozo_security.peers [{$peer}] requires a non-empty base_uri");
		}
		
		$mode = isset($peerConfig['security_mode']) && is_string($peerConfig['security_mode'])
			? (string)$peerConfig['security_mode']
			: Profile::MODE_SIGNED_REQUEST;
		
		if (!in_array($mode, Profile::SECURITY_MODES, true)) {
			throw new ConfigurationException(
				"tozo_security.peers [{$peer}] security_mode must be one of: " . implode(', ', Profile::SECURITY_MODES)
			);
		}
		
		return [
			'base_uri'      => $baseUri,
			'security_mode' => $mode,
			'encryption'    => isset($peerConfig['encryption']) && $peerConfig['encryption'] === true,
		];
	}
	
	/**
	 * 生成 Profile 注册表键名。
	 *
	 * 使用范围：normalize 展开 peers、外部按对端反查 Profile 名。
	 * 适用场景：保持「当前服务视角」的命名语义，日志与路由可直接定位关系。
	 *
	 * 函数逻辑：
	 * 1. 服务标识经 segment 规范化为 snake_case。
	 * 2. 按 {本服务}_{关系}_{对端} 拼接。
	 *
	 * @param string $service 本服务标识。示例："tozo-app-api"
	 * @param string $relation 关系片段｜outbound_to 或 inbound_from。示例："outbound_to"
	 * @param string $peer 对端标识。示例："app-admin-api"
	 * @return string Profile 名称。示例："tozo_app_api_outbound_to_app_admin_api"
	 */
	public static function profileName(string $service, string $relation, string $peer)
	{
		return self::segment($service) . '_' . $relation . '_' . self::segment($peer);
	}
	
	/**
	 * 把服务标识规范化为 snake_case 片段。
	 *
	 * 使用范围：profileName 拼接前处理。
	 * 适用场景：连字符与驼峰统一转下划线，保证 Profile 名可预测。
	 *
	 * 函数逻辑：
	 * 1. 拆驼峰边界后把非字母数字替换为下划线。
	 * 2. 转小写并去除首尾下划线。
	 *
	 * @param string $service 服务标识｜原始形态。示例："tozoApp-api"
	 * @return string 规范化片段。示例："tozo_app_api"
	 */
	private static function segment(string $service)
	{
		$withBoundaries = preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', $service);
		$normalized     = preg_replace('/[^a-zA-Z0-9]+/', '_', (string)$withBoundaries);
		
		return trim(strtolower((string)$normalized), '_');
	}
	
	/**
	 * 生成单个 Profile 的完整配置段。
	 *
	 * 使用范围：normalize 为每个 peer 生成 outbound/inbound 两次调用。
	 * 适用场景：把 19 个恒定字段固化，只按方向填入 5 个真变量。
	 *
	 * 函数逻辑：
	 * 1. 按方向确定 caller/callee，推导两个用途 key_id。
	 * 2. 填入签名、加密、响应完整性、存储、审计各段的内置常量。
	 * 3. token 三开关按 security_mode 决定；plus 模式下按方向开启对应腿。
	 *
	 * @param string $direction 通信方向｜inbound 或 outbound。示例："outbound"
	 * @param string $caller 调用方标识｜签名原文 client_id。示例："tozo-app-api"
	 * @param string $callee 接收方标识｜签名原文 target_service。示例："app-admin-api"
	 * @param string $environment 环境标识｜参与 key_id 命名空间。示例："production"
	 * @param array $options peer 选项｜normalizePeerOptions 结果。示例：["security_mode"=>"signed_request"]
	 * @return array 完整 Profile 配置段。示例：["enabled"=>true,"direction"=>"outbound",...]
	 */
	private static function buildProfile(
		string $direction,
		string $caller,
		string $callee,
		string $environment,
		array  $options
	)
	{
		$mode       = (string)$options['security_mode'];
		$isOutbound = $direction === Profile::DIRECTION_OUTBOUND;
		$tokenLeg   = $mode !== Profile::MODE_SIGNED_REQUEST;
		
		$profile = [
			// enabled bool｜声明 peer 即启用该信任关系。
			'enabled'            => true,
			// direction string｜通信方向；outbound 负责签名，inbound 负责验签。
			'direction'          => $direction,
			// client_id string｜调用方身份；参与签名原文与 AAD 绑定。
			'client_id'          => $caller,
			// subject_type string｜主体类型；内部系统固定 service。
			'subject_type'       => 'service',
			// subject_id string｜主体 ID；与调用方标识一致。
			'subject_id'         => $caller,
			// target_service string｜接收方身份；参与签名原文与 AAD 绑定。
			'target_service'     => $callee,
			// security_mode string｜安全模式；基线 signed_request，可按关系升级。
			'security_mode'      => $mode,
			// signature array｜请求签名段；HMAC-SHA256 完整性与防重放。
			'signature'          => [
				// enabled bool｜token_only 之外的模式均需请求签名。
				'enabled'                      => $mode !== Profile::MODE_TOKEN_ONLY,
				// driver string｜签名算法；协议 v1 白名单唯一值。
				'driver'                       => Profile::DEFAULT_SIGNATURE_DRIVER,
				// key_id string｜请求用途密钥标识；由四元组推导。
				'key_id'                       => self::keyId($environment, $caller, $callee, 'request'),
				// max_age_seconds int｜签名最大年龄。
				'max_age_seconds'              => self::SIGNATURE_MAX_AGE_SECONDS,
				// clock_skew_seconds int｜时钟偏差容忍。
				'clock_skew_seconds'           => self::CLOCK_SKEW_SECONDS,
				// replay_protection bool｜Nonce 防重放登记。
				'replay_protection'            => true,
				// replay_safety_margin_seconds int｜TTL 安全余量。
				'replay_safety_margin_seconds' => self::REPLAY_SAFETY_MARGIN_SECONDS,
			],
			// encryption array｜请求载荷加密段；默认关闭，按关系开启。
			'encryption'         => [
				// enabled bool｜是否加密请求 Body。
				'enabled'             => $options['encryption'] === true,
				// driver string｜加密算法；协议 v1 白名单唯一值。
				'driver'              => Profile::DEFAULT_ENCRYPTION_DRIVER,
				// max_plaintext_bytes int｜明文体积上限，防不可捕获的 OOM。
				'max_plaintext_bytes' => self::MAX_PLAINTEXT_BYTES,
			],
			// response_integrity array｜响应完整性段；调用方验证、被调用方生成。
			'response_integrity' => [
				// required bool｜拒绝没有响应保护的返回。
				'required'  => true,
				// mode string｜响应保护模式；signed 为方向绑定 HMAC。
				'mode'      => 'signed',
				// signature array｜响应专用签名密钥；不得复用请求密钥。
				'signature' => [
					// key_id string｜响应用途密钥标识；由四元组推导。
					'key_id' => self::keyId($environment, $caller, $callee, 'response'),
				],
			],
			// replay_store array｜防重放后端；多实例须为共享缓存。
			'replay_store'       => [
				// driver string｜防重放驱动；协议 v1 白名单唯一值。
				'driver' => 'cache',
			],
			// audit array｜审计后端；四系统统一使用共享缓存。
			'audit'              => [
				// driver string｜审计驱动。
				'driver' => 'cache',
			],
		];
		
		// 加密密钥只在实际开启加密时引用；否则 ConfigChecker 会探测一个无需存在的密钥。
		if ($options['encryption'] === true) {
			$profile['encryption']['key_id'] = self::keyId($environment, $caller, $callee, 'encryption');
		}
		
		// token 段：signed_request 三开关全关；plus/token_only 按方向开启对应腿。
		$profile['token'] = [
			// attach_enabled bool｜出站是否附加 Bearer Token。
			'attach_enabled' => $tokenLeg && $isOutbound,
			// verify_enabled bool｜入站是否验证 Token。
			'verify_enabled' => $tokenLeg && !$isOutbound,
			// issue_enabled bool｜是否在本 Profile 签发 Token。
			'issue_enabled'  => false,
		];
		
		if ($tokenLeg) {
			$profile['token']['driver']         = 'jwt_hs256';
			$profile['token']['issuer']         = $caller;
			$profile['token']['audience']       = [$callee];
			$profile['token']['ttl_seconds']    = 900;
			$profile['token']['signing_key_id'] = self::keyId($environment, $caller, $callee, 'token');
			
			if (!$isOutbound) {
				$profile['token']['allowed_subject_types'] = ['service'];
				$profile['token']['expected_client_id']    = $caller;
				$profile['authentication']                 = ['driver' => 'jwt'];
			}
		}
		
		return $profile;
	}
	
	/**
	 * 推导用途密钥标识。
	 *
	 * 使用范围：buildProfile 为签名/加密/响应/Token 各用途生成标识。
	 * 适用场景：消除手写 24 个 key_id 的负担，同时保证两端推导结果一致。
	 *
	 * 函数逻辑：
	 * 1. 按 {environment}_{caller}_to_{callee}_{usage} 拼接。
	 * 2. 结果必须落在 ConfigChecker::KEY_ID_PATTERN 允许的字符集内。
	 *
	 * @param string $environment 环境标识｜密钥命名空间。示例："production"
	 * @param string $caller 调用方标识。示例："tozo-app-api"
	 * @param string $callee 接收方标识。示例："app-admin-api"
	 * @param string $usage 用途标识｜request/response/token 等。示例："request"
	 * @return string 推导出的 key_id。示例："production_tozo-app-api_to_app-admin-api_request"
	 */
	public static function keyId(string $environment, string $caller, string $callee, string $usage)
	{
		return $environment . '_' . $caller . '_to_' . $callee . '_' . $usage;
	}
	
	/**
	 * 由 Profile 展开结果推导 features 开关。
	 *
	 * 使用范围：normalize 组装内部形态时调用。
	 * 适用场景：消除「开关 true 且被引用」的双重声明，用户不再手写 features。
	 *
	 * 函数逻辑：
	 * 1. 遍历展开后的 Profile，按实际引用的能力置位。
	 * 2. token_issuer 仅在存在 attach/issue 腿时开启，保持默认不签发。
	 *
	 * @param array $profiles Profile 配置表｜展开结果。示例：["a_outbound_to_b"=>[...]]
	 * @return array features 开关表。示例：["signature"=>true,"token_issuer"=>false]
	 */
	private static function deriveFeatures(array $profiles)
	{
		$features = [
			'authentication'     => false,
			'signature'          => false,
			'encryption'         => false,
			'response_integrity' => false,
			'token_verifier'     => false,
			'token_issuer'       => false,
			'token_revocation'   => false,
			'scope'              => false,
			'http_client'        => false,
			'audit'              => false,
		];
		
		foreach ($profiles as $profile) {
			$isInbound = ($profile['direction'] ?? '') === Profile::DIRECTION_INBOUND;
			
			if (($profile['signature']['enabled'] ?? false) === true) {
				$features['signature'] = true;
			}
			
			if (($profile['encryption']['enabled'] ?? false) === true) {
				$features['encryption'] = true;
			}
			
			if (($profile['response_integrity']['required'] ?? false) === true) {
				$features['response_integrity'] = true;
			}
			
			if (($profile['token']['verify_enabled'] ?? false) === true) {
				$features['token_verifier'] = true;
				$features['scope']          = true;
			}
			
			if (($profile['token']['attach_enabled'] ?? false) === true
				|| ($profile['token']['issue_enabled'] ?? false) === true) {
				$features['token_issuer'] = true;
			}
			
			if ($isInbound && isset($profile['authentication']['driver'])) {
				$features['authentication'] = true;
			}
			
			if (!$isInbound) {
				$features['http_client'] = true;
				$features['audit']       = true;
			}
		}
		
		return $features;
	}
	
	/**
	 * 解析密钥提供器配置。
	 *
	 * 使用范围：normalize 组装内部形态时调用。
	 * 适用场景：极简配置默认使用受控目录，不依赖任何环境变量。
	 *
	 * 函数逻辑：
	 * 1. 用户显式声明 key_providers 时原样采用。
	 * 2. 缺省使用 file driver，目录留 null 由 FileKeyProvider 回退 storage 路径。
	 *
	 * @param array $config 原始极简配置。示例：["service"=>"tozo-app-api"]
	 * @return array key_providers 配置段。示例：["driver"=>"file","file"=>["path"=>null]]
	 */
	private static function resolveKeyProviders(array $config)
	{
		if (isset($config['key_providers']) && is_array($config['key_providers'])) {
			return $config['key_providers'];
		}
		
		return [
			// driver string｜密钥来源；file 从受控目录按 {key_id}.key 读取。
			'driver' => 'file',
			// file array｜受控文件提供器参数。
			'file'   => [
				// path string|null｜受控目录；null 时回退 storage_path('app/tozo/keys')。
				'path' => null,
			],
		];
	}
	
	/**
	 * 解析日志配置。
	 *
	 * 使用范围：normalize 组装内部形态时调用。
	 * 适用场景：极简配置无需声明日志参数，保留显式覆盖能力。
	 *
	 * 函数逻辑：
	 * 1. 用户显式声明 logging 时原样采用。
	 * 2. 缺省启用日志、通道 null、级别 info。
	 *
	 * @param array $config 原始极简配置。示例：["service"=>"tozo-app-api"]
	 * @return array logging 配置段。示例：["enabled"=>true,"channel"=>"null","level"=>"info"]
	 */
	private static function resolveLogging(array $config)
	{
		if (isset($config['logging']) && is_array($config['logging'])) {
			return $config['logging'];
		}
		
		return [
			// enabled bool｜是否输出 SDK 安全日志。
			'enabled' => true,
			// channel string｜audit driver=log 时使用的日志通道。
			'channel' => 'null',
			// level string｜审计事件写入级别。
			'level'   => 'info',
		];
	}
	
	/**
	 * 解析出站传输配置。
	 *
	 * 使用范围：normalize 组装内部形态时调用；替代原 tozo_services.php 的 http/tls 段。
	 * 适用场景：超时与 TLS 约束在四系统间完全一致，固化为内置默认。
	 *
	 * 函数逻辑：
	 * 1. 用户显式声明 http 时按键合并，缺失项用内置默认补齐。
	 * 2. TLS 证书校验默认开启，生产不得关闭。
	 *
	 * @param array $config 原始极简配置。示例：["service"=>"tozo-app-api"]
	 * @return array http 配置段。示例：["timeout"=>10,"connect_timeout"=>3,"verify"=>true]
	 */
	private static function resolveHttp(array $config)
	{
		$http = isset($config['http']) && is_array($config['http']) ? $config['http'] : [];
		
		return [
			// timeout int｜读取超时秒数。
			'timeout'         => isset($http['timeout']) ? (int)$http['timeout'] : self::HTTP_TIMEOUT,
			// connect_timeout int｜TCP 连接超时秒数。
			'connect_timeout' => isset($http['connect_timeout'])
				? (int)$http['connect_timeout']
				: self::HTTP_CONNECT_TIMEOUT,
			// verify bool｜是否校验证书链与主机名；生产不可关闭。
			'verify'          => !isset($http['verify']) || $http['verify'] === true,
			// min_version string｜最低 TLS 版本。
			'min_version'     => isset($http['min_version']) && is_string($http['min_version'])
				? (string)$http['min_version']
				: self::TLS_MIN_VERSION,
		];
	}
}
