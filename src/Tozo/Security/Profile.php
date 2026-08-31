<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Profile
 *
 * 文件功能：
 * - 表示一组明确且单向的通信信任关系（inbound/outbound）
 * - 承载认证、签名、加密、响应完整性、Token、Scope 与用途密钥配置
 * - validate() 在启动/config:cache 阶段完成结构校验与安全模式一致性校验
 *
 * 安全边界：
 * - 不持有任何真实密钥，仅保存 key_id；密钥由 KeyProvider 运行期读取
 * - 安全必填项缺失、显式 null、非法 driver 一律抛出 ConfigurationException，不回退默认值
 * - security_mode 与 direction 的开关组合必须满足设计 §10 矩阵
 * - 响应完整性密钥为独立用途，禁止复用请求加密/签名密钥
 */

namespace Tozo\Security;

use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\UnsupportedDriverException;

class Profile
{
	/**
	 * 入站方向：本 Profile 描述"本系统作为被调用方"的验证规则。
	 * 入站解析绝不回退默认 Profile，候选必须唯一。
	 */
	public const DIRECTION_INBOUND = 'inbound';
	
	/**
	 * 出站方向：本 Profile 描述"本系统作为调用方"的签名与附加 Token 规则。
	 * default_profile 只能指向出站 Profile。
	 */
	public const DIRECTION_OUTBOUND = 'outbound';
	
	/**
	 * 安全模式：仅验证 Token（或 HMAC-Bearer 持钥证明），不做请求签名。
	 * 只允许用于评审过的低风险幂等路由，禁止用于写操作与敏感数据修改。
	 */
	public const MODE_TOKEN_ONLY = 'token_only';
	
	/**
	 * 安全模式：仅验证请求签名，签名 key_id 的归属即唯一认证主体。
	 * 禁止叠加 Token 作为第二认证分支，避免出现"两者之一通过即放行"的模糊语义。
	 */
	public const MODE_SIGNED_REQUEST = 'signed_request';
	
	/**
	 * 安全模式：Token 与请求签名必须同时通过（AND 语义）。
	 * 写操作、敏感操作与外部合作方调用的推荐模式；任一失败即拒绝，绝不退化为其他模式。
	 */
	public const MODE_TOKEN_PLUS_REQUEST_SIGNATURE = 'token_plus_request_signature';
	
	/**
	 * 安全模式白名单：Profile 的 security_mode 必须严格命中其中一项。
	 * 首版只支持这三种固定组合，不接受运行时自由拼装认证与签名条件。
	 */
	public const SECURITY_MODES = [
		self::MODE_TOKEN_ONLY,
		self::MODE_SIGNED_REQUEST,
		self::MODE_TOKEN_PLUS_REQUEST_SIGNATURE,
	];
	
	/**
	 * 身份主体类型白名单：service（内部系统）、partner（外部合作方）、user（登录用户）。
	 * 三类权限互不可替代——同名 Scope 在不同主体类型间不产生等价关系。
	 */
	public const SUBJECT_TYPES = ['service', 'partner', 'user'];
	
	/**
	 * 请求签名 driver 白名单。首版仅 HMAC-SHA256；
	 * 请求方不得通过任何 Header 指定算法，服务端只认本白名单。
	 */
	public const SIGNATURE_DRIVERS = ['hmac_sha256'];
	
	/**
	 * 载荷加密 driver 白名单。首版仅 AES-256-GCM（AEAD）；
	 * 不含 CBC 等无完整性保护的算法，避免静默降级。
	 */
	public const ENCRYPTION_DRIVERS = ['aes_256_gcm'];
	
	/**
	 * Token driver 白名单。jwt_rs256 为推荐值（签发方持私钥、验证方仅持公钥）；
	 * jwt_hs256 为共享密钥方案，不建议在多系统间广泛使用。
	 */
	public const TOKEN_DRIVERS = ['jwt_rs256', 'jwt_hs256'];
	
	/**
	 * 认证 driver 白名单：jwt（JWT 体系，验证签发方令牌）与
	 * hmac_bearer_sha256（共享密钥持钥证明，无需签发基础设施）。
	 * 两者的区别在于信任来源：jwt 信任第三方签发者的签名，需配置 issuer 与 kid 白名单；
	 * hmac_bearer 直接以持有共享密钥证明身份，适合无授权中心的双边场景。
	 * 白名单外的取值一律拒绝，不允许请求方通过任何 Header 指定认证方式。
	 */
	public const AUTHENTICATION_DRIVERS = ['jwt', 'hmac_bearer_sha256'];
	
	/**
	 * 签名 driver 缺省值。仅当 Profile 已明确启用签名而未指定 driver 时生效；
	 * 外部合作方 Profile 必须显式声明，不依赖此默认值以免双方理解不一致。
	 */
	public const DEFAULT_SIGNATURE_DRIVER = 'hmac_sha256';
	
	/**
	 * 加密 driver 缺省值。仅当 Profile 已明确启用加密而未指定 driver 时生效。
	 */
	public const DEFAULT_ENCRYPTION_DRIVER = 'aes_256_gcm';
	
	/**
	 * Token driver 缺省值。同时作为 Issuer 与 Verifier 算法映射表的键，
	 * 两侧共用同一常量以保证签发算法与验证算法不会漂移。
	 */
	public const DEFAULT_TOKEN_DRIVER = 'jwt_rs256';
	
	/**
	 * Profile 名称，即配置 profiles 段下的键名。
	 * 用于日志定位、路由绑定（tozo_profile）与 default_profile 引用。
	 *
	 * @var string
	 */
	private $name;
	
	/**
	 * 是否启用。false 时跳过全部结构校验且不进入注册表，
	 * 使模板 Profile 可以带着未注入的 key_id 安全地留在配置文件中。
	 *
	 * @var bool
	 */
	private $enabled;
	
	/**
	 * 通信方向，取值为 inbound 或 outbound。
	 * 决定模式矩阵校验的是验证侧开关还是附加侧开关。
	 *
	 * @var string
	 */
	private $direction;
	
	/**
	 * 调用方唯一标识。参与签名原文与 AEAD AAD 的绑定，
	 * 同时作为入站 Profile 候选查找的不可信索引依据。
	 *
	 * @var string
	 */
	private $clientId;
	
	/**
	 * 本端主体类型（service/partner/user）。
	 * 签发时构成 sub 前缀，signed_request 模式下用于构造签名主体。
	 *
	 * @var string
	 */
	private $subjectType;
	
	/**
	 * 本端主体 ID。与 subjectType 组成规范形态 sub=type:id 写入签发的令牌，
	 * 因此只在需要签发 Token 或 signed_request 构造签名主体时必填，纯验证方可为 null。
	 * 它标识的是**本端自己**，与 clientId 在出站 Profile 中通常同值；
	 * 入站 Profile 不用它——那时主体来自对端令牌而非本端配置。
	 *
	 * @var string|null
	 */
	private $subjectId;
	
	/**
	 * 目标服务标识。参与签名原文与 AAD 绑定，
	 * 使同一份密文/签名无法被复用到另一个接收方。
	 *
	 * @var string
	 */
	private $targetService;
	
	/**
	 * 安全模式，取值见 SECURITY_MODES。
	 * 是"必须满足哪些验证条件"的唯一定义点，不允许运行时改变。
	 *
	 * @var string
	 */
	private $securityMode;
	
	/**
	 * 认证段原始配置。含 driver（jwt / hmac_bearer_sha256）与
	 * hmac_bearer 场景必填的 key_id。非数组形态在构造时归一为空数组。
	 *
	 * @var array
	 */
	private $authentication;
	
	/**
	 * 请求签名段原始配置。含 enabled、driver、key_id 与四个时间窗参数
	 * （max_age_seconds / clock_skew_seconds / replay_protection / replay_safety_margin_seconds）。
	 * 保存原始数组而非拆成独立属性，是因为这些值要整段传给 Signer，
	 * 拆开会让新增参数时需同步改动多处。
	 * enabled=false 时其余字段不参与校验，使 token_only 模式无需填写签名参数。
	 *
	 * @var array
	 */
	private $signature;
	
	/**
	 * 请求加密段原始配置。含 enabled、driver 与 key_id；
	 * 此处的 key_id 只用于请求方向，响应方向另有独立密钥。
	 *
	 * @var array
	 */
	private $encryption;
	
	/**
	 * 响应完整性段原始配置。含 required、固定 mode（encrypted / signed）
	 * 与对应的 encryption.key_id 或 signature.key_id。
	 * mode 必须在配置期固定而不能由响应内容决定——否则攻击者可通过剥离保护头
	 * 把 signed 响应降级为无保护响应。
	 * required=true 时未受保护的响应一律拒绝，这是调用端的最后一道防线。
	 *
	 * @var array
	 */
	private $responseIntegrity;
	
	/**
	 * Token 段原始配置。含 attach/verify/issue 三个方向开关、driver、
	 * issuer、audience、ttl、allowed_kids、expected_client_id 等全部 claims 绑定基准。
	 * 三个开关必须与 Profile 方向自洽：入站只允许 verify，出站只允许 attach/issue；
	 * 不自洽的组合在校验期即失败，不留到运行期产生「签了但没人验」这类静默失效。
	 * 全部 claims 基准集中在此段，使验证器不必从多处拼装绑定条件。
	 *
	 * @var array
	 */
	private $token;
	
	/**
	 * Scope 段原始配置。allowed_scopes 为权限白名单，首版禁止通配符；
	 * 读取时优先本段，缺失才回退 token.allowed_scopes。
	 *
	 * @var array
	 */
	private $scope;
	
	/**
	 * 防重放存储段原始配置。首版 driver 仅支持 cache。
	 * 该后端**必须是多实例共享的**（Redis 等）：进程内数组或单机文件无法提供
	 * 跨实例的「只写一次」语义，多实例部署下同一个 Nonce 会在不同实例各被放行一次，
	 * 防重放形同失效且不产生任何报错。这一点无法由 SDK 校验，须部署方保证。
	 *
	 * @var array
	 */
	private $replayStore;
	
	/**
	 * Token 吊销段原始配置。enabled 为 true 时验证器才实际查询 jti；
	 * 与防重放是两个独立契约，禁止混用同一条记录语义。
	 *
	 * @var array
	 */
	private $tokenRevocation;
	
	/**
	 * 审计段原始配置。driver 取 cache（共享缓存，便于程序化查询）或
	 * log（Laravel 日志通道，便于接入既有日志采集）。
	 * AuditSink 是宿主内的共享绑定，因此全部出站 Profile 必须选同一 driver——
	 * 混用会让容器无法同时满足两者，该冲突在启动期即被拒绝。
	 *
	 * @var array
	 */
	private $audit;
	
	/**
	 * 密钥提供器。Profile 自身不持有任何真实密钥，
	 * 仅保存该通道供运行期按 key_id 检索，使配置与密钥来源解耦。
	 *
	 * @var KeyProviderInterface
	 */
	private $keyProvider;
	
	/**
	 * 构造 Profile 并装载各配置段。
	 *
	 * 使用范围：fromConfig 内部在三层合并完成后调用。
	 * 适用场景：把原始数组固化为类型化字段，供全部 getter 与 validate 使用。
	 *
	 * 函数逻辑：
	 * 1. 逐段读取标量与子数组；非法形态回退空数组/缺省值。
	 * 2. 保存注入的密钥提供器供 getKeyProvider 使用。
	 *
	 * @param string $name Profile 名称｜注册表键。示例："order_inbound"
	 * @param array $config 配置数组｜合并后的原始段。示例：['direction'=>'outbound',...]
	 * @param KeyProviderInterface $keyProvider 密钥提供器｜运行期密钥检索通道。示例：new ArrayKeyProvider([...])
	 * @return void 无返回值。
	 */
	public function __construct(string $name, array $config, KeyProviderInterface $keyProvider)
	{
		$this->name              = $name;
		$this->enabled           = ($config['enabled'] ?? true) === true;
		$this->direction         = (string)($config['direction'] ?? '');
		$this->clientId          = (string)($config['client_id'] ?? '');
		$this->subjectType       = (string)($config['subject_type'] ?? 'service');
		$this->subjectId         = isset($config['subject_id']) && $config['subject_id'] !== null
			? (string)$config['subject_id']
			: null;
		$this->targetService     = (string)($config['target_service'] ?? '');
		$this->securityMode      = (string)($config['security_mode'] ?? '');
		$this->authentication    = is_array($config['authentication'] ?? null) ? $config['authentication'] : [];
		$this->signature         = is_array($config['signature'] ?? null) ? $config['signature'] : [];
		$this->encryption        = is_array($config['encryption'] ?? null) ? $config['encryption'] : [];
		$this->responseIntegrity = is_array($config['response_integrity'] ?? null) ? $config['response_integrity'] : [];
		$this->token             = is_array($config['token'] ?? null) ? $config['token'] : [];
		$this->scope             = is_array($config['scope'] ?? null) ? $config['scope'] : [];
		$this->replayStore       = is_array($config['replay_store'] ?? null) ? $config['replay_store'] : [];
		$this->tokenRevocation   = is_array($config['token_revocation'] ?? null) ? $config['token_revocation'] : [];
		$this->audit             = is_array($config['audit'] ?? null) ? $config['audit'] : [];
		$this->keyProvider       = $keyProvider;
	}
	
	/**
	 * 从应用配置构建 Profile 并立即执行结构校验。
	 *
	 * 使用范围：ServiceProvider.buildProfileRegistry、测试夹具构造。
	 * 适用场景：把 tozo_security.profiles.* 原始数组固化为已校验对象。
	 *
	 * 函数逻辑：
	 * 1. applyAppDefaults 执行三层合并的第二层。
	 * 2. new self 后调用 validate()，失败即抛配置异常。
	 * @param string $name Profile 名称｜注册表键。示例："order_inbound"
	 * @param array $config 配置数组｜Profile 原始配置段。示例：["direction"=>"outbound",...]
	 * @param KeyProviderInterface $keyProvider 密钥提供器｜按 key_id 检索真实密钥。示例：new ArrayKeyProvider([...])
	 * @param array $appDefaults 应用级默认值｜tozo_security.defaults 段。示例：["signature"=>["max_age_seconds"=>300]]
	 * @return self 构建并校验通过的 Profile 实例。示例：同一实例
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	public static function fromConfig(
		string               $name,
		array                $config,
		KeyProviderInterface $keyProvider,
		array                $appDefaults = []
	)
	{
		self::rejectExplicitNulls($name, $config);
		self::validateRawTypes($name, $config);
		$config = self::applyAppDefaults($config, $appDefaults);
		self::rejectExplicitNulls($name, $config);
		self::validateRawTypes($name, $config);
		$profile = new self($name, $config, $keyProvider);
		$profile->validate();
		
		return $profile;
	}
	
	/**
	 * 拒绝 Profile 配置树中的显式 null，避免 null 被误解为关闭或默认值。
	 *
	 * 使用范围：fromConfig 的三层配置合并之前。
	 * 适用场景：区分“省略配置”与“明确关闭”，防止安全开关静默降级。
	 * 函数逻辑：
	 * 1. 递归检查所有配置段并保留完整点号路径。
	 * 2. subject_id 是签发场景的可选行为字段，允许显式 null；其他字段必须省略或提供有效值。
	 * @param string $name Profile 名称｜用于异常定位。示例："order_inbound"
	 * @param array $config Profile 原始配置段。示例：["signature"=>["enabled"=>true]]
	 * @param string $prefix 当前递归路径。示例："signature"
	 * @return void 发现显式 null 时抛出 ConfigurationException。
	 * @throws ConfigurationException 安全配置显式为 null 时抛出。
	 */
	private static function rejectExplicitNulls(string $name, array $config, string $prefix = '')
	{
		foreach ($config as $key => $value) {
			$path = $prefix === '' ? (string)$key : $prefix . '.' . $key;
			
			if ($value === null && $path !== 'subject_id') {
				throw new ConfigurationException(
					"Profile [{$name}] field [{$path}] must not be null; omit it or use an explicit value"
				);
			}
			
			if (is_array($value)) {
				self::rejectExplicitNulls($name, $value, $path);
			}
		}
	}
	
	/**
	 * 校验安全配置显式字段的原生类型。
	 *
	 * 使用范围：fromConfig 合并默认值之前。
	 * 适用场景：阻止字符串/整数开关被静默解释为 false，避免绕过启用 Profile 的完整校验。
	 * 函数逻辑：
	 * 1. 逐个检查顶层 enabled、功能段数组和安全开关。
	 * 2. 显式配置类型不匹配时立即抛出，不把错误归一化为缺省值。
	 * @param string $name Profile 名称｜用于异常定位。示例："order_inbound"
	 * @param array $config Profile 原始配置段。示例：["enabled"=>true,"signature"=>[...]]
	 * @return void 类型全部有效时静默返回。
	 * @throws ConfigurationException 显式配置类型非法时抛出。
	 */
	private static function validateRawTypes(string $name, array $config)
	{
		self::assertBooleanField($name, $config, 'enabled');
		
		foreach (['direction', 'client_id', 'subject_type', 'target_service', 'security_mode'] as $field) {
			self::assertStringField($name, $config, $field);
		}
		
		if (array_key_exists('subject_id', $config)
			&& $config['subject_id'] !== null
			&& !is_string($config['subject_id'])) {
			throw new ConfigurationException(
				"Profile [{$name}] field [subject_id] must be string or null"
			);
		}
		
		foreach ([
			         'authentication',
			         'signature',
			         'encryption',
			         'response_integrity',
			         'token',
			         'scope',
			         'replay_store',
			         'token_revocation',
			         'audit',
		         ] as $section) {
			if (array_key_exists($section, $config) && !is_array($config[$section])) {
				throw new ConfigurationException(
					"Profile [{$name}] field [{$section}] must be an array"
				);
			}
		}
		
		foreach ([
			         ['signature', 'enabled'],
			         ['signature', 'replay_protection'],
			         ['encryption', 'enabled'],
			         ['response_integrity', 'required'],
			         ['token', 'attach_enabled'],
			         ['token', 'verify_enabled'],
			         ['token', 'issue_enabled'],
			         ['token_revocation', 'enabled'],
		         ] as $field) {
			$section = $field[0];
			$key     = $field[1];
			
			if (isset($config[$section])
				&& is_array($config[$section])
				&& array_key_exists($key, $config[$section])
				&& !is_bool($config[$section][$key])) {
				throw new ConfigurationException(
					"Profile [{$name}] field [{$section}.{$key}] must be boolean"
				);
			}
		}
	}
	
	/**
	 * 校验单个显式布尔字段。
	 *
	 * 使用范围：validateRawTypes 顶层开关检查。
	 * 适用场景：保持“省略”和“显式非布尔值”的语义边界。
	 * @param string $name Profile 名称｜用于异常定位。示例："order_inbound"
	 * @param array $config Profile 原始配置段。
	 * @param string $field 字段路径。示例："enabled"
	 * @return void 类型有效时静默返回。
	 * @throws ConfigurationException 字段存在但不是布尔值时抛出。
	 */
	private static function assertBooleanField(string $name, array $config, string $field)
	{
		if (array_key_exists($field, $config) && !is_bool($config[$field])) {
			throw new ConfigurationException(
				"Profile [{$name}] field [{$field}] must be boolean"
			);
		}
	}
	
	/**
	 * 校验单个显式字符串字段。
	 *
	 * 使用范围：validateRawTypes 基础身份与模式字段检查。
	 * 适用场景：禁止整数/布尔值经过强制转换后伪装成合法身份标识。
	 * @param string $name Profile 名称｜用于异常定位。示例："order_inbound"
	 * @param array $config Profile 原始配置段。
	 * @param string $field 字段名。示例："client_id"
	 * @return void 类型有效时静默返回。
	 * @throws ConfigurationException 字段存在但不是字符串时抛出。
	 */
	private static function assertStringField(string $name, array $config, string $field)
	{
		if (array_key_exists($field, $config) && !is_string($config[$field])) {
			throw new ConfigurationException(
				"Profile [{$name}] field [{$field}] must be string"
			);
		}
	}
	
	/**
	 * 应用级默认值第二层合并。
	 *
	 * 使用范围：fromConfig 内部调用。
	 * 适用场景：Profile 缺 max_age_seconds 时用 defaults 补齐；显式 null 不覆盖。
	 *
	 * 函数逻辑：
	 * 1. 遍历 signature/encryption/token 三段。
	 * 2. 仅 array_key_exists 不存在时填充默认值。
	 * @param array $config 配置数组｜Profile 原始配置段。示例：["direction"=>"outbound",...]
	 * @param array $defaults 默认值段｜待合并子树。示例：["token"=>["ttl_seconds"=>900]]
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private static function applyAppDefaults(array $config, array $defaults)
	{
		foreach (['signature', 'encryption', 'token'] as $section) {
			if (!isset($defaults[$section]) || !is_array($defaults[$section])) {
				continue;
			}
			
			$base = isset($config[$section]) && is_array($config[$section]) ? $config[$section] : [];
			foreach ($defaults[$section] as $field => $value) {
				if (!array_key_exists($field, $base)) {
					$base[$field] = $value;
				}
			}
			$config[$section] = $base;
		}
		
		return $config;
	}
	
	/**
	 * 执行全量结构校验与安全模式一致性矩阵。
	 *
	 * 使用范围：fromConfig 与 HttpClient.setProfile 即时校验。
	 * 适用场景：拦截 key_id 缺失、模式组合矛盾等问题在启动期即失败。
	 *
	 * 函数逻辑：
	 * 1. 未启用直接返回。
	 * 2. 依次校验基础字段/签名/认证/加密/响应完整性/Token/Scope/存储。
	 * 3. 最后执行安全模式一致性矩阵。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	public function validate()
	{
		if ($this->name === '') {
			throw new ConfigurationException('Profile name is required');
		}
		
		if (!$this->enabled) {
			// 未启用的 Profile 不参与运行，跳过后续校验（由 Registry 过滤）。
			return;
		}
		
		if ($this->direction !== self::DIRECTION_INBOUND && $this->direction !== self::DIRECTION_OUTBOUND) {
			throw new ConfigurationException("Profile [{$this->name}] direction must be inbound or outbound");
		}
		
		if (!in_array($this->securityMode, self::SECURITY_MODES, true)) {
			throw new ConfigurationException(
				"Profile [{$this->name}] security_mode must be one of: " . implode(', ', self::SECURITY_MODES)
			);
		}
		
		if ($this->clientId === '') {
			throw new ConfigurationException("Profile [{$this->name}] client_id is required");
		}
		
		if (!in_array($this->subjectType, self::SUBJECT_TYPES, true)) {
			throw new ConfigurationException("Profile [{$this->name}] subject_type must be one of: "
				. implode(', ', self::SUBJECT_TYPES));
		}
		
		if ($this->targetService === '') {
			throw new ConfigurationException("Profile [{$this->name}] target_service is required");
		}
		
		$this->validateSignature();
		$this->validateAuthentication();
		$this->validateEncryption();
		$this->validateResponseIntegrity();
		$this->validateToken();
		$this->validateScope();
		$this->validateStores();
		$this->validateSecurityModeConsistency();
	}
	
	/**
	 * 校验签名段结构与 driver 白名单。
	 *
	 * 使用范围：validate 内部调用。
	 * 适用场景：拦截 hmac 之外 driver、key_id 缺失、数值非法。
	 *
	 * 函数逻辑：
	 * 1. enabled!==true 返回。
	 * 2. driver 白名单；key_id 必填；数值字段类型与正性检查。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private function validateSignature()
	{
		if (($this->signature['enabled'] ?? false) !== true) {
			return;
		}
		
		$driver = (string)($this->signature['driver'] ?? self::DEFAULT_SIGNATURE_DRIVER);
		if (!in_array($driver, self::SIGNATURE_DRIVERS, true)) {
			throw new UnsupportedDriverException(
				"Profile [{$this->name}] unsupported signature driver [{$driver}]"
			);
		}
		
		if ($this->getSignatureKeyId() === null) {
			throw new ConfigurationException("Profile [{$this->name}] signature.key_id is required when enabled");
		}
		
		foreach (['max_age_seconds', 'clock_skew_seconds', 'replay_safety_margin_seconds'] as $field) {
			if (array_key_exists($field, $this->signature) && !is_numeric($this->signature[$field])) {
				throw new ConfigurationException("Profile [{$this->name}] signature.{$field} must be numeric");
			}
		}
		
		if ($this->getSignatureMaxAgeSeconds() <= 0) {
			throw new ConfigurationException("Profile [{$this->name}] signature.max_age_seconds must be positive");
		}
	}
	
	/**
	 * 返回签名用途 key_id。
	 *
	 * 使用范围：Signer 检索密钥与白名单比对。
	 * 适用场景：HMAC 用途密钥标识读取。
	 *
	 * 函数逻辑：
	 * 1. 合法非空返回否则 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getSignatureKeyId()
	{
		return isset($this->signature['key_id']) && is_string($this->signature['key_id'])
		&& $this->signature['key_id'] !== ''
			? $this->signature['key_id']
			: null;
	}
	
	/**
	 * 返回签名最大年龄(秒)。
	 *
	 * 使用范围：verify 时间窗计算。
	 * 适用场景：默认 300，可按链路收紧。
	 *
	 * 函数逻辑：
	 * 1. signature.max_age_seconds ?? 300 强转 int。
	 * @return int 整型值（秒/数量）。示例：425
	 */
	public function getSignatureMaxAgeSeconds()
	{
		return (int)($this->signature['max_age_seconds'] ?? 300);
	}
	
	/**
	 * 校验认证段 driver 白名单与 key_id。
	 *
	 * 使用范围：validate 内部调用。
	 * 适用场景：hmac_bearer_sha256 必须显式声明 authentication.key_id。
	 *
	 * 函数逻辑：
	 * 1. 无 driver 返回。
	 * 2. driver 白名单校验。
	 * 3. hmac_bearer 场景强制 key_id。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private function validateAuthentication()
	{
		$driver = $this->getAuthenticationDriver();
		if ($driver === null) {
			return;
		}
		
		if (!in_array($driver, self::AUTHENTICATION_DRIVERS, true)) {
			throw new UnsupportedDriverException(
				"Profile [{$this->name}] unsupported authentication driver [{$driver}]"
			);
		}
		
		if ($this->isOutbound() && $driver === 'hmac_bearer_sha256') {
			throw new ConfigurationException(
				"Profile [{$this->name}] hmac_bearer_sha256 is an inbound authentication driver"
			);
		}
		
		if ($driver === 'hmac_bearer_sha256' && $this->getAuthenticationKeyId() === null) {
			throw new ConfigurationException(
				"Profile [{$this->name}] authentication.key_id is required for hmac_bearer_sha256"
			);
		}
	}
	
	/**
	 * 返回认证 driver。
	 *
	 * 使用范围：ServiceProvider 认证器装配选择。
	 * 适用场景：jwt 与 hmac_bearer_sha256 切换依据。
	 *
	 * 函数逻辑：
	 * 1. 读 authentication.driver，缺省 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getAuthenticationDriver()
	{
		return isset($this->authentication['driver']) && is_string($this->authentication['driver'])
			? $this->authentication['driver']
			: null;
	}
	
	/**
	 * 判断是否出站方向。
	 *
	 * 使用范围：OutboundSignerMiddleware 解析校验。
	 * 适用场景：调用端配置专用。
	 *
	 * 函数逻辑：
	 * 1. direction===outbound。
	 * @return bool 布尔判定结果。示例：true
	 */
	public function isOutbound()
	{
		return $this->direction === self::DIRECTION_OUTBOUND;
	}
	
	/**
	 * 返回认证用途 key_id。
	 *
	 * 使用范围：HmacBearerAuthenticator 白名单比对。
	 * 适用场景：共享密钥认证场景必填项读取。
	 *
	 * 函数逻辑：
	 * 1. 读 authentication.key_id，非法返 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getAuthenticationKeyId()
	{
		return isset($this->authentication['key_id']) && is_string($this->authentication['key_id'])
		&& $this->authentication['key_id'] !== ''
			? $this->authentication['key_id']
			: null;
	}
	
	/**
	 * 校验加密段结构。
	 *
	 * 使用范围：validate 内部调用。
	 * 适用场景：仅允许 aes_256_gcm；启用时 key_id 必填。
	 *
	 * 函数逻辑：
	 * 1. enabled!==true 返回。
	 * 2. driver 白名单；key_id 必填。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private function validateEncryption()
	{
		if (($this->encryption['enabled'] ?? false) !== true) {
			return;
		}
		
		$driver = (string)($this->encryption['driver'] ?? self::DEFAULT_ENCRYPTION_DRIVER);
		if (!in_array($driver, self::ENCRYPTION_DRIVERS, true)) {
			throw new UnsupportedDriverException(
				"Profile [{$this->name}] unsupported encryption driver [{$driver}]"
			);
		}
		
		if ($this->getEncryptionKeyId() === null) {
			throw new ConfigurationException("Profile [{$this->name}] encryption.key_id is required when enabled");
		}
		
		// 体积上限若被显式配置，必须是正整数：写成 0 或负数会让闸门形同虚设，
		// 属于配置错误而不是"不限制"（不限制应当直接省略该键）。
		if (array_key_exists('max_plaintext_bytes', $this->encryption)) {
			$limit = $this->encryption['max_plaintext_bytes'];
			
			if (!is_numeric($limit) || (int)$limit <= 0) {
				throw new ConfigurationException(
					"Profile [{$this->name}] encryption.max_plaintext_bytes must be a positive integer"
				);
			}
		}
	}
	
	/**
	 * 返回请求加密 key_id。
	 *
	 * 使用范围：信封白名单比对与密钥检索。
	 * 适用场景：请求与响应密钥隔离的请求侧标识。
	 *
	 * 函数逻辑：
	 * 1. 合法非空返回否则 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getEncryptionKeyId()
	{
		return isset($this->encryption['key_id']) && is_string($this->encryption['key_id'])
		&& $this->encryption['key_id'] !== ''
			? $this->encryption['key_id']
			: null;
	}
	
	/**
	 * 校验响应完整性 mode 固定与用途密钥隔离。
	 *
	 * 使用范围：validate 内部调用。
	 * 适用场景：encrypted 必须配响应加密密钥且不得复用请求密钥；signed 同理。
	 *
	 * 函数逻辑：
	 * 1. required!==true 返回。
	 * 2. mode 白名单 encrypted|signed。
	 * 3. 对应子段 key_id 必填并与请求密钥比对去重。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private function validateResponseIntegrity()
	{
		if (($this->responseIntegrity['required'] ?? false) !== true) {
			return;
		}
		
		$mode = (string)($this->responseIntegrity['mode'] ?? '');
		if ($mode !== 'encrypted' && $mode !== 'signed') {
			throw new ConfigurationException(
				"Profile [{$this->name}] response_integrity.mode must be encrypted or signed"
			);
		}
		
		if ($mode === 'encrypted') {
			$respKeyId = $this->responseIntegrity['encryption']['key_id'] ?? null;
			if (!is_string($respKeyId) || $respKeyId === '') {
				throw new ConfigurationException(
					"Profile [{$this->name}] response_integrity.encryption.key_id is required in encrypted mode"
				);
			}
			
			// 响应加密密钥不得复用请求加密密钥（独立用途）。
			if ($this->getEncryptionKeyId() !== null && $respKeyId === $this->getEncryptionKeyId()) {
				throw new ConfigurationException(
					"Profile [{$this->name}] response encryption key must differ from request encryption key"
				);
			}
		}
		
		if ($mode === 'signed') {
			$sigKeyId = $this->responseIntegrity['signature']['key_id'] ?? null;
			if (!is_string($sigKeyId) || $sigKeyId === '') {
				throw new ConfigurationException(
					"Profile [{$this->name}] response_integrity.signature.key_id is required in signed mode"
				);
			}
			
			// 响应签名密钥不得复用请求签名密钥（独立用途）。
			if ($this->getSignatureKeyId() !== null && $sigKeyId === $this->getSignatureKeyId()) {
				throw new ConfigurationException(
					"Profile [{$this->name}] response signature key must differ from request signature key"
				);
			}
		}
	}
	
	/**
	 * 校验 Token 段方向开关与必填项。
	 *
	 * 使用范围：validate 内部调用。
	 * 适用场景：attach/verify/issue 各自的 issuer/audience/kids/subject_id 等前置齐全。
	 *
	 * 函数逻辑：
	 * 1. 三开关全关返回。
	 * 2. driver/issuer/audience/ttl 公共校验。
	 * 3. attach|issue 需 signing_key_id；issue 需 subject_id。
	 * 4. verify 需类型白名单/expected_client_id/kids 或 hs256 密钥；allowed_tenants 条目非空。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private function validateToken()
	{
		$attach = $this->isTokenAttachEnabled();
		$verify = $this->isTokenVerifyEnabled();
		$issue  = $this->isTokenIssueEnabled();
		
		// Token 开关必须与 Profile 方向一致，避免无关开关触发错误的依赖注册或执行分支。
		if ($this->isInbound() && ($attach || $issue)) {
			throw new ConfigurationException(
				"Profile [{$this->name}] inbound profiles only allow token.verify_enabled"
			);
		}
		
		if ($this->isOutbound() && $verify) {
			throw new ConfigurationException(
				"Profile [{$this->name}] outbound profiles do not allow token.verify_enabled"
			);
		}
		
		// 吊销记录只由入站 Token 验证器消费，不能配置在出站或无验证腿的 Profile 上。
		if ($this->isTokenRevocationEnabled() && (!$this->isInbound() || !$verify)) {
			throw new ConfigurationException(
				"Profile [{$this->name}] token_revocation.enabled requires inbound token.verify_enabled=true"
			);
		}
		
		if (!$attach && !$verify && !$issue) {
			return;
		}
		
		$driver = $this->getTokenDriver();
		if (!in_array($driver, self::TOKEN_DRIVERS, true)) {
			throw new UnsupportedDriverException("Profile [{$this->name}] unsupported token driver [{$driver}]");
		}
		
		if ($this->getTokenIssuer() === null) {
			throw new ConfigurationException("Profile [{$this->name}] token.issuer is required when token enabled");
		}
		
		if ($this->getTokenAudience() === []) {
			throw new ConfigurationException("Profile [{$this->name}] token.audience is required when token enabled");
		}
		
		if ($this->getTokenTtlSeconds() <= 0) {
			throw new ConfigurationException("Profile [{$this->name}] token.ttl_seconds must be positive");
		}
		
		if (($attach || $issue) && $this->getTokenSigningKeyId() === null) {
			throw new ConfigurationException(
				"Profile [{$this->name}] token.signing_key_id is required for attach/issue"
			);
		}
		
		if ($issue && $this->subjectId === null) {
			throw new ConfigurationException(
				"Profile [{$this->name}] subject_id is required when issue_enabled (sub=subject_type:subject_id)"
			);
		}
		
		if ($verify) {
			// 入站 Token 验证必须明确选择 jwt 或 HMAC-Bearer 认证器；
			// 否则 Profile 能通过结构校验，却只能在首个请求运行到中间件时才暴露缺失依赖。
			if ($this->getAuthenticationDriver() === null) {
				throw new ConfigurationException(
					"Profile [{$this->name}] authentication.driver is required when verify_enabled"
				);
			}
			
			if ($this->getAllowedSubjectTypes() === []) {
				throw new ConfigurationException(
					"Profile [{$this->name}] token.allowed_subject_types is required when verify_enabled"
				);
			}
			
			if ($this->getExpectedClientId() === null) {
				throw new ConfigurationException(
					"Profile [{$this->name}] token.expected_client_id is required for inbound verification"
				);
			}
			
			if ($driver === 'jwt_rs256' && $this->getAllowedKids() === []) {
				throw new ConfigurationException(
					"Profile [{$this->name}] token.allowed_kids map is required for jwt_rs256 verification"
				);
			}
			
			foreach ($this->getAllowedTenants() as $tenant) {
				if ($tenant === '') {
					throw new ConfigurationException(
						"Profile [{$this->name}] token.allowed_tenants entries must be non-empty strings"
					);
				}
			}
			
			if ($driver === 'jwt_hs256' && $this->getTokenSigningKeyId() === null) {
				throw new ConfigurationException(
					"Profile [{$this->name}] token.signing_key_id is required for jwt_hs256 verification"
				);
			}
		}
	}
	
	/**
	 * 返回出站附加开关。
	 *
	 * 使用范围：HttpClient/Middleware 决定是否带 Token。
	 * 适用场景：plus 模式出站腿判定依据。
	 *
	 * 函数逻辑：
	 * 1. token.attach_enabled===true。
	 * @return bool 布尔判定结果。示例：true
	 */
	public function isTokenAttachEnabled()
	{
		return ($this->token['attach_enabled'] ?? false) === true;
	}
	
	/**
	 * 返回入站验证开关。
	 *
	 * 使用范围：Verifier 前置条件与模式矩阵。
	 * 适用场景：plus/token_only 入站腿判定依据。
	 *
	 * 函数逻辑：
	 * 1. token.verify_enabled===true。
	 * @return bool 布尔判定结果。示例：true
	 */
	public function isTokenVerifyEnabled()
	{
		return ($this->token['verify_enabled'] ?? false) === true;
	}
	
	/**
	 * 返回签发开关。
	 *
	 * 使用范围：Issuer 前置条件。
	 * 适用场景：仅授权系统为 true。
	 *
	 * 函数逻辑：
	 * 1. token.issue_enabled===true。
	 * @return bool 布尔判定结果。示例：true
	 */
	public function isTokenIssueEnabled()
	{
		return ($this->token['issue_enabled'] ?? false) === true;
	}
	
	/**
	 * 判断是否入站方向。
	 *
	 * 使用范围：模式矩阵与候选过滤。
	 * 适用场景：服务端验证分支判定。
	 *
	 * 函数逻辑：
	 * 1. direction===inbound。
	 * @return bool 布尔判定结果。示例：true
	 */
	public function isInbound()
	{
		return $this->direction === self::DIRECTION_INBOUND;
	}
	
	/**
	 * 返回吊销开关。
	 *
	 * 使用范围：Verifier 是否执行 jti 查询。
	 * 适用场景：高安全链路建议开启。
	 *
	 * 函数逻辑：
	 * 1. token_revocation.enabled===true。
	 * @return bool 布尔判定结果。示例：true
	 */
	public function isTokenRevocationEnabled()
	{
		return ($this->tokenRevocation['enabled'] ?? false) === true;
	}
	
	/**
	 * 返回 Token driver。
	 *
	 * 使用范围：固定算法选择。
	 * 适用场景：jwt_rs256/jwt_hs256 二选一。
	 *
	 * 函数逻辑：
	 * 1. token.driver ?? jwt_rs256。
	 * @return string 字符串值。示例："order-api"
	 */
	public function getTokenDriver()
	{
		return (string)($this->token['driver'] ?? self::DEFAULT_TOKEN_DRIVER);
	}
	
	/**
	 * 返回允许 issuer。
	 *
	 * 使用范围：iss 绑定比对基准。
	 * 适用场景：多签发方体系区分来源。
	 *
	 * 函数逻辑：
	 * 1. 合法非空返回否则 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getTokenIssuer()
	{
		return isset($this->token['issuer']) && is_string($this->token['issuer'])
		&& $this->token['issuer'] !== ''
			? $this->token['issuer']
			: null;
	}
	
	/**
	 * 返回允许 audience 列表。
	 *
	 * 使用范围：aud 交集校验与签发写入。
	 * 适用场景：归一化为字符串数组。
	 *
	 * 函数逻辑：
	 * 1. 标量转单元素数组。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getTokenAudience()
	{
		$audience = $this->token['audience'] ?? [];
		
		return is_array($audience) ? array_map('strval', $audience) : [$audience];
	}
	
	/**
	 * 返回 Token 有效期(秒)。
	 *
	 * 使用范围：签发 exp 计算。
	 * 适用场景：默认 900 短时效。
	 *
	 * 函数逻辑：
	 * 1. token.ttl_seconds ?? 900。
	 * @return int 整型值（秒/数量）。示例：425
	 */
	public function getTokenTtlSeconds()
	{
		return (int)($this->token['ttl_seconds'] ?? 900);
	}
	
	/**
	 * 返回 Token 签名 key_id。
	 *
	 * 使用范围：私钥检索与 kid Header 取值。
	 * 适用场景：RS256 私钥/HS256 共享密钥标识。
	 *
	 * 函数逻辑：
	 * 1. 合法非空返回否则 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getTokenSigningKeyId()
	{
		return isset($this->token['signing_key_id']) && is_string($this->token['signing_key_id'])
		&& $this->token['signing_key_id'] !== ''
			? $this->token['signing_key_id']
			: null;
	}
	
	/**
	 * 返回主体类型白名单。
	 *
	 * 使用范围：入站验证与 Scope 授权。
	 * 适用场景：三类主体权限隔离。
	 *
	 * 函数逻辑：
	 * 1. 归一化字符串数组。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getAllowedSubjectTypes()
	{
		$types = $this->token['allowed_subject_types'] ?? [];
		
		return is_array($types) ? array_map('strval', $types) : [];
	}
	
	/**
	 * 返回期望客户端标识。
	 *
	 * 使用范围：入站 client 绑定比对。
	 * 适用场景：防 Header 冒充的密码学基准。
	 *
	 * 函数逻辑：
	 * 1. 合法非空返回否则 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getExpectedClientId()
	{
		return isset($this->token['expected_client_id']) && is_string($this->token['expected_client_id'])
		&& $this->token['expected_client_id'] !== ''
			? $this->token['expected_client_id']
			: null;
	}
	
	/**
	 * 返回 kid=>key_id 映射。
	 *
	 * 使用范围：RS256 验证白名单构建。
	 * 适用场景：公钥轮换并存与未知 kid 拒绝。
	 *
	 * 函数逻辑：
	 * 1. 过滤合法键值后返回。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getAllowedKids()
	{
		$kids = $this->token['allowed_kids'] ?? [];
		
		if (!is_array($kids)) {
			return [];
		}
		
		$map = [];
		foreach ($kids as $kid => $keyId) {
			if (is_string($kid) && is_string($keyId) && $kid !== '' && $keyId !== '') {
				$map[$kid] = $keyId;
			}
		}
		
		return $map;
	}
	
	/**
	 * 返回租户白名单。
	 *
	 * 使用范围：入站 tenant_id 绑定校验。
	 * 适用场景：跨租户令牌横向使用防线。
	 *
	 * 函数逻辑：
	 * 1. 归一化字符串数组，空=不启用。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getAllowedTenants()
	{
		$tenants = $this->token['allowed_tenants'] ?? [];
		
		return is_array($tenants) ? array_map('strval', $tenants) : [];
	}
	
	/**
	 * 校验 Scope 白名单且禁通配符。
	 *
	 * 使用范围：validate 内部调用。
	 * 适用场景：拦截 order.* 类通配导致越权。
	 *
	 * 函数逻辑：
	 * 1. 空列表返回。
	 * 2. 逐项禁止 * 字符。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private function validateScope()
	{
		$scopes = $this->getAllowedScopes();
		
		if ($scopes === []) {
			return;
		}
		
		foreach ($scopes as $scope) {
			if ($scope === '*' || strpos($scope, '*') !== false) {
				throw new ConfigurationException(
					"Profile [{$this->name}] wildcard scope [{$scope}] is not allowed in first version"
				);
			}
		}
	}
	
	/**
	 * 返回 Scope 白名单。
	 *
	 * 使用范围：签发交集与越权校验。
	 * 适用场景：优先 scope.allowed_scopes，回退 token.allowed_scopes。
	 *
	 * 函数逻辑：
	 * 1. 归一化字符串数组。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getAllowedScopes()
	{
		$scopes = $this->scope['allowed_scopes']
			?? $this->token['allowed_scopes']
			?? [];
		
		return is_array($scopes) ? array_map('strval', $scopes) : [];
	}
	
	/**
	 * 校验存储段 driver 白名单。
	 *
	 * 使用范围：validate 内部调用。
	 * 适用场景：replay 仅 cache；吊销 cache；audit cache|log。
	 *
	 * 函数逻辑：
	 * 1. replay_store.driver 校验。
	 * 2. 吊销启用时 driver 校验。
	 * 3. audit driver ∈ {cache,log}。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private function validateStores()
	{
		$replayDriver = (string)($this->replayStore['driver'] ?? 'cache');
		if ($replayDriver !== 'cache') {
			throw new UnsupportedDriverException(
				"Profile [{$this->name}] unsupported replay_store driver [{$replayDriver}]"
			);
		}
		
		if ($this->isTokenRevocationEnabled()) {
			$revocationDriver = (string)($this->tokenRevocation['driver'] ?? 'cache');
			if ($revocationDriver !== 'cache') {
				throw new UnsupportedDriverException(
					"Profile [{$this->name}] unsupported token_revocation driver [{$revocationDriver}]"
				);
			}
		}
		
		$auditDriver = (string)($this->audit['driver'] ?? 'cache');
		// audit driver 白名单：cache（共享缓存）或 log（Laravel Log 通道）。
		if ($auditDriver !== 'cache' && $auditDriver !== 'log') {
			throw new UnsupportedDriverException(
				"Profile [{$this->name}] unsupported audit driver [{$auditDriver}]"
			);
		}
	}
	
	/**
	 * 执行三种安全模式×方向一致性矩阵。
	 *
	 * 使用范围：validate 最后一步。
	 * 适用场景：token_only 禁签名；signed_request 禁 Token；plus 双腿齐备（bearer 可作认证腿）。
	 *
	 * 函数逻辑：
	 * 1. 计算 signatureOn 与 tokenEngaged（入站看 verify，出站看 attach|issue）。
	 * 2. 按模式分支校验组合，违者抛配置异常。
	 * @return void 返回值。
	 * @throws ConfigurationException 结构非法时抛出。
	 */
	private function validateSecurityModeConsistency()
	{
		$signatureOn = ($this->signature['enabled'] ?? false) === true;
		// 出站方向：attach（调用端附加）或 issue（授权签发方）均视为 Token 腿生效。
		$tokenEngaged = $this->isInbound()
			? $this->isTokenVerifyEnabled()
			: ($this->isTokenAttachEnabled() || $this->isTokenIssueEnabled());
		
		switch ($this->securityMode) {
			case self::MODE_TOKEN_ONLY:
				// token_only 要求签名关闭；Token 腿可为 JWT 验证/附加或 hmac_bearer 持钥证明。
				if ($signatureOn) {
					throw new ConfigurationException(
						"Profile [{$this->name}] mode token_only requires signature.enabled=false"
					);
				}
				$bearerAuth = $this->getAuthenticationDriver() === 'hmac_bearer_sha256';
				if (!$tokenEngaged && !$bearerAuth) {
					$expected = $this->isInbound() ? 'verify_enabled' : 'attach_enabled/issue_enabled';
					throw new ConfigurationException(
						"Profile [{$this->name}] mode token_only requires token.{$expected}=true"
					);
				}
				break;
			
			case self::MODE_SIGNED_REQUEST:
				// signed_request 以签名 key_id 归属为唯一认证主体，禁止叠加 Token 分支。
				if (!$signatureOn) {
					throw new ConfigurationException(
						"Profile [{$this->name}] mode signed_request requires signature.enabled=true"
					);
				}
				if ($this->isTokenAttachEnabled() || $this->isTokenVerifyEnabled()) {
					throw new ConfigurationException(
						"Profile [{$this->name}] mode signed_request forbids token attach/verify"
					);
				}
				break;
			
			case self::MODE_TOKEN_PLUS_REQUEST_SIGNATURE:
				// AND 语义：两类功能必须同时开启，任一失败均拒绝，不得退化为另一模式。
				if (!$signatureOn || !$tokenEngaged) {
					$expected = $this->isInbound() ? 'verify_enabled' : 'attach_enabled/issue_enabled';
					throw new ConfigurationException(
						"Profile [{$this->name}] mode token_plus_request_signature requires "
						. "signature.enabled=true and token.{$expected}=true"
					);
				}
				break;
		}
	}
	
	/**
	 * 返回 Profile 名称。
	 *
	 * 使用范围：日志、注册表引用、异常消息。
	 * 适用场景：多 Profile 部署时唯一定位信任关系。
	 *
	 * 函数逻辑：
	 * 1. 返回 name 属性。
	 * @return string 字符串值。示例："order-api"
	 */
	public function getName()
	{
		return $this->name;
	}
	
	/**
	 * 返回启用状态。
	 *
	 * 使用范围：注册表构建过滤。
	 * 适用场景：灰度下线某合作方时置 false 即整体跳过。
	 *
	 * 函数逻辑：
	 * 1. 返回 enabled 属性。
	 * @return bool 布尔判定结果。示例：true
	 */
	public function isEnabled()
	{
		return $this->enabled;
	}
	
	/**
	 * 返回通信方向。
	 *
	 * 使用范围：中间件方向断言、出站解析。
	 * 适用场景：防止 inbound 配置被用于发起调用。
	 *
	 * 函数逻辑：
	 * 1. 返回 direction 属性。
	 * @return string 字符串值。示例："order-api"
	 */
	public function getDirection()
	{
		return $this->direction;
	}
	
	/**
	 * 返回客户端标识。
	 *
	 * 使用范围：签名原文/AAD/候选索引比对。
	 * 适用场景：Header 提示与密码学归属的绑定基准。
	 *
	 * 函数逻辑：
	 * 1. 返回 clientId 属性。
	 * @return string 字符串值。示例："product-center"
	 */
	public function getClientId()
	{
		return $this->clientId;
	}
	
	/**
	 * 返回本端主体类型。
	 *
	 * 使用范围：签发 sub 组成、授权类型防线。
	 * 适用场景：service/partner/user 三类互斥。
	 *
	 * 函数逻辑：
	 * 1. 返回 subjectType 属性。
	 * @return string 字符串值。示例："service"
	 */
	public function getSubjectType()
	{
		return $this->subjectType;
	}
	
	/**
	 * 返回本端主体 ID。
	 *
	 * 使用范围：签发 sub=type:id 组成。
	 * 适用场景：issue_enabled 场景必填来源。
	 *
	 * 函数逻辑：
	 * 1. 返回 subjectId 或 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getSubjectId()
	{
		return $this->subjectId;
	}
	
	/**
	 * 返回目标服务标识。
	 *
	 * 使用范围：签名原文/AAD/HttpClient 审计。
	 * 适用场景：绑定接收方防跨服务重放。
	 *
	 * 函数逻辑：
	 * 1. 返回 targetService 属性。
	 * @return string 字符串值。示例："order-api"
	 */
	public function getTargetService()
	{
		return $this->targetService;
	}
	
	/**
	 * 返回安全模式。
	 *
	 * 使用范围：中间件 authenticateByMode 分派。
	 * 适用场景：AND/OR 语义的唯一定义点。
	 *
	 * 函数逻辑：
	 * 1. 返回 securityMode 属性。
	 * @return string 字符串值。示例："order-api"
	 */
	public function getSecurityMode()
	{
		return $this->securityMode;
	}
	
	/**
	 * 返回请求签名开关。
	 *
	 * 使用范围：HttpClient、出站中间件和入站模式分派。
	 * 适用场景：区分 signed/plus 与 token_only，避免无关签名依赖阻塞纯 Token 链路。
	 *
	 * @return bool true 表示当前 Profile 启用请求签名。
	 */
	public function isSignatureEnabled()
	{
		return ($this->signature['enabled'] ?? false) === true;
	}
	
	/**
	 * 返回签发默认租户上下文。
	 *
	 * 使用范围：extraClaims 未显式给 tenant_id 时兜底。
	 * 适用场景：多租户体系默认归属。
	 *
	 * 函数逻辑：
	 * 1. 合法非空返回否则 null。
	 * @return string|null 字符串值；未配置时 null。示例："order-signing" 或 null
	 */
	public function getTokenTenantId()
	{
		return isset($this->token['tenant_id']) && is_string($this->token['tenant_id'])
		&& $this->token['tenant_id'] !== ''
			? $this->token['tenant_id']
			: null;
	}
	
	/**
	 * 返回签名段配置。
	 *
	 * 使用范围：Signer sign/verify 聚合读取。
	 * 适用场景：一次取全 enabled/driver/key_id/窗口参数。
	 *
	 * 函数逻辑：
	 * 1. 返回 signature 属性。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getSignatureConfig()
	{
		return $this->signature;
	}
	
	/**
	 * 返回防重放开关。
	 *
	 * 使用范围：Signer.verify 决定是否登记 Nonce。
	 * 适用场景：低风险幂等路由可关闭。
	 *
	 * 函数逻辑：
	 * 1. signature.replay_protection ?? true。
	 * @return bool 布尔判定结果。示例：true
	 */
	public function getReplayProtectionEnabled()
	{
		return ($this->signature['replay_protection'] ?? true) === true;
	}
	
	/**
	 * 按公式计算 ReplayStore TTL。
	 *
	 * 使用范围：Signer.registerNonce 下发时长。
	 * 适用场景：保证 TTL≥接受窗口防合法重试误判。
	 *
	 * 函数逻辑：
	 * 1. max_age + 2*skew + margin。
	 * @return int 整型值（秒/数量）。示例：425
	 */
	public function getReplayTtlSeconds()
	{
		return $this->getSignatureMaxAgeSeconds()
			+ 2 * $this->getClockSkewSeconds()
			+ $this->getReplaySafetyMarginSeconds();
	}
	
	/**
	 * 返回时钟偏差容忍(秒)。
	 *
	 * 使用范围：时间窗与 TTL 公式。
	 * 适用场景：双端时钟不同步容忍度。
	 *
	 * 函数逻辑：
	 * 1. signature.clock_skew_seconds ?? 60。
	 * @return int 整型值（秒/数量）。示例：425
	 */
	public function getClockSkewSeconds()
	{
		return (int)($this->signature['clock_skew_seconds'] ?? 60);
	}
	
	/**
	 * 返回防重放余量(秒)。
	 *
	 * 使用范围：TTL 公式第三项。
	 * 适用场景：默认 5 秒安全边界。
	 *
	 * 函数逻辑：
	 * 1. signature.replay_safety_margin_seconds ?? 5。
	 * @return int 整型值（秒/数量）。示例：425
	 */
	public function getReplaySafetyMarginSeconds()
	{
		return (int)($this->signature['replay_safety_margin_seconds'] ?? 5);
	}
	
	/**
	 * 返回加密段配置。
	 *
	 * 使用范围：Cipher/Middleware 判定启用与参数。
	 * 适用场景：聚合读取 enabled/driver/key_id。
	 *
	 * 函数逻辑：
	 * 1. 返回 encryption 属性。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getEncryptionConfig()
	{
		return $this->encryption;
	}
	
	/**
	 * 返回加密明文体积上限（字节）。
	 *
	 * 使用范围：AesGcmCipher 在分配大块内存前做闸门判断。
	 * 适用场景：加密峰值内存约为明文的 3.5～6 倍；不设上限时超大 Body 会触发
	 *           不可捕获的 fatal OOM，调用方拿不到异常也写不了审计。
	 *           返回 null 表示不限制（保持既有行为，由部署方显式选择）。
	 *
	 * 函数逻辑：
	 * 1. 读 encryption.max_plaintext_bytes；缺失或非数值返回 null。
	 *
	 * @return int|null 上限字节数；未配置时 null 表示不限制。示例：8388608（8 MB）
	 */
	public function getEncryptionMaxPlaintextBytes()
	{
		if (!isset($this->encryption['max_plaintext_bytes'])) {
			return null;
		}
		
		$limit = $this->encryption['max_plaintext_bytes'];
		
		return is_numeric($limit) ? (int)$limit : null;
	}
	
	/**
	 * 返回响应加密用途 key_id。
	 *
	 * 响应密钥位于 response_integrity.encryption，与请求 encryption.key_id
	 * 分属不同用途；响应完整性验证和响应生成必须读取同一个专用标识。
	 *
	 * @return string|null 响应加密 key_id；未配置时返回 null。
	 */
	public function getResponseEncryptionKeyId()
	{
		$encryption = $this->responseIntegrity['encryption'] ?? [];
		
		return is_array($encryption) && isset($encryption['key_id'])
		&& is_string($encryption['key_id']) && $encryption['key_id'] !== ''
			? $encryption['key_id']
			: null;
	}
	
	/**
	 * 返回响应完整性配置。
	 *
	 * 使用范围：Checker/HttpClient 按 mode 验证。
	 * 适用场景：required/mode/子密钥聚合读取。
	 *
	 * 函数逻辑：
	 * 1. 返回 responseIntegrity 属性。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getResponseIntegrityConfig()
	{
		return $this->responseIntegrity;
	}
	
	/**
	 * 返回 Token 段配置。
	 *
	 * 使用范围：Issuer/Verifier 聚合读取。
	 * 适用场景：attach/verify/issue 全参数入口。
	 *
	 * 函数逻辑：
	 * 1. 返回 token 属性。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getTokenConfig()
	{
		return $this->token;
	}
	
	/**
	 * 返回 Token 时间偏差(秒)。
	 *
	 * 使用范围：firebase leeway 注入。
	 * 适用场景：exp/nbf 判定容差。
	 *
	 * 函数逻辑：
	 * 1. token.clock_skew_seconds ?? 60。
	 * @return int 整型值（秒/数量）。示例：425
	 */
	public function getTokenClockSkewSeconds()
	{
		return (int)($this->token['clock_skew_seconds'] ?? 60);
	}
	
	/**
	 * 返回审计段配置。
	 *
	 * 使用范围：ServiceProvider 选择 audit 后端。
	 * 适用场景：cache/log 切换依据。
	 *
	 * 函数逻辑：
	 * 1. 返回 audit 属性。
	 * @return array 配置或列表数组。示例：["key"=>"value"]
	 */
	public function getAuditConfig()
	{
		return $this->audit;
	}
	
	/**
	 * 返回注入的密钥提供器。
	 *
	 * 使用范围：需要直连密钥源的高级用法。
	 * 适用场景：保持 Profile 与密钥来源关联。
	 *
	 * 函数逻辑：
	 * 1. 返回 keyProvider 属性。
	 * @return KeyProviderInterface 注入的密钥提供器实例。示例：EnvKeyProvider 实例
	 */
	public function getKeyProvider()
	{
		return $this->keyProvider;
	}
}
