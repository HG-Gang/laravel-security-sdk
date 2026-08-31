<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Tozo Security ServiceProvider
 *
 * 文件功能：
 * - 根 Provider：读取配置、构建 Profile 注册表并完成结构校验（启动即失败）
 * - 按“应用功能开启 AND 至少一个 Profile 引用”按需注册接口绑定（设计 §16.1）
 * - 注册存储适配器、HTTP Client、中间件与 artisan 命令的容器绑定
 *
 * 安全边界：
 * - token_issuer 默认关闭；关闭时不注册 TokenIssuerInterface，避免无意加载私钥
 * - 结构校验不读取生产密钥、不连接 Redis；密钥与外部依赖只在运行期首次解析时读取
 * - 配置错误抛出 ConfigurationException，禁止静默降级
 */

namespace Tozo\Security;

use Psr\Log\LoggerInterface;
use Tozo\Security\Clock\SystemClock;
use Tozo\Security\Key\EnvKeyProvider;
use Tozo\Security\Http\TozoHttpClient;
use Tozo\Security\Key\FileKeyProvider;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Scope\ScopeAuthorizer;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Contracts\ClockInterface;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Signature\HmacSha256Signer;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Contracts\HttpClientInterface;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Contracts\ReplayStoreInterface;
use Tozo\Security\Contracts\TokenIssuerInterface;
use Tozo\Security\Authentication\JwtAuthenticator;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Contracts\TokenVerifierInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Authentication\AuthenticatorRouter;
use Tozo\Security\Contracts\ScopeAuthorizerInterface;
use Tozo\Security\Encryption\ResponseIntegrityChecker;
use Tozo\Security\Contracts\ResponseIntegrityInterface;
use Tozo\Security\Authentication\HmacBearerAuthenticator;
use Tozo\Security\Contracts\TokenRevocationStoreInterface;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Tozo\Security\Laravel\Middleware\OutboundSignerMiddleware;
use Tozo\Security\Laravel\Middleware\ResponseIntegrityMiddleware;
use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;
use Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware;

class ServiceProvider extends IlluminateServiceProvider
{
	/**
	 * 注册全部容器绑定。
	 *
	 * 使用范围：Laravel 包发现机制或宿主手动注册 Provider 时由框架调用一次。
	 * 适用场景：应用启动装配阶段建立“配置→注册表→门控绑定”的完整依赖图。
	 *
	 * 函数逻辑：
	 * 1. mergeConfigFrom 合并包内默认配置（宿主已发布文件优先）。
	 * 2. normalizeConfiguration 把极简配置展开为内部完整形态。
	 * 3. 尊重既有绑定注册时钟与密钥提供器单例。
	 * 4. 注册 Profile 注册表懒加载单例；随后存储适配器、功能门控绑定、HTTP 与中间件。
	 *
	 * @return void 无返回值。
	 */
	public function register()
	{
		// 包内配置合并；路径相对 src/Tozo/Security 向上三级到包根。
		$this->mergeConfigFrom(__DIR__ . '/../../../config/tozo_security.php', 'tozo_security');
		
		// 极简配置展开：必须在任何组件读取 profiles/features 之前完成，
		// 否则门控判定会看到空注册表并静默跳过全部能力绑定。
		$this->normalizeConfiguration();
		
		// 共享基础依赖：尊重宿主应用/测试的既有绑定，不覆盖。
		if (!$this->app->bound(ClockInterface::class)) {
			$this->app->singleton(ClockInterface::class, function () {
				return new SystemClock();
			});
		}
		
		if (!$this->app->bound(KeyProviderInterface::class)) {
			$this->app->singleton(KeyProviderInterface::class, function ($app) {
				return $this->createKeyProvider($app);
			});
		}
		
		// Profile 注册表：首次解析时构建并全量结构校验。
		$this->app->singleton('tozo_security.profiles', function ($app) {
			return $this->buildProfileRegistry($app);
		});
		
		$this->registerStorageAdapters();
		$this->registerFeatureBindings();
		$this->registerHttpAndMiddleware();
	}
	
	/**
	 * 把极简配置展开为内部完整形态并写回配置仓储。
	 *
	 * 使用范围：register() 内部调用，紧随 mergeConfigFrom 之后。
	 * 适用场景：宿主只声明 service/environment/peers 时，由展开器生成 Profile 与 features。
	 *
	 * 函数逻辑：
	 * 1. 非极简形态直接返回，旧的完整配置继续按原路径工作。
	 * 2. 极简形态经 ConfigNormalizer 展开后整树写回 config('tozo_security')。
	 *
	 * @return void 无返回值。
	 * @throws ConfigurationException environment 缺失或 peers 结构非法。
	 */
	private function normalizeConfiguration()
	{
		$config = $this->app['config']->get('tozo_security', []);
		
		if (!is_array($config) || !Support\ConfigNormalizer::isCompact($config)) {
			return;
		}
		
		$this->app['config']->set('tozo_security', Support\ConfigNormalizer::normalize($config));
	}
	
	/**
	 * 按配置创建密钥提供器。
	 *
	 * 使用范围：KeyProviderInterface 绑定闭包首次解析时调用。
	 * 适用场景：env/file/array 三来源集中决策；production 拒绝 array 防测试密钥泄漏。
	 *
	 * 函数逻辑：
	 * 1. 读 key_providers.driver；switch 分派构造对应实现。
	 * 2. env 支持自定义前缀；file 支持自定义目录；array 从容器解析（可带状态映射）。
	 * 3. 白名单外抛 ConfigurationException。
	 *
	 * @param mixed $app 容器实例｜Illuminate Container/Application。示例：$this->app
	 * @return KeyProviderInterface 密钥提供器实例。示例：new EnvKeyProvider('TOZO_SECURITY_KEY_')
	 * @throws ConfigurationException driver 不支持或 production 使用 array。
	 */
	private function createKeyProvider($app)
	{
		$config = $app['config']->get('tozo_security.key_providers', []);
		$driver = (string)($config['driver'] ?? 'env');
		
		switch ($driver) {
			case 'env':
				return new EnvKeyProvider((string)($config['env']['prefix'] ?? EnvKeyProvider::DEFAULT_PREFIX));
			
			case 'file':
				return new FileKeyProvider(isset($config['file']['path']) ? (string)$config['file']['path'] : null);
			
			case 'array':
				// 仅测试环境使用（设计 §15）；生产配置该 driver 属于配置错误。
				if ((string)($app['config']->get('tozo_security.environment') ?? '') === 'production') {
					throw new ConfigurationException('ArrayKeyProvider is not allowed in production');
				}
				
				/** @var ArrayKeyProvider $provider */
				$provider = $app->make(ArrayKeyProvider::class);
				
				return $provider;
			
			default:
				throw new ConfigurationException("Unsupported key provider driver [{$driver}]");
		}
	}
	
	/**
	 * 构建已校验的 Profile 注册表。
	 *
	 * 使用范围：'tozo_security.profiles' 单例首次解析时调用。
	 * 适用场景：把原始数组配置固化为已校验对象表，供门控判断与中间件检索。
	 *
	 * 函数逻辑：
	 * 1. 读取 profiles 与 defaults 段。
	 * 2. 逐项 Profile::fromConfig（含三层合并与全量校验），异常即启动失败。
	 * 3. 仅保留 enabled=true 的 Profile 进入注册表。
	 *
	 * @param mixed $app 容器实例｜读取 config 与 KeyProvider。示例：$this->app
	 * @return array<string,Profile> 名称=>已校验 Profile。示例：['svc_to_order'=>..., 'order_inbound'=>...]
	 * @throws ConfigurationException 任一 Profile 结构非法。
	 */
	private function buildProfileRegistry($app)
	{
		$config         = $app['config']->get('tozo_security', []);
		$profilesConfig = is_array($config['profiles'] ?? null) ? $config['profiles'] : [];
		$keyProvider    = $app->make(KeyProviderInterface::class);
		
		$registry = [];
		// 应用级 defaults 第三层合并来源（Profile 显式值 > defaults > SDK 内置）。
		$appDefaults = is_array($config['defaults'] ?? null) ? $config['defaults'] : [];
		
		foreach ($profilesConfig as $name => $profileConfig) {
			if (!is_array($profileConfig)) {
				throw new ConfigurationException("Profile [{$name}] configuration must be an array");
			}
			
			$profile = Profile::fromConfig((string)$name, $profileConfig, $keyProvider, $appDefaults);
			
			if ($profile->isEnabled()) {
				$registry[(string)$name] = $profile;
			}
		}
		
		return $registry;
	}
	
	/**
	 * 注册三个存储适配器。
	 *
	 * 使用范围：register() 内部调用。
	 * 适用场景：Replay/吊销/审计统一走容器契约，后端可按配置切换 cache/log。
	 *
	 * 函数逻辑：
	 * 1. ReplayStore/吊销存储注入 CacheRepository 单例。
	 * 2. AuditSink 要求所有出站 Profile 使用同一 audit.driver，再选择 cache 或 log 后端。
	 *
	 * @return void 无返回值。
	 */
	private function registerStorageAdapters()
	{
		// 签名与 HMAC-Bearer 都需要原子 Nonce 登记；其他 Profile 不加载该存储。
		if ($this->anyProfileUses(function (Profile $p) {
			return $p->isSignatureEnabled()
				|| $p->getAuthenticationDriver() === HmacBearerAuthenticator::DRIVER;
		})) {
			$this->app->singleton(ReplayStoreInterface::class, function ($app) {
				return new Storage\LaravelCacheReplayStore($app->make(CacheRepository::class));
			});
		}
		
		if ($this->featureUsed('token_revocation', function (Profile $p) {
			return $p->isTokenRevocationEnabled();
		})) {
			$this->app->singleton(TokenRevocationStoreInterface::class, function ($app) {
				return new Storage\LaravelCacheTokenRevocationStore($app->make(CacheRepository::class));
			});
		}
		
		// HttpClient 的每次出站请求都写审计，因此 AuditSink 只随出站能力装配。
		if (!$this->featureUsed('audit', function (Profile $p) {
			return $p->isOutbound();
		})) {
			return;
		}
		
		// AuditSink 是共享绑定；多个出站 Profile 若选择不同后端，无法同时满足两者，必须启动即拒绝。
		$driver = null;
		foreach ($this->resolveProfiles() as $profile) {
			if (!$profile->isOutbound()) {
				continue;
			}
			
			$audit    = $profile->getAuditConfig();
			$declared = isset($audit['driver']) && is_string($audit['driver']) && $audit['driver'] !== ''
				? $audit['driver']
				: 'cache';
			
			if ($driver !== null && $driver !== $declared) {
				throw new ConfigurationException(
					"Outbound Profiles must use one audit driver; found [{$driver}] and [{$declared}]"
				);
			}
			
			$driver = $declared;
		}
		
		$driver = $driver ?? 'cache';
		$this->app->singleton(AuditSinkInterface::class, function ($app) use ($driver) {
			// audit driver 已在注册阶段完成跨 Profile 一致性校验。
			if ($driver === 'log') {
				if (!$app->bound(LoggerInterface::class)) {
					throw new ConfigurationException(
						'Audit driver [log] requires a Psr\Log\LoggerInterface binding'
					);
				}
				
				return new Storage\LaravelLogAuditSink(
					$app->make(LoggerInterface::class),
					(string)($app['config']->get('tozo_security.logging.level') ?? 'info')
				);
			}
			
			return new Storage\LaravelCacheAuditSink($app->make(CacheRepository::class));
		});
	}
	
	/**
	 * 遍历注册表判断引用。
	 *
	 * 使用范围：featureUsed 与 TokenVerifier 吊销注入判定。
	 * 适用场景：逐 Profile 执行任意引用谓词。
	 *
	 * 函数逻辑：
	 * 1. 任一 Profile 使 $check 为真即返回 true。
	 *
	 * @param callable $check 引用谓词｜fn(Profile):bool。示例：fn($p)=>$p->isTokenRevocationEnabled()
	 * @return bool true=存在引用。示例：true
	 */
	private function anyProfileUses(callable $check)
	{
		foreach ($this->resolveProfiles() as $profile) {
			if ($check($profile)) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * 安全解析 Profile 注册表。
	 *
	 * 使用范围：门控与 HTTP 装配处读取注册表。
	 * 适用场景：未注册（如纯单元环境）时返回空表而非报错。
	 *
	 * 函数逻辑：
	 * 1. bound 检查通过才 make，否则空数组。
	 *
	 * @return array<string,Profile> 名称=>Profile 映射。示例：["svc_to_order"=>Profile, ...]
	 */
	private function resolveProfiles()
	{
		if (!$this->app->bound('tozo_security.profiles')) {
			return [];
		}
		
		/** @var array<string,Profile> $profiles */
		$profiles = $this->app->make('tozo_security.profiles');
		
		return $profiles;
	}
	
	/**
	 * 判断“功能开启且至少一个 Profile 引用”。
	 *
	 * 使用范围：registerFeatureBindings 各门控分支调用。
	 * 适用场景：双条件门控口径统一，避免各处重复实现不一致。
	 *
	 * 函数逻辑：
	 * 1. featureEnabled 为假直接返回 false。
	 * 2. 否则 anyProfileUses 遍历注册表执行引用判定。
	 *
	 * @param string $feature 功能键｜features 配置键。示例："signature"
	 * @param callable $usageCheck 引用判定｜fn(Profile):bool。示例：fn($p)=>$p->isTokenVerifyEnabled()
	 * @return bool true=应注册该能力绑定。示例：true
	 */
	private function featureUsed(string $feature, callable $usageCheck)
	{
		if (!$this->featureEnabled($feature)) {
			return false;
		}
		
		return $this->anyProfileUses($usageCheck);
	}
	
	/**
	 * 读取功能开关布尔值。
	 *
	 * 使用范围：featureUsed 第一条件与 http_client 门控。
	 * 适用场景：统一读取入口避免键名拼写漂移。
	 *
	 * 函数逻辑：
	 * 1. config 读取 tozo_security.features.{feature}，缺省 false。
	 *
	 * @param string $feature 功能键｜features 配置键。示例："http_client"
	 * @return bool true=开启。示例：true
	 */
	private function featureEnabled(string $feature)
	{
		return (bool)$this->app['config']->get("tozo_security.features.{$feature}", false);
	}
	
	/**
	 * 按需注册功能接口绑定。
	 *
	 * 使用范围：register() 内部调用。
	 * 适用场景：features 开启且至少一个 Profile 引用时才注册，避免私钥被无意加载。
	 *
	 * 函数逻辑：
	 * 1. signature→HmacSha256Signer；encryption→AesGcmCipher；response_integrity→ResponseIntegrityChecker。
	 * 2. token_verifier→JwtTokenVerifier + Authenticator 按 driver 装配（jwt/hmac_bearer_sha256）。
	 * 3. token_issuer→JwtTokenIssuer（默认关闭）；scope→ScopeAuthorizer。
	 *
	 * @return void 无返回值。
	 */
	private function registerFeatureBindings()
	{
		// 签名：features.signature 且存在 signature.enabled 的 Profile。
		if ($this->featureUsed('signature', function (Profile $p) {
			return ($p->getSignatureConfig()['enabled'] ?? false) === true;
		})) {
			$this->app->singleton(SignerInterface::class, function ($app) {
				return new HmacSha256Signer(
					$app->make(KeyProviderInterface::class),
					$app->make(ReplayStoreInterface::class),
					$app->make(ClockInterface::class)
				);
			});
		}
		
		// 加密。
		if ($this->featureUsed('encryption', function (Profile $p) {
			return ($p->getEncryptionConfig()['enabled'] ?? false) === true;
		})) {
			$this->app->singleton(PayloadCipherInterface::class, function ($app) {
				return new AesGcmCipher($app->make(KeyProviderInterface::class));
			});
		}
		
		// 响应完整性。
		if ($this->featureUsed('response_integrity', function (Profile $p) {
			return ($p->getResponseIntegrityConfig()['required'] ?? false) === true;
		})) {
			$this->app->singleton(ResponseIntegrityInterface::class, function ($app) {
				return new ResponseIntegrityChecker(
					new AesGcmCipher($app->make(KeyProviderInterface::class)),
					$app->make(KeyProviderInterface::class)
				);
			});
		}
		
		// Token 验证：入站 verify_enabled；吊销存储可选注入。
		if ($this->featureUsed('token_verifier', function (Profile $p) {
			return $p->isTokenVerifyEnabled();
		})) {
			$this->app->singleton(TokenVerifierInterface::class, function ($app) {
				return new \Tozo\Security\Token\JwtTokenVerifier(
					$app->make(KeyProviderInterface::class),
					$app->make(ClockInterface::class),
					$app->bound(TokenRevocationStoreInterface::class) && $this->anyProfileUses(function (Profile $p) {
						return $p->isTokenRevocationEnabled();
					}) ? $app->make(TokenRevocationStoreInterface::class) : null
				);
			});
		}
		
		// 认证器：按全部 Profile 收集 driver，运行期由路由器依据当前 Profile 选择实现。
		if ($this->featureUsed('authentication', function (Profile $p) {
			return $p->isInbound() && $p->getAuthenticationDriver() !== null;
		})) {
			$this->app->singleton(AuthenticatorInterface::class, function ($app) {
				$drivers = [];
				foreach ($this->resolveProfiles() as $profile) {
					if (!$profile->isInbound()) {
						continue;
					}
					
					$declared = $profile->getAuthenticationDriver();
					if ($declared !== null) {
						$drivers[$declared] = true;
					}
				}
				
				$authenticators = [];
				
				if (isset($drivers[JwtAuthenticator::DRIVER])) {
					if (!$app->bound(TokenVerifierInterface::class)) {
						throw new ConfigurationException(
							'Authentication driver [jwt] requires features.token_verifier'
						);
					}
					
					$authenticators[] = new JwtAuthenticator($app->make(TokenVerifierInterface::class));
				}
				
				if (isset($drivers[HmacBearerAuthenticator::DRIVER])) {
					$authenticators[] = new HmacBearerAuthenticator(
						$app->make(KeyProviderInterface::class),
						$app->make(ReplayStoreInterface::class),
						$app->make(ClockInterface::class)
					);
				}
				
				return new AuthenticatorRouter($authenticators);
			});
		}
		
		// Token 签发：默认关闭；只有显式开启 features.token_issuer 才注册，避免加载私钥。
		if ($this->featureUsed('token_issuer', function (Profile $p) {
			return $p->isTokenIssueEnabled() || $p->isTokenAttachEnabled();
		})) {
			$this->app->singleton(TokenIssuerInterface::class, function ($app) {
				return new \Tozo\Security\Token\JwtTokenIssuer(
					$app->make(KeyProviderInterface::class),
					$app->make(ClockInterface::class)
				);
			});
		}
		
		// Scope 只在入站 Token 或 Profile Scope 白名单实际使用时注册。
		if ($this->featureUsed('scope', function (Profile $p) {
			return $p->isInbound()
				&& ($p->isTokenVerifyEnabled() || $p->getAllowedScopes() !== []);
		})) {
			$this->app->singleton(ScopeAuthorizerInterface::class, function () {
				return new ScopeAuthorizer();
			});
		}
	}
	
	/**
	 * 注册 HTTP Client 与中间件绑定。
	 *
	 * 使用范围：register() 内部调用。
	 * 适用场景：出站调用入口 tozo.http 与出入站中间件绑定的统一装配。
	 *
	 * 函数逻辑：
	 * 1. http_client 开启 → TozoHttpClient 单例并绑定默认出站 Profile；别名 tozo.http。
	 * 2. inbound/outbound 中间件绑定：按需注入 cipher/logger/issuer 可空依赖。
	 *
	 * @return void 无返回值。
	 */
	private function registerHttpAndMiddleware()
	{
		if ($this->featureUsed('http_client', function (Profile $p) {
			return $p->isOutbound();
		})) {
			// 用 bind 而非 singleton：HttpClient 持有可变的默认 Profile。
			// 若共享单例，服务 B 调用 setProfile 会覆盖服务 A 的目标 Profile，
			// 使 A 的请求被签往错误的目标服务且无任何报错。每次解析新实例可消除该污染；
			// 依赖本身是无状态单例，构造开销可忽略。
			$this->app->bind(HttpClientInterface::class, function ($app) {
				/** @var TozoHttpClient $client */
				$client = new TozoHttpClient(
					$app->make(AuditSinkInterface::class),
					$app->bound(SignerInterface::class) ? $app->make(SignerInterface::class) : null,
					$app->bound(PayloadCipherInterface::class) ? $app->make(PayloadCipherInterface::class) : null,
					$app->bound(ResponseIntegrityInterface::class) ? $app->make(ResponseIntegrityInterface::class) : null,
					$app->bound(TokenIssuerInterface::class) ? $app->make(TokenIssuerInterface::class) : null
				);
				
				$profiles = $app->make('tozo_security.profiles');
				
				// 按对端服务名装配选路表，使业务可用 to('pos-api') 而不必记 Profile 名。
				$client->setRoutes($this->buildOutboundRoutes($app, $profiles));
				
				// 绑定默认出站 Profile（仅供调用端本地选择，服务端不受影响）。
				$default = (string)($app['config']->get('tozo_security.default_profile') ?? '');
				if ($default !== '' && isset($profiles[$default]) && $profiles[$default]->isOutbound()) {
					$client->setProfile($profiles[$default]);
				}
				
				return $client;
			});
			
			$this->app->alias(HttpClientInterface::class, 'tozo.http');
			
			// Facade::getFacadeAccessor() 返回 'tozo_security'；必须存在该绑定，
			// 否则 TozoSecurity::get()/post() 等代理调用会抛 BindingResolutionException。
			// 代理目标为安全 HttpClient，与 Facade 类注释声明的 @method 列表一致。
			$this->app->alias(HttpClientInterface::class, 'tozo_security');
		}
		
		// 中间件绑定：依赖签名/认证功能开启；未开启时解析将失败，尽早暴露配置错误。
		$this->app->bind('tozo.middleware.inbound', function ($app) {
			return new InboundAuthenticatorMiddleware(
				$app->make('tozo_security.profiles'),
				$app->bound(SignerInterface::class) ? $app->make(SignerInterface::class) : null,
				$app->bound(AuthenticatorInterface::class) ? $app->make(AuthenticatorInterface::class) : null,
				$app->bound(ScopeAuthorizerInterface::class) ? $app->make(ScopeAuthorizerInterface::class) : null,
				$app->bound(PayloadCipherInterface::class) ? $app->make(PayloadCipherInterface::class) : null,
				$app->bound(LoggerInterface::class) ? $app->make(LoggerInterface::class) : null
			);
		});
		
		$this->app->bind('tozo.middleware.outbound', function ($app) {
			return new OutboundSignerMiddleware(
				$app->make('tozo_security.profiles'),
				(string)($app['config']->get('tozo_security.default_profile') ?? '') ?: null,
				$app->bound(SignerInterface::class) ? $app->make(SignerInterface::class) : null,
				$app->bound(PayloadCipherInterface::class) ? $app->make(PayloadCipherInterface::class) : null,
				$app->bound(TokenIssuerInterface::class) ? $app->make(TokenIssuerInterface::class) : null
			);
		});
		
		// 响应保护中间件：被调用方侧生成 encrypted/signed 保护，与调用端验证形成闭环。
		$this->app->bind('tozo.middleware.response', function ($app) {
			return new ResponseIntegrityMiddleware(
				$app->bound(ResponseIntegrityInterface::class)
					? $app->make(ResponseIntegrityInterface::class)
					: null,
				$app->bound(LoggerInterface::class) ? $app->make(LoggerInterface::class) : null
			);
		});
	}
	
	/**
	 * 构建「目标服务 => 出站关系」选路表。
	 *
	 * 使用范围：HttpClientInterface 绑定闭包内调用。
	 * 适用场景：把 peers 声明的根地址与注册表中的出站 Profile 配对，供 to() 按对端名选路。
	 *
	 * 函数逻辑：
	 * 1. 遍历已启用的出站 Profile，以其 target_service 为键。
	 * 2. 根地址取 peers 中该对端的 base_uri；未声明的关系不进入选路表。
	 *
	 * @param mixed $app 容器实例｜读取 peers 配置。示例：$this->app
	 * @param array<string,Profile> $profiles Profile 注册表｜已校验。示例：["a_outbound_to_b"=>Profile]
	 * @return array 选路表｜服务标识=>["profile"=>Profile,"base_uri"=>string]。示例：["pos-api"=>[...]]
	 */
	private function buildOutboundRoutes($app, array $profiles)
	{
		$peers  = $app['config']->get('tozo_security.peers', []);
		$peers  = is_array($peers) ? $peers : [];
		$routes = [];
		
		foreach ($profiles as $profile) {
			if (!$profile->isOutbound()) {
				continue;
			}
			
			$target = $profile->getTargetService();
			$peer   = isset($peers[$target]) ? $peers[$target] : null;
			
			// 兼容两种 peer 声明：字符串简写与含 base_uri 的数组形态。
			$baseUri = is_string($peer) ? $peer : (is_array($peer) && isset($peer['base_uri']) ? (string)$peer['base_uri'] : '');
			
			if ($baseUri === '') {
				continue;
			}
			
			$routes[$target] = [
				'profile'  => $profile,
				'base_uri' => $baseUri,
			];
		}
		
		return $routes;
	}
	
	/**
	 * 发布配置并执行启动期校验。
	 *
	 * 使用范围：框架在所有 Provider 注册完成后调用。
	 * 适用场景：发布配置文件供宿主覆盖；跨层矛盾在此启动即失败。
	 *
	 * 函数逻辑：
	 * 1. publishes 双标签（config + tozo-security-config）。
	 * 2. 控制台环境注册 artisan 命令。
	 * 3. validateConfiguration 执行结构体检，失败抛 ConfigurationException。
	 *
	 * @return void 无返回值。
	 * @throws ConfigurationException 配置存在结构错误。
	 */
	public function boot()
	{
		// 发布配置：通用 config 组 + 具名标签，便于 artisan vendor:publish 精准发布。
		// 安装即自动合并缺失键（mergeConfigFrom）；发布后以宿主 config/tozo_security.php 为准。
		$this->publishes([
			__DIR__ . '/../../../config/tozo_security.php' => config_path('tozo_security.php'),
		], ['config', 'tozo-security-config']);
		
		$this->registerCommands();
		$this->validateConfiguration();
	}
	
	/**
	 * 注册 artisan 命令。
	 *
	 * 使用范围：boot() 内部调用，仅控制台环境生效。
	 * 适用场景：三个运维入口——install 按配置生成密钥、check-config 体检自洽性、
	 *           make-key 单独生成一个密钥用于轮换或临时补齐。
	 *
	 * 函数逻辑：
	 * 1. 容器支持 runningInConsole 且处于控制台时注册命令类。
	 * 2. 非控制台环境不注册：Web 请求不应能触发密钥生成这类写盘操作。
	 *
	 * @return void 无返回值。
	 */
	private function registerCommands()
	{
		$inConsole = method_exists($this->app, 'runningInConsole')
			? $this->app->runningInConsole()
			: false;
		
		if ($inConsole) {
			$this->commands([
				Laravel\Command\SecurityCheckConfigCommand::class,
				Laravel\Command\SecurityInstallCommand::class,
				Laravel\Command\SecurityMakeKeyCommand::class,
			]);
		}
	}
	
	/**
	 * 跨层结构校验：委托 Support\ConfigChecker，与 artisan 命令共用同一事实来源。
	 *
	 * 使用范围：boot() 末尾调用。
	 * 适用场景：Profile 引用未启用功能/default_profile 缺失等矛盾在启动期即失败。
	 *
	 * 函数逻辑：
	 * 1. 取 tozo_security 配置树交给 ConfigChecker 结构级体检。
	 * 2. ok=false 时聚合 errors 抛 ConfigurationException。
	 *
	 * @return void 通过则静默。
	 * @throws ConfigurationException 存在任一结构错误。
	 */
	private function validateConfiguration()
	{
		$config = $this->app['config']->get('tozo_security', []);
		
		$result = (new Support\ConfigChecker())->check($config);
		
		if (!$result['ok']) {
			throw new ConfigurationException(implode('; ', $result['errors']));
		}
	}
}
