<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TozoHttpClient
 *
 * 文件功能：
 * - 调用端统一安全 HTTP Client：稳定序列化 → 可选加密 → Body Hash → 签名 → 附加 Token → 发送
 *   → 响应完整性验证（解密/验签）→ 审计
 * - 传输层可注入（测试桩/自定义客户端）；默认使用 Illuminate PendingRequest
 *
 * 安全边界：
 * - Encrypt-then-Sign：签名必须覆盖最终 wire-level Body（加密信封），顺序不可颠倒
 * - Token 签发失败不吞异常，直接失败关闭
 * - response_integrity.required=true 时未受保护或校验失败的响应一律抛异常，不交给业务
 * - 审计事件经脱敏，不含密钥、完整 Token 与敏感 Body
 */

namespace Tozo\Security\Http;

use Throwable;
use Tozo\Security\Payload;
use Tozo\Security\Profile;
use Illuminate\Http\Client\PendingRequest;
use Tozo\Security\Protocol\ProtocolVersion;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Exceptions\ProtocolException;
use Tozo\Security\Exceptions\SecurityException;
use Tozo\Security\Contracts\HttpClientInterface;
use Tozo\Security\Contracts\TokenIssuerInterface;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Contracts\ResponseIntegrityInterface;

class TozoHttpClient implements HttpClientInterface
{
	/**
	 * 请求签名器。签名对象必须是**加密之后的最终 wire Body**，不是原始业务数据——
	 * 顺序颠倒会让签名覆盖不到实际发送的字节，中间人替换密文而签名仍然有效。
	 * token_only 模式不需要签名，此时为 null；但 Profile 声明需要签名而这里为 null
	 * 时必须抛 ConfigurationException，不能静默跳过签名步骤。
	 *
	 * @var SignerInterface|null
	 */
	private $signer;
	
	/**
	 * 载荷加解密器。只在 Profile 显式开启 encryption 时使用，负责把明文 Body
	 * 替换为 AES-256-GCM 信封 JSON（Encrypt-then-Sign 的第一步）。
	 * 未开启加密的 Profile 不注入该依赖，避免无意加载加密密钥；
	 * 开启了却为 null 时抛 ConfigurationException 而非发送明文。
	 *
	 * @var PayloadCipherInterface|null
	 */
	private $cipher;
	
	/**
	 * 响应完整性验证器，支持 encrypted（解密并验证 AEAD 标签）与 signed（验证响应 HMAC）
	 * 两种模式。它是调用端的最后一道防线：response_integrity.required=true 时，
	 * 未受保护或验证失败的响应一律抛异常，绝不把可疑内容交给业务层。
	 * 为 null 表示本客户端不做响应验证，此时 Profile 不得要求 required。
	 *
	 * @var ResponseIntegrityInterface|null
	 */
	private $integrity;
	
	/**
	 * 审计接收器。这是唯一的**必需**依赖：每次出站请求无论成败都要留痕，
	 * 否则事后无法回答「这个签名是谁在什么时候发出的」。
	 * 事件在写入前一律经 AuditSanitizer 脱敏，不含密钥、完整 Token 与敏感 Body。
	 *
	 * @var AuditSinkInterface
	 */
	private $auditSink;
	
	/**
	 * Token 签发器。仅在 Profile 的 token.attach_enabled=true 时使用，
	 * 为出站请求现场签发 Bearer Token。
	 * 默认为 null 是**有意的安全边界**：不开启 attach 就不注册该绑定，
	 * 使未授权签发的系统连私钥都不会被加载（设计 §13「默认安装只验证不签发」）。
	 * attach 已开启而这里为 null 时抛 ConfigurationException，不降级为无 Token 请求。
	 *
	 * @var TokenIssuerInterface|null
	 */
	private $tokenIssuer;
	
	/**
	 * 传输闭包。签名为 fn(method,url,headers,body,http_options):array{status,headers,body}。
	 * 存在两个用途：测试注入桩替身以断言签名头与 Body 的实际字节；宿主替换为自己的
	 * HTTP 栈（如带熔断或链路追踪的客户端）。
	 * 无论替换成什么，加密→签名→审计的顺序都在本类内完成，传输层拿到的已是最终字节，
	 * 因此替换传输不会绕过任何安全步骤。为 null 时回退 Illuminate PendingRequest。
	 *
	 * @var callable|null
	 */
	private $transport;
	
	/**
	 * 默认出站 Profile。这是本类**唯一的可变状态**，也是唯一的污染风险点：
	 * setProfile() 就地修改本实例，若业务把同一实例存入静态属性或跨服务传递，
	 * 后调用者会覆盖前者的目标，使请求被签往错误的目标服务且不产生任何报错。
	 * 容器因此把 HttpClientInterface 注册为 bind 而非 singleton；
	 * to() 与 withProfile() 都返回副本，从根上消除该污染。
	 * 为 null 表示未绑定，此时每次调用必须显式选路或传 Profile，否则抛 ConfigurationException。
	 *
	 * @var Profile|null
	 */
	private $profile;
	
	/**
	 * 当前绑定对端的 HTTPS 根地址，由 to() 从配置的 peers 声明中取得。
	 * 非空时业务可只写相对路径（如 '/api/orders'），由 resolveUrl 补全为绝对 URL；
	 * 传绝对 URL 时原样使用，保证旧写法不受影响。
	 * 为 null 表示未经 to() 选路，此时相对路径会在 urlWithQuery 阶段因缺少 host
	 * 被判为协议错误——不猜测目标主机是有意设计。
	 *
	 * @var string|null
	 */
	private $baseUri;
	
	/**
	 * 出站选路表，键为对端服务标识，值含该关系的出站 Profile 与根地址。
	 * 由 ServiceProvider 在装配时按配置的 peers 与已校验的 Profile 注册表配对生成，
	 * 使业务能用对端服务名选路，不必记忆 Profile 名与域名。
	 * 只收录 peers 中声明了根地址的关系；未声明的对端不进表，
	 * to() 查不到即抛 ConfigurationException，绝不回退到任意 Profile。
	 *
	 * @var array<string,array{profile:Profile,base_uri:string}>
	 */
	private $routes = [];
	
	/**
	 * 构造安全客户端并注入五项协作依赖。
	 *
	 * 使用范围：ServiceProvider 注册 HttpClientInterface 单例、测试构造传输桩时调用。
	 * 适用场景：业务通过容器获取“自动加密→签名→附加Token→响应验证”的统一出站入口。
	 *
	 * 函数逻辑：
	 * 1. 审计接收器为唯一必需依赖，置于首位；其余能力按 Profile 需要注入。
	 * 2. signer/cipher/integrity/tokenIssuer 可空，运行期按 Profile 开关校验后再使用。
	 * 3. transport 可空（回退 Illuminate PendingRequest）；自定义传输可读取第 5 个 http_options 参数。
	 *
	 * @param AuditSinkInterface $auditSink 审计接收器｜唯一必需依赖，脱敏落盘。示例：new LaravelCacheAuditSink($cache)
	 * @param SignerInterface|null $signer 签名器｜signed/plus 出站 Profile 必需，token_only 可为 null。
	 * @param PayloadCipherInterface|null $cipher 加解密器｜加密 Profile 必需。示例：new AesGcmCipher($keys)
	 * @param ResponseIntegrityInterface|null $integrity 完整性验证器｜响应侧。示例：new ResponseIntegrityChecker($cipher,$keys)
	 * @param TokenIssuerInterface|null $tokenIssuer Token 签发器｜attach 必需。示例：new JwtTokenIssuer(...)
	 * @param callable|null $transport 传输闭包｜测试桩；第 5 个参数为受控 HTTP 选项。示例：function ($m,$u,$h,$b,$o){ return ['status'=>200,'headers'=>[],'body'=>'{}']; }
	 * @return void 无返回值。
	 */
	public function __construct(
		AuditSinkInterface         $auditSink,
		SignerInterface            $signer = null,
		PayloadCipherInterface     $cipher = null,
		ResponseIntegrityInterface $integrity = null,
		TokenIssuerInterface       $tokenIssuer = null,
		callable                   $transport = null
	)
	{
		$this->signer      = $signer;
		$this->cipher      = $cipher;
		$this->integrity   = $integrity;
		$this->auditSink   = $auditSink;
		$this->tokenIssuer = $tokenIssuer;
		$this->transport   = $transport;
	}
	
	/**
	 * 返回当前绑定的默认出站 Profile。
	 *
	 * 使用范围：调用方可观测当前信任关系时调用。
	 * 适用场景：多 Profile 应用确认客户端当前缺省目标。
	 *
	 * 函数逻辑：
	 * 1. 返回私有 profile 属性；未绑定为 null。
	 *
	 * @return Profile|null 默认出站 Profile；未绑定返回 null。示例：默认出站 Profile 或 null
	 */
	public function getProfile()
	{
		return $this->profile;
	}
	
	/**
	 * 就地绑定默认出站 Profile 并立即结构校验。
	 *
	 * 使用范围：ServiceProvider 装配默认项、单一目标系统的应用在启动期调用一次。
	 * 适用场景：配置错误在绑定瞬间暴露而非首次发请求时才失败。
	 *
	 * 并发与共享警告：
	 * 本方法**修改当前实例状态**。容器把 HttpClientInterface 注册为 bind（每次解析新实例），
	 * 因此各业务各自解析时互不影响；但若业务把同一实例存入静态属性或跨服务传递，
	 * 后调用者的 setProfile 会覆盖前者的目标 Profile，导致请求被签往错误的目标服务。
	 * 多目标场景请改用 withProfile()（返回新实例）或在每次调用时传入 $profile 参数。
	 *
	 * 函数逻辑：
	 * 1. 非 null 即执行 validate()；随后保存引用。
	 *
	 * @param Profile|null $profile 出站 Profile｜传 null 解除绑定。示例：Profile::fromConfig('svc_to_order',...)
	 * @return void 无返回值。
	 * @throws \Tozo\Security\Exceptions\ConfigurationException 结构校验失败。
	 */
	public function setProfile(Profile $profile = null)
	{
		if ($profile !== null) {
			// 切换 Profile 即完成结构校验，错误尽早暴露。
			$profile->validate();
		}
		
		$this->profile = $profile;
	}
	
	/**
	 * 返回绑定了指定 Profile 的**新实例**，当前实例保持不变。
	 *
	 * 使用范围：同一应用需要按不同信任关系发起调用时的推荐入口。
	 * 适用场景：服务 A 与服务 B 各自持有不同目标 Profile，
	 *           用本方法可避免 setProfile 在共享实例上互相覆盖——
	 *           那类污染会让请求被签往错误的目标服务，且不会有任何报错。
	 *
	 * 函数逻辑：
	 * 1. clone 当前实例，复制全部无状态协作依赖（签名器/加解密器/传输闭包等）。
	 * 2. 在副本上完成 Profile 结构校验与绑定后返回，原实例状态不受影响。
	 *
	 * @param Profile|null $profile 出站 Profile｜传 null 得到未绑定副本。示例：Profile::fromConfig('svc_to_order',...)
	 * @return self 已绑定该 Profile 的新实例。示例：$client->withProfile($orderProfile)
	 * @throws \Tozo\Security\Exceptions\ConfigurationException 结构校验失败。
	 */
	public function withProfile(Profile $profile = null)
	{
		// 依赖均为无状态服务，浅拷贝即可；唯一可变状态 profile 在副本上单独设置。
		$clone = clone $this;
		$clone->setProfile($profile);
		
		return $clone;
	}
	
	/**
	 * 注册「目标服务 => 出站关系」选路表。
	 *
	 * 使用范围：ServiceProvider 装配 HttpClient 时按 peers 与 Profile 注册表调用一次。
	 * 适用场景：让调用方用对端服务名选路，不必记忆 Profile 名与根地址。
	 *
	 * 函数逻辑：
	 * 1. 整表替换；键为对端服务标识，值含该关系的出站 Profile 与根地址。
	 *
	 * @param array $routes 选路表｜服务标识=>["profile"=>Profile,"base_uri"=>string]。示例：["pos-api"=>["profile"=>$p,"base_uri"=>"https://pos-api.example.com"]]
	 * @return void 无返回值。
	 */
	public function setRoutes(array $routes)
	{
		$this->routes = $routes;
	}
	
	/**
	 * 按对端服务名选路，返回已绑定该关系的**新实例**。
	 *
	 * 使用范围：业务发起跨系统调用的推荐入口，替代手写 Profile 名与完整 URL。
	 * 适用场景：四系统互调时 `->to('pos-api')->post('/api/orders', $data)` 即可，
	 *           Profile 与根地址均由配置推导，调用方不接触任何安全参数。
	 *
	 * 函数逻辑：
	 * 1. 选路表中查找该目标服务，缺失即抛配置异常（不猜测、不回退默认 Profile）。
	 * 2. clone 出新实例并绑定该关系的 Profile 与根地址，原实例不受影响。
	 *
	 * @param string $service 目标服务标识｜须为配置 peers 中声明的键。示例："pos-api"
	 * @return self 已绑定该关系的新实例。示例：$client->to('pos-api')
	 * @throws ConfigurationException 该目标服务未在 peers 中声明或无对应出站 Profile。
	 */
	public function to(string $service)
	{
		if (!isset($this->routes[$service])) {
			$known = array_keys($this->routes);
			
			throw new ConfigurationException(
				"No outbound relation configured for target service [{$service}]"
				. ($known === [] ? '' : '; declared peers: ' . implode(', ', $known))
			);
		}
		
		$route = $this->routes[$service];
		
		// 依赖均为无状态服务，浅拷贝即可；两项可变状态在副本上单独设置。
		$clone = clone $this;
		$clone->setProfile($route['profile']);
		$clone->baseUri = (string)$route['base_uri'];
		
		return $clone;
	}
	
	/**
	 * 发起 GET 安全请求。
	 *
	 * 使用范围：只读接口调用方使用。
	 * 适用场景：查询订单状态等幂等读操作，仍需签名与防重放保护。
	 *
	 * 函数逻辑：
	 * 1. 委托 request('GET', ...)，无 Body 数据。
	 *
	 * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders/42"
	 * @param array $options 请求选项｜headers/query/request_id/body。示例：["query"=>["full"=>1]]
	 * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：Profile::fromConfig(...)
	 * @return TozoResponse 已验证响应｜required 时 Body 为明文。示例：TozoResponse(200, [], "{}")
	 * @throws ConfigurationException 未提供 Profile 或配置非法。
	 * @throws \Tozo\Security\Exceptions\ResponseIntegrityException 响应验证失败。
	 */
	public function get(string $url, array $options = [], Profile $profile = null)
	{
		return $this->request('GET', $url, [], $options, $profile);
	}
	
	/**
	 * 执行出站七步统一流程。
	 *
	 * 使用范围：五个公开 HTTP 方法入口的内部汇聚点。
	 * 适用场景：强制所有出站调用遵循同一顺序——序列化→可选加密→签名→Header→发送→完整性→审计，
	 *           杜绝各业务自行拼装导致的 Encrypt-then-Sign 顺序错误。
	 *
	 * 函数逻辑：
	 * 1. 解析生效 Profile（参数优先，回退默认绑定），缺失即异常；执行 validate()。
	 * 2. 稳定序列化 Body（options.body 直传或 data JSON 编码）。
	 * 3. 加密开启则 cipher.encrypt 替换 Body 为信封 JSON。
	 * 4. signer.sign 对最终 Body 签名（写入 timestamp/nonce/hash/signature）。
	 * 5. buildHeaders 组装并覆盖 X-Tozo-*；attach 场景签发 Token。
	 * 6. send 传输后包装 TozoResponse；verifyResponse 按 mode 强制验证。
	 * 7. audit 写入脱敏事件后返回响应。
	 *
	 * @param string $method HTTP 方法｜大写。示例："POST"
	 * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders"
	 * @param array $data 业务数据｜POST/PUT/PATCH 体。示例：["sku"=>"A-1"]
	 * @param array $options 请求选项｜headers/query/request_id/body。示例：["request_id"=>"req-1"]
	 * @param Profile|null $profile 请求级 Profile｜null 回退默认绑定。示例：null
	 * @return TozoResponse 已验证（如要求）的响应对象。示例：TozoResponse(200, [], "{}")
	 * @throws ConfigurationException 无 Profile/配置非法/mode 不支持。
	 * @throws \Tozo\Security\Exceptions\EncryptionException 加密失败。
	 * @throws \Tozo\Security\Exceptions\SignatureException 签名链路失败。
	 * @throws \Tozo\Security\Exceptions\ResponseIntegrityException 响应验证失败。
	 * @throws SecurityException 审计写入失败。
	 * @throws ProtocolException 传输层失败。
	 */
	private function request(
		string  $method,
		string  $url,
		array   $data,
		array   $options,
		Profile $profile = null
	)
	{
		$effective = $profile ?? $this->profile;
		if ($effective === null) {
			throw new ConfigurationException('TozoHttpClient requires a profile');
		}
		
		$effective->validate();
		
		// 1. 稳定序列化：确定最终 JSON Body 原始字节。
		if (isset($options['body']) && is_string($options['body'])) {
			$body = $options['body'];
		} else {
			$body = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
			if ($body === false) {
				// 编码失败时不能把 false 强转为空 Body，否则签名内容与调用方原意不一致。
				throw new ProtocolException(
					'Request JSON serialization failed',
					400,
					null,
					'request_serialization_failed'
				);
			}
		}
		
		// to() 选路后允许只写相对路径；绝对 URL 用法保持原样。
		$requestUrl = $this->urlWithQuery($this->resolveUrl($url), $options['query'] ?? []);
		$parts      = parse_url($requestUrl);
		
		$payload = new Payload([
			'method'         => $method,
			'path'           => is_array($parts) && isset($parts['path']) ? $parts['path'] : '/',
			// 签名 query 直接取最终请求 URL 的原始字节，与服务端 QUERY_STRING 同源。
			'query'          => is_array($parts) && isset($parts['query']) ? (string)$parts['query'] : '',
			'content_type'   => 'application/json',
			'client_id'      => $effective->getClientId(),
			'target_service' => $effective->getTargetService(),
			'body'           => (string)$body,
		]);
		
		// 2. 可选加密：Body 替换为信封 JSON（先加密）。
		if (($effective->getEncryptionConfig()['enabled'] ?? false) === true) {
			if ($this->cipher === null) {
				throw new ConfigurationException('Encryption enabled but cipher binding is missing');
			}
			
			$payload = $this->cipher->encrypt($payload, $effective);
		}
		
		// 3. 只有签名腿开启时才计算证明；token_only 必须保持无签名请求。
		if ($effective->isSignatureEnabled()) {
			if ($this->signer === null) {
				throw new ConfigurationException('Signature enabled but signer binding is missing');
			}
			
			$payload = $this->signer->sign($payload, $effective);
		}
		
		// 4. 按 security_mode 附加 Token；签发失败不吞异常。
		$headers = $this->buildHeaders($payload, $effective, $options);
		
		// 5. 发送请求。
		$httpOptions = $this->getHttpOptions($options);
		$raw         = $this->send($method, $requestUrl, $headers, (string)$payload->get('body'), $httpOptions);
		
		$response = new TozoResponse(
			(int)$raw['status'],
			is_array($raw['headers']) ? $raw['headers'] : [],
			(string)$raw['body']
		);
		
		// 6. 响应完整性：required 时强制验证，未受保护响应一律拒绝。
		$response = $this->verifyResponse($response, $effective);
		
		// 7. 脱敏审计。
		$this->audit($method, $requestUrl, $response, $effective);
		
		return $response;
	}
	
	/**
	 * 将 options.query 追加到 URL 原有 query 之后，产出实际请求地址。
	 *
	 * 使用范围：request() 第 1 步内部调用。
	 * 适用场景：签名与传输必须共享同一份 query 字节——服务端按 QUERY_STRING 规范化验签，
	 *           因此这里生成的字节必须就是最终发送出去的字节，不能再做二次重排。
	 *
	 * 函数逻辑：
	 * 1. URL 必须含 host，否则视为协议错误（不猜测相对地址）。
	 * 2. options.query 按顶层键覆盖 URL 原有同名参数：被覆盖的原参数（含重复键与
	 *    方括号同族键）整组移除，未被覆盖的重复键原样保留。
	 * 3. 保留段与 options 渲染段拼接后交给 canonicalQueryString 统一排序与编码，
	 *    使最终 URL 本身即为规范形态；parse_url 取出的 query 与服务端 QUERY_STRING 完全一致。
	 *
	 * @param string $url 目标地址｜可自带 query。示例："https://order-api.internal/api/orders?page=2"
	 * @param mixed $query 附加参数｜数组，非数组视为空。示例：["tags"=>["x","y"]]
	 * @return string 最终请求 URL（query 已规范化）。示例："https://order-api.internal/api/orders?page=2&tags=x&tags=y"
	 * @throws ProtocolException URL 缺少 host。
	 */
	private function urlWithQuery(string $url, $query)
	{
		$query = is_array($query) ? $query : [];
		$parts = parse_url($url);
		if (!is_array($parts) || !isset($parts['host'])) {
			throw new ProtocolException('HTTP URL is invalid', 400, null, 'invalid_http_url');
		}
		
		// options 提供的顶层键构成覆盖集合；URL 中同族参数不再保留，避免出现新旧两个值。
		$overridden = [];
		foreach (array_keys($query) as $optionKey) {
			$overridden[CanonicalRequest::topLevelQueryKey((string)$optionKey)] = true;
		}
		
		$segments = [];
		if (isset($parts['query']) && $parts['query'] !== '') {
			foreach (explode('&', (string)$parts['query']) as $segment) {
				if ($segment === '') {
					continue;
				}
				
				$split  = explode('=', $segment, 2);
				$urlKey = CanonicalRequest::topLevelQueryKey(urldecode($split[0]));
				if (isset($overridden[$urlKey])) {
					// 该键由 options 显式给出，原 URL 值整组丢弃（含重复键）。
					continue;
				}
				
				$segments[] = $segment;
			}
		}
		
		if ($query !== []) {
			$segments[] = CanonicalRequest::buildQueryString($query);
		}
		
		// 规范化后的字节既作为签名输入，也作为实际发送的 URL，二者不存在第二套渲染结果。
		$canonical = CanonicalRequest::canonicalQueryString(implode('&', $segments));
		
		$base = (isset($parts['scheme']) ? $parts['scheme'] . '://' : '')
			. $parts['host']
			. (isset($parts['port']) ? ':' . $parts['port'] : '')
			. (isset($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/');
		
		return $canonical === '' ? $base : $base . '?' . $canonical;
	}
	
	/**
	 * 把相对路径按当前绑定的根地址补全为绝对 URL。
	 *
	 * 使用范围：request() 解析目标地址时首先调用。
	 * 适用场景：to() 选路后业务只写 '/api/orders'；直接传绝对 URL 的旧用法保持不变。
	 *
	 * 函数逻辑：
	 * 1. 已含 scheme 的地址视为绝对 URL，原样返回。
	 * 2. 未绑定根地址时原样返回，交由 urlWithQuery 按协议错误拒绝。
	 * 3. 否则去除根地址尾部斜杠与路径首部斜杠后拼接，避免出现双斜杠。
	 *
	 * @param string $url 目标地址｜绝对 URL 或相对路径。示例："/api/orders"
	 * @return string 绝对 URL。示例："https://pos-api.example.com/api/orders"
	 */
	private function resolveUrl(string $url)
	{
		if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', $url) === 1) {
			return $url;
		}
		
		if ($this->baseUri === null || $this->baseUri === '') {
			return $url;
		}
		
		return rtrim($this->baseUri, '/') . '/' . ltrim($url, '/');
	}
	
	/**
	 * 组装 Protocol v1 Header 集合并附加 Token。
	 *
	 * 使用范围：request 第 5 步内部调用。
	 * 适用场景：先合并业务自定义头，再用七个安全头覆盖，杜绝外部伪造 X-Tozo-*；
	 *           attach_enabled 时现场签发 Bearer Token。
	 *
	 * 函数逻辑：
	 * 1. 合并 options.headers 作为基底。
	 * 2. 覆盖写入 Version/Client/Key/Timestamp/Nonce/Signature/Content-Type 七头。
	 * 3. options.request_id 存在时透传 X-Request-Id。
	 * 4. attach_enabled：issuer 缺失抛配置异常；issue 成功写 Authorization。
	 *
	 * @param Payload $payload 已签名负载｜提供六个元数据值。示例：new Payload([...,'signature'=>'qE8f'])
	 * @param Profile $profile 生效 Profile｜提供 attach 开关。示例：Profile::fromConfig(...)
	 * @param array $options 请求选项｜headers/request_id 来源。示例：["headers"=>["X-Lang"=>"php"]]
	 * @return array 最终 Header 映射｜名称=>值。示例：["X-Tozo-Signature"=>"qE8f","Authorization"=>"Bearer eyJ..."]
	 * @throws ConfigurationException attach 启用但签发器缺失。
	 * @throws \Tozo\Security\Exceptions\TokenIssuanceException Token 签发失败。
	 */
	private function buildHeaders(Payload $payload, Profile $profile, array $options)
	{
		$data = $payload->getData();
		
		// 业务自定义 Header 先合并，安全 Header 随后覆盖，防止外部伪造 X-Tozo-*。
		$headers = isset($options['headers']) && is_array($options['headers']) ? $options['headers'] : [];
		
		// 安全 Header 由当前 Profile 唯一决定，不能沿用调用方或上一次请求的残留值。
		unset(
			$headers['X-Tozo-Key-Id'],
			$headers['X-Tozo-Timestamp'],
			$headers['X-Tozo-Nonce'],
			$headers['X-Tozo-Signature'],
			$headers['Authorization']
		);
		
		$headers['X-Tozo-Protocol-Version'] = ProtocolVersion::getCurrent();
		$headers['X-Tozo-Client-Id']        = (string)($data['client_id'] ?? '');
		$headers['Content-Type']            = (string)($data['content_type'] ?? 'application/json');
		
		if ($profile->isSignatureEnabled()) {
			$headers['X-Tozo-Key-Id']    = (string)($data['key_id'] ?? '');
			$headers['X-Tozo-Timestamp'] = (string)($data['timestamp'] ?? '');
			$headers['X-Tozo-Nonce']     = (string)($data['nonce'] ?? '');
			$headers['X-Tozo-Signature'] = (string)($data['signature'] ?? '');
		}
		
		if (!empty($options['request_id'])) {
			$headers['X-Request-Id'] = (string)$options['request_id'];
		}
		
		// token_plus_request_signature / token_only 出站需附加 Token。
		if ($profile->isTokenAttachEnabled()) {
			if ($this->tokenIssuer === null) {
				throw new ConfigurationException(
					"Profile [{$profile->getName()}] requires token attach but issuer binding is missing"
				);
			}
			
			$token                    = $this->tokenIssuer->issue($profile);
			$headers['Authorization'] = 'Bearer ' . $token;
		}
		
		return $headers;
	}
	
	/**
	 * 读取调用方提供的受控 HTTP 选项。
	 *
	 * 使用范围：request() 发送前。
	 * 适用场景：四系统宿主配置将超时、TLS 证书校验等参数显式传入传输层。
	 * 函数逻辑：
	 * 1. 未提供时返回空数组。
	 * 2. 提供但不是数组时抛出配置异常，避免静默忽略部署参数。
	 * @param array $options 请求选项｜含可选 http_options。示例：["http_options"=>["verify"=>true]]
	 * @return array 受控传输选项。示例：["timeout"=>10,"verify"=>true]
	 * @throws ConfigurationException http_options 不是数组时抛出。
	 */
	private function getHttpOptions(array $options)
	{
		if (!array_key_exists('http_options', $options)) {
			return [];
		}
		
		if (!is_array($options['http_options'])) {
			throw new ConfigurationException('http_options must be an array');
		}
		
		$supported = [
			'timeout',
			'connect_timeout',
			'verify',
			'proxy',
			'cert',
			'ssl_key',
			'curl',
			'allow_redirects',
			'http_errors',
		];
		$result    = [];
		
		foreach ($supported as $key) {
			if (array_key_exists($key, $options['http_options'])) {
				$result[$key] = $options['http_options'][$key];
			}
		}
		
		return $result;
	}
	
	/**
	 * 执行实际传输。
	 *
	 * 使用范围：request 第 6 步内部调用。
	 * 适用场景：测试注入闭包捕获请求；生产环境回退 Illuminate PendingRequest（需 guzzle）。
	 *
	 * 函数逻辑：
	 * 1. transport 闭包存在 → 传入 method/url/headers/body/http_options 并返回其数组结果。
	 * 2. 否则新建 PendingRequest，withHeaders 后 send(body、超时及允许的 Guzzle 选项)。
	 * 3. 统一收拢为 {status,headers,body} 数组；任何 Throwable 包装为 ProtocolException(502)。
	 *
	 * @param string $method HTTP 方法｜大写。示例："POST"
	 * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders"
	 * @param array $headers 最终 Header｜含全部 X-Tozo-*。示例：["X-Tozo-Signature"=>"qE8f"]
	 * @param string $body 最终 wire Body｜可能为信封 JSON。示例：'{"sku":"A-1"}'
	 * @param array $httpOptions 受控传输选项｜timeout/connect_timeout/verify 等。示例：["timeout"=>12]
	 * @return array{status:int,headers:array,body:string} 传输结果三元组。示例：["status"=>200,"headers"=>[],"body"=>"{}"]
	 * @throws ProtocolException 传输层任何失败（保留原链）。
	 */
	private function send(string $method, string $url, array $headers, string $body, array $httpOptions = [])
	{
		try {
			if ($this->transport !== null) {
				$result = ($this->transport)($method, $url, $headers, $body, $httpOptions);
			} else {
				$pending = new PendingRequest();
				$pending = $pending->withHeaders($headers);
				
				$sendOptions = [
					'body'    => $body,
					'timeout' => 10,
				];
				foreach ([
					         'connect_timeout',
					         'verify',
					         'proxy',
					         'cert',
					         'ssl_key',
					         'curl',
					         'allow_redirects',
					         'http_errors',
				         ] as $option) {
					if (array_key_exists($option, $httpOptions)) {
						$sendOptions[$option] = $httpOptions[$option];
					}
				}
				if (array_key_exists('timeout', $httpOptions)) {
					$sendOptions['timeout'] = $httpOptions['timeout'];
				}
				
				$response = $pending->send($method, $url, $sendOptions);
				
				$result = [
					'status'  => $response->status(),
					'headers' => $response->headers(),
					'body'    => $response->body(),
				];
			}
			
			// 自定义传输属于不可信模块边界，返回形态不完整时不能继续构造伪响应。
			if (!is_array($result)
				|| !isset($result['status'])
				|| !is_int($result['status'])
				|| $result['status'] < 100
				|| $result['status'] > 599
				|| !isset($result['headers'])
				|| !is_array($result['headers'])
				|| !array_key_exists('body', $result)
				|| !is_string($result['body'])) {
				throw new ProtocolException(
					'HTTP transport returned an invalid response shape',
					502,
					null,
					'http_transport_invalid_response'
				);
			}
			
			return $result;
		} catch (Throwable $e) {
			if ($e instanceof ProtocolException) {
				throw $e;
			}
			
			// 下游状态未知时不伪造成功；异常消息不拼接外部细节，原异常仅保留在内部链路。
			throw new ProtocolException('HTTP transport failed', 502, $e, 'http_transport_failed');
		}
	}
	
	/**
	 * 按固定 mode 验证响应完整性。
	 *
	 * 使用范围：request 第 7 步内部调用。
	 * 适用场景：encrypted 模式解密替换 Body；signed 模式常量时间验签；未要求的 Profile 原样放行。
	 *
	 * 函数逻辑：
	 * 1. required!==true → 原样返回。
	 * 2. encrypted → integrity.decryptEncryptedResponse 并用明文重建响应。
	 * 3. signed → integrity.verifySignedResponse 后原样返回。
	 * 4. 其他 mode 抛配置异常（Profile 校验已拦截，此处兜底）。
	 *
	 * @param TozoResponse $response 待验证响应｜传输原始结果。示例：new TozoResponse(200,[],'{...}')
	 * @param Profile $profile 生效 Profile｜提供 required/mode。示例：Profile::fromConfig(...)
	 * @return TozoResponse 验证后的响应｜encrypted 模式 Body 为明文。示例：验证后的 TozoResponse
	 * @throws ConfigurationException mode 不支持。
	 * @throws \Tozo\Security\Exceptions\ResponseIntegrityException 验证失败。
	 */
	private function verifyResponse(TozoResponse $response, Profile $profile)
	{
		$config = $profile->getResponseIntegrityConfig();
		
		if (($config['required'] ?? false) !== true) {
			return $response;
		}
		
		$mode = (string)($config['mode'] ?? '');
		
		if ($mode === 'encrypted') {
			if ($this->integrity === null) {
				throw new ConfigurationException('Response integrity enabled but checker binding is missing');
			}
			
			$plaintext = $this->integrity->decryptEncryptedResponse($response->getBody(), $profile);
			
			return new TozoResponse($response->getStatus(), $response->getHeaders(), $plaintext);
		}
		
		if ($mode === 'signed') {
			if ($this->integrity === null) {
				throw new ConfigurationException('Response integrity enabled but checker binding is missing');
			}
			
			$this->integrity->verifySignedResponse($response->getBody(), $response->getHeaders(), $profile);
			
			return $response;
		}
		
		throw new ConfigurationException("Unsupported response_integrity.mode [{$mode}]");
	}
	
	/**
	 * 写入脱敏审计事件。
	 *
	 * 使用范围：request 第 8 步内部调用（响应验证之后）。
	 * 适用场景：出站调用留痕——动作/目标/路径/状态/client/profile/时间，敏感键由 Sink 二次剔除。
	 *
	 * 函数逻辑：
	 * 1. 组装八字段事件（id 为 CSPRNG 十六进制）。
	 * 2. auditSink.log 写入；任何 Throwable 包装为 SecurityException(audit_sink_unavailable)。
	 *
	 * @param string $method HTTP 方法｜大写化后入审计。示例："POST"
	 * @param string $url 目标地址｜仅取 path 入审计。示例："https://order-api.internal/api/orders"
	 * @param TozoResponse $response 已验证响应｜取状态码。示例：new TozoResponse(200,...)
	 * @param Profile $profile 生效 Profile｜提供 target/client/name。示例：Profile::fromConfig(...)
	 * @return void 成功静默完成。
	 * @throws SecurityException 审计后端不可用（fail-closed）。
	 */
	private function audit(string $method, string $url, TozoResponse $response, Profile $profile)
	{
		try {
			$this->auditSink->log([
				'id'        => bin2hex(random_bytes(8)),
				'action'    => strtoupper($method),
				'target'    => $profile->getTargetService(),
				'path'      => parse_url($url, PHP_URL_PATH) ?: '/',
				'status'    => $response->getStatus(),
				'client_id' => $profile->getClientId(),
				'profile'   => $profile->getName(),
				'timestamp' => time(),
			]);
		} catch (Throwable $e) {
			// 审计写入失败按安全存储故障处理，不静默丢弃。
			throw new SecurityException('Audit sink unavailable', 503, $e, 'audit_sink_unavailable');
		}
	}
	
	/**
	 * 发起 POST 安全请求。
	 *
	 * 使用范围：创建资源等写操作调用方使用。
	 * 适用场景：提交订单——Body 经确定性 JSON 序列化后参与加密与签名。
	 *
	 * 函数逻辑：
	 * 1. 委托 request('POST', ...)，$data 序列化为 Body。
	 *
	 * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders"
	 * @param array $data 业务数据｜JSON 序列化体。示例：["sku"=>"A-1"]
	 * @param array $options 请求选项｜同 get。示例：["request_id"=>"req-1"]
	 * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
	 * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
	 * @throws ConfigurationException 同 request()。
	 * @throws \Tozo\Security\Exceptions\ResponseIntegrityException 响应验证失败。
	 */
	public function post(string $url, array $data = [], array $options = [], Profile $profile = null)
	{
		return $this->request('POST', $url, $data, $options, $profile);
	}
	
	/**
	 * 发起 PUT 安全请求。
	 *
	 * 使用范围：全量更新操作调用方使用。
	 * 适用场景：整体替换订单信息，Body 全量参与完整性证明。
	 *
	 * 函数逻辑：
	 * 1. 委托 request('PUT', ...)。
	 *
	 * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders/42"
	 * @param array $data 业务数据｜全量字段。示例：["sku"=>"A-2","amount"=>3]
	 * @param array $options 请求选项｜同 get。示例：[]
	 * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
	 * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
	 * @throws ConfigurationException 同 request()。
	 * @throws \Tozo\Security\Exceptions\ResponseIntegrityException 响应验证失败。
	 */
	public function put(string $url, array $data = [], array $options = [], Profile $profile = null)
	{
		return $this->request('PUT', $url, $data, $options, $profile);
	}
	
	/**
	 * 发起 DELETE 安全请求。
	 *
	 * 使用范围：删除操作调用方使用。
	 * 适用场景：作废订单——无 Body 但签名仍绑定方法/路径/时间戳/Nonce。
	 *
	 * 函数逻辑：
	 * 1. 委托 request('DELETE', ...)，无 Body 数据。
	 *
	 * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders/42"
	 * @param array $options 请求选项｜同 get。示例：[]
	 * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
	 * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
	 * @throws ConfigurationException 同 request()。
	 * @throws \Tozo\Security\Exceptions\ResponseIntegrityException 响应验证失败。
	 */
	public function delete(string $url, array $options = [], Profile $profile = null)
	{
		return $this->request('DELETE', $url, [], $options, $profile);
	}
	
	/**
	 * 发起 PATCH 安全请求。
	 *
	 * 使用范围：部分更新操作调用方使用。
	 * 适用场景：仅改状态字段——差异 Body 参与签名，防止局部篡改。
	 *
	 * 函数逻辑：
	 * 1. 委托 request('PATCH', ...)。
	 *
	 * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders/42"
	 * @param array $data 业务数据｜差异字段。示例：["status"=>"cancelled"]
	 * @param array $options 请求选项｜同 get。示例：[]
	 * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
	 * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
	 * @throws ConfigurationException 同 request()。
	 * @throws \Tozo\Security\Exceptions\ResponseIntegrityException 响应验证失败。
	 */
	public function patch(string $url, array $data = [], array $options = [], Profile $profile = null)
	{
		return $this->request('PATCH', $url, $data, $options, $profile);
	}
}
