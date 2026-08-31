<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * InboundAuthenticatorMiddleware
 *
 * 文件功能：
 * - 入站安全中间件：Profile 唯一候选解析 → 协议版本校验 → 按 security_mode 验签/验 Token
 *   → Scope 授权 → 注入 Subject 与 Profile 到 request attributes
 * - 防重放登记在签名验证通过后由 Signer 内部完成（token_only 不登记 Nonce）
 *
 * 安全边界：
 * - Header 中的 client_id 仅作为不可信索引；候选必须唯一，未知或多候选直接拒绝
 * - 对外响应只输出安全类别错误码（invalid_signature 等），不泄露原因细节与内部消息
 * - ReplayStore/吊销存储故障映射为 503 temporarily_unavailable，绝不降级放行
 */

namespace Tozo\Security\Laravel\Middleware;

use Closure;
use Throwable;
use Tozo\Security\Payload;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Illuminate\Http\Response;
use Tozo\Security\Identity\Subject;
use Tozo\Security\Protocol\ProtocolVersion;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Exceptions\ProtocolException;
use Tozo\Security\Exceptions\SecurityException;
use Tozo\Security\Exceptions\SignatureException;
use Tozo\Security\Profile;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\AuthenticationException;
use Tozo\Security\Contracts\ScopeAuthorizerInterface;
use Tozo\Security\Exceptions\ReplayStoreUnavailableException;
use Tozo\Security\Exceptions\RevocationStoreUnavailableException;
use Tozo\Security\Exceptions\ScopeException;
use Tozo\Security\Exceptions\DecryptionException;

class InboundAuthenticatorMiddleware
{
    /**
     * 已校验的入站 Profile 注册表，键为 Profile 名，值为已通过结构校验的对象。
     * 中间件按路由的 tozo_profile 默认值精确查表，**绝不回退默认 Profile**——
     * 回退会让来自 A 的请求被按 B 的规则验证，等于绕过信任关系边界。
     * 表中只含 enabled=true 的 Profile，禁用的关系在此不可见。
     *
     * @var array<string,Profile>
     */
    private $profiles;
    
    /**
     * 请求验签器。signed_request 与 token_plus_request_signature 两种模式必需；
     * 纯 token_only 模式不做签名校验，此时可为 null。
     * Profile 要求验签而这里为 null 时抛 ConfigurationException——
     * 静默跳过验签会让未签名请求被当作已验证请求放行。
     *
     * @var SignerInterface|null
     */
    private $signer;
    
    /**
     * 认证器（通常是按 driver 分派的 AuthenticatorRouter）。
     * token_only 与 token_plus_request_signature 模式必需；
     * 纯 signed_request 模式以签名密钥归属为认证主体，不需要它，此时为 null。
     * Profile 要求认证而这里为 null 时抛 ConfigurationException，不降级为仅验签。
     *
     * @var AuthenticatorInterface|null
     */
    private $authenticator;
    
    /**
     * Scope 授权判定器，执行「路由所需 Scope ⊆ 主体已授予 Scope」的包含判定。
     * 认证解决「你是谁」，它解决「你能不能做这件事」，两者不可互相替代。
     * 未启用 Scope 能力时为 null；此时路由不得声明 Scope 要求，
     * 否则等于声明了却从不校验。
     *
     * @var ScopeAuthorizerInterface|null
     */
    private $scopeAuthorizer;
    
    /**
     * 载荷解密器，把入站的 AES-256-GCM 信封还原为明文 Body。
     * 顺序上必须**先验签再解密**：签名覆盖的是密文字节，
     * 先解密会让验签失去对实际传输内容的绑定。
     * 未启用加密的 Profile 不需要它，此时为 null；
     * Profile 声明加密而这里为 null 时抛异常，不把密文当明文交给业务。
     *
     * @var PayloadCipherInterface|null
     */
    private $cipher;
    
    /**
     * 日志器，只记录失败原因码与请求元数据（Profile 名、client_id、时间戳）。
     * 绝不记录密钥、完整 Token 与请求 Body——日志通常有更宽的读取面，
     * 把敏感内容写进去等于扩大泄露面。
     * 为 null 时静默跳过日志，不影响验证结论。
     *
     * @var LoggerInterface|null
     */
    private $logger;
    
    /**
     * 构造入站中间件并注入五项协作依赖。
     *
     * 使用范围：ServiceProvider 注册容器绑定 tozo.middleware.inbound 时调用。
     * 适用场景：宿主路由挂载本中间件前，把注册表与各能力实现装配为可复用实例。
     *
     * 函数逻辑：
     * 1. 依次保存注册表、签名器、认证器、授权器；授权器、加解密器与日志器可空。
     *
     * @param array $profiles Profile 注册表｜名称=>已校验 Profile。示例：['order_inbound'=>$profile]
     * @param SignerInterface|null $signer 签名器｜signed/plus Profile 必需，纯 token Profile 可为 null。
     * @param AuthenticatorInterface|null $authenticator 认证器｜token/plus Profile 必需，纯 signed Profile 可为 null。
     * @param ScopeAuthorizerInterface|null $scopeAuthorizer 授权器｜无 Scope 路由需求时可为空。示例：new ScopeAuthorizer()
     * @param PayloadCipherInterface|null $cipher 加解密器｜加密 Profile 必需。示例：new AesGcmCipher($keys)
     * @param LoggerInterface|null $logger 日志器｜PSR-3 实例。示例：Log::channel('security')
     * @return void 无返回值。
     */
    public function __construct(
        array                    $profiles,
        SignerInterface          $signer = null,
        AuthenticatorInterface   $authenticator = null,
        ScopeAuthorizerInterface $scopeAuthorizer = null,
        PayloadCipherInterface   $cipher = null,
        LoggerInterface          $logger = null
    )
    {
        $this->profiles        = $profiles;
        $this->signer          = $signer;
        $this->authenticator   = $authenticator;
        $this->scopeAuthorizer = $scopeAuthorizer;
        $this->cipher          = $cipher;
        $this->logger          = $logger;
    }
    
    /**
     * 执行入站六步安全管线，通过后放行至业务层。
     *
     * 使用范围：宿主路由 middleware 挂载；Laravel 内核在业务控制器前调用。
     * 适用场景：order-api 所有受保护接口的统一入口——未验证请求在此被拦截为安全类别码响应。
     *
     * 函数逻辑：
     * 1. resolveProfile 解析唯一候选；2. 协议版本白名单校验；
     * 3. buildPayload 后按 security_mode 分派 AND 语义验证；
     * 4. 加密 Profile 解密 Body 并替换请求体；
     * 5. Scope 授权（路由参数 scopes 逗号分隔）；
     * 6. 注入 subject/profile/payload 三属性后放行 $next。
     * 异常路径：SecurityException→安全类别响应；其余 Throwable→500 internal_error。
     *
     * @param Request $request HTTP 请求对象｜Illuminate 入站实例。示例：Request::create('/api/orders','POST',..., $body)
     * @param Closure $next 后续管线｜下一环中间件/控制器。示例：function ($req) { return $next($req); }
     * @param string|null $scopes Scope 参数串｜逗号分隔的接口要求权限。示例："order.read,order.write"
     * @return mixed 业务响应或安全错误 JSON 响应。
     */
    public function handle(Request $request, Closure $next, string $scopes = null)
    {
        try {
            // 1. 解析唯一 Profile 候选：路由绑定优先，Header 仅作索引提示。
            $profile = $this->resolveProfile($request);
            
            // 2. 协议版本白名单：未支持协议明确拒绝。
            ProtocolVersion::requireSupported($request->header('X-Tozo-Protocol-Version'));
            
            $payload = $this->buildPayload($request, $profile);
            
            // 3. 按 security_mode 执行 AND 语义验证，不做“验签或验 Token”的模糊 OR。
            $subject = $this->authenticateByMode($payload, $profile);
            
            // 4. 按需解密请求体（签名已通过，密文可信来源确认）。
            if (($profile->getEncryptionConfig()['enabled'] ?? false) === true) {
                if ($this->cipher === null) {
                    // Profile 要求解密但功能未启用属于服务端配置缺陷；显式抛出而非触发
                    // null 方法调用的 Error，保证日志得到稳定原因码而不是 unexpected 分支。
                    throw new ConfigurationException(
                        'Encryption enabled but cipher binding is missing'
                    );
                }
                
                $payload = $this->cipher->decrypt($payload, $profile);
                $request = $this->replaceRequestBody($request, (string)$payload->get('body'));
            }
            
            // 5. Scope 授权（required_scopes ⊆ granted_scopes）。
            $requiredScopes = $scopes === null || trim($scopes) === ''
                ? []
                : array_map('trim', explode(',', $scopes));
            if ($requiredScopes !== []) {
                if ($this->scopeAuthorizer === null) {
                    throw new ConfigurationException(
                        'Scope authorization is required but scope authorizer binding is missing'
                    );
                }
                
                $this->scopeAuthorizer->authorize($subject, $profile, $requiredScopes);
            } elseif ($this->scopeAuthorizer !== null) {
                // 保留无路由 Scope 时的主体类型校验；未启用 Scope 功能时允许纯认证模式运行。
                $this->scopeAuthorizer->authorize($subject, $profile, []);
            }
            
            // 6. 注入认证结果供业务层使用。
            $request->attributes->set('tozo_security_subject', $subject);
            $request->attributes->set('tozo_security_profile', $profile);
            $request->attributes->set('tozo_security_payload', $payload);
            
            return $next($request);
        } catch (SecurityException $e) {
            return $this->securityFailureResponse($e);
        } catch (Throwable $e) {
            // 未预期异常不向调用方泄露内部信息。
            $this->log('error', 'unexpected_inbound_failure', $e);
            
            $json = json_encode(['error' => 'internal_error']);
            return new Response($json, 500, ['Content-Type' => 'application/json']);
        }
    }
    
    /**
     * 解析唯一入站 Profile 候选。
     *
     * 使用范围：handle 第 1 步内部调用。
     * 适用场景：多合作方共用一个部署时，依据路由绑定或 X-Tozo-Client-Id 定位唯一信任关系，
     *           杜绝“遍历所有 Profile 直到某个验签成功”的降级攻击面。
     *
     * 函数逻辑：
     * 1. 路由参数 tozo_profile 存在 → 直接取注册表；未知绑定抛 AuthenticationException(invalid_request)。
     * 2. 否则读 X-Tozo-Client-Id 提示头；缺失即拒。
     * 3. 收集 client_id 匹配（hash_equals 防时序）且方向为 inbound 的候选；数量≠1 一律拒绝。
     *
     * @param Request $request HTTP 请求对象｜提供路由参数与 Header。示例：Request::create(...)
     * @return Profile 唯一命中的入站 Profile。示例：唯一入站 Profile 对象
     * @throws AuthenticationException 无候选/多候选/未知绑定（reason=invalid_request）。
     */
    private function resolveProfile(Request $request)
    {
        // 路由显式绑定时直接取得唯一候选。
        $routeProfile = $request->route('tozo_profile');
        if (is_string($routeProfile) && $routeProfile !== '') {
            if (!isset($this->profiles[$routeProfile])) {
                throw new AuthenticationException('Unknown profile binding', 401, null, 'invalid_request');
            }
            
            $profile = $this->profiles[$routeProfile];
            if (!$profile->isInbound()) {
                throw new AuthenticationException('Inbound middleware cannot use an outbound profile', 401, null, 'invalid_request');
            }
            
            // 路由已锁定 Profile 时，Header 仍必须与该关系的 client_id 一致；
            // 否则签名原文可能验证通过，但业务层拿到的身份索引并非该 Profile 约定的调用方。
            $hint = $request->header('X-Tozo-Client-Id');
            if (!is_string($hint) || $hint === '' || !hash_equals($profile->getClientId(), $hint)) {
                throw new AuthenticationException('Profile client identity mismatch', 401, null, 'invalid_request');
            }
            
            return $profile;
        }
        
        // Header client_id 仅作不可信索引：候选必须唯一，禁止遍历尝试验签。
        $hint = $request->header('X-Tozo-Client-Id');
        if (!is_string($hint) || $hint === '') {
            throw new AuthenticationException('Missing profile hint header', 401, null, 'invalid_request');
        }
        
        $candidates = [];
        foreach ($this->profiles as $profile) {
            if ($profile->isInbound() && hash_equals($profile->getClientId(), $hint)) {
                $candidates[] = $profile;
            }
        }
        
        if (count($candidates) !== 1) {
            throw new AuthenticationException('No unique inbound profile candidate', 401, null, 'invalid_request');
        }
        
        return $candidates[0];
    }
    
    /**
     * 从 HTTP 请求构建签名/认证共享 Payload。
     *
     * 使用范围：handle 第 3 步之前内部调用。
     * 适用场景：把散落在 Header/Body 的上下文与签名元数据聚合为单一载体，供 Signer 与认证器统一读取。
     *
     * 函数逻辑：
     * 1. 收集 method/path/query/content_type/body 与 X-Tozo-* 五个元数据头。
     * 2. 解析 Authorization：保留原始头（hmac_bearer 用）并预剥离 Bearer 前缀（jwt 用）。
     *
     * @param Request $request HTTP 请求对象｜数据来源。示例：Request::create(...)
     * @param Profile $profile 入站 Profile｜提供 target_service 字段。示例：Profile::fromConfig(...)
     * @return Payload 聚合后的验证载荷。示例：new Payload(['method'=>'POST','path'=>'/api/orders','signature'=>'qE8f',...])
     */
    private function buildPayload(Request $request, Profile $profile)
    {
        $authorization = (string)$request->header('Authorization', '');
        $bearer        = strpos($authorization, 'Bearer ') === 0 ? substr($authorization, 7) : '';
        
        return new Payload([
            'method'               => $request->getMethod(),
            'path'                 => '/' . ltrim($request->path(), '/'),
            // query 必须取线上原始字节：$request->query->all() 会把重复键折叠为最后一个值、
            // 把 filter[status] 解析成嵌套数组，与调用端的规范化结果不一致会导致合法请求验签失败。
            'query'                => (string)$request->server->get('QUERY_STRING', ''),
            'content_type'         => (string)$request->header('Content-Type', ''),
            'body'                 => (string)$request->getContent(),
            'client_id'            => (string)$request->header('X-Tozo-Client-Id', ''),
            'target_service'       => $profile->getTargetService(),
            'timestamp'            => (string)$request->header('X-Tozo-Timestamp', ''),
            'nonce'                => (string)$request->header('X-Tozo-Nonce', ''),
            'key_id'               => (string)$request->header('X-Tozo-Key-Id', ''),
            'signature'            => (string)$request->header('X-Tozo-Signature', ''),
            'authorization'        => (string)$request->header('Authorization', ''),
            'authorization_bearer' => $bearer,
        ]);
    }
    
    /**
     * 按 security_mode 分派 AND 语义验证并返回主体。
     *
     * 使用范围：handle 第 3 步内部调用。
     * 适用场景：三种模式各自固定验证组合——token_only 只认证；signed_request 以 key_id 归属为主体；
     *           plus 先验签（含 Nonce 登记）再验 Token，任一失败整体拒绝。
     *
     * 函数逻辑：
     * 1. token_only → authenticator.authenticate。
     * 2. signed_request → signer.verify 后构造以签名为凭据的 Subject（scope 空，授权另判）。
     * 3. plus → signer.verify + authenticator.authenticate 顺序执行。
     * 4. 未知模式抛 ConfigurationException（结构校验兜底）。
     *
     * @param Payload $payload 验证载荷｜buildPayload 产物。示例：new Payload([...])
     * @param Profile $profile 入站 Profile｜提供 securityMode 与绑定基准。示例：Profile::fromConfig(...)
     * @return Subject 验证通过的主体对象。示例：验证通过的主体对象
     * @throws SignatureException 验签链路失败（含重放/时钟偏差）。
     * @throws AuthenticationException Token/证明认证失败。
     * @throws ConfigurationException 未知安全模式。
     */
    private function authenticateByMode(Payload $payload, Profile $profile)
    {
        switch ($profile->getSecurityMode()) {
            case Profile::MODE_TOKEN_ONLY:
                if ($this->authenticator === null) {
                    throw new ConfigurationException('Token authentication is enabled but authenticator binding is missing');
                }
                
                return $this->authenticator->authenticate($payload, $profile);
            
            case Profile::MODE_SIGNED_REQUEST:
                if ($this->signer === null) {
                    throw new ConfigurationException('Signature verification is enabled but signer binding is missing');
                }
                
                $this->signer->verify($payload, $profile);
                
                // signed_request 以签名 key_id 归属为唯一认证主体。
                return new Subject([
                    'sub'          => $profile->getSubjectType() . ':' . $profile->getClientId(),
                    'client_id'    => $profile->getClientId(),
                    'iss'          => 'signature:' . (string)$payload->get('key_id'),
                    'aud'          => [$profile->getTargetService()],
                    'subject_type' => $profile->getSubjectType(),
                    'scope'        => [],
                ]);
            
            case Profile::MODE_TOKEN_PLUS_REQUEST_SIGNATURE:
                if ($this->signer === null || $this->authenticator === null) {
                    throw new ConfigurationException('Token and signature bindings are required for plus mode');
                }
                
                // AND 语义：先验签（含防重放登记），再验 Token；顺序固定。
                $this->signer->verify($payload, $profile);
                
                return $this->authenticator->authenticate($payload, $profile);
            
            default:
                throw new ConfigurationException("Unsupported security mode [{$profile->getSecurityMode()}]");
        }
    }
    
    /**
     * 用解密明文替换请求体。
     *
     * 使用范围：handle 第 4 步，仅加密 Profile 且解密成功后调用。
     * 适用场景：业务控制器继续用 $request->getContent()/input() 读到明文，无需感知信封协议。
     *
     * 函数逻辑：
     * 1. initialize 重建请求：query/post/attributes/cookies/server 原样保留，内容替换为明文字节。
     *
     * @param Request $request HTTP 请求对象｜将被就地重建。示例：Request::create(...)
     * @param string $plaintext 明文字节｜AEAD 校验通过后的 Body。示例：'{"order_id":42}'
     * @return Request 同一请求实例（内容已替换）。示例：同一 Request 实例（内容已替换）
     */
    private function replaceRequestBody(Request $request, string $plaintext)
    {
        $request->initialize(
            $request->query->all(),
            $request->request->all(),
            $request->attributes->all(),
            $request->cookies->all(),
            [],
            $request->server->all(),
            $plaintext
        );
        
        return $request;
    }
    
    /**
     * 将类型化安全异常映射为对外安全类别响应。
     *
     * 使用范围：handle 的 SecurityException 分支内部调用。
     * 适用场景：对外只暴露 invalid_signature/invalid_authentication/access_denied/temporarily_unavailable/
     *           invalid_request/internal_error 五类安全码；原因码仅进日志。
     *
     * 函数逻辑：
     * 1. 先记录 reason_code 日志。
     * 2. 按异常族映射：存储不可用→503；解密/协议→400 invalid_request；签名族→401 invalid_signature；
     *    Scope→403 access_denied；配置→500 internal_error；其余认证族→401 invalid_authentication。
     *
     * @param SecurityException $e 安全异常｜携带稳定 reason code 的子类实例。示例：new InvalidSignatureException()
     * @return Response JSON 响应｜{"error":"<安全类别>"}，不含内部细节。
     */
    private function securityFailureResponse(SecurityException $e)
    {
        $this->log('warning', $e->getReasonCode(), $e);
        
        if ($e instanceof ReplayStoreUnavailableException || $e instanceof RevocationStoreUnavailableException) {
            $json = json_encode(['error' => 'temporarily_unavailable']);
            return new Response($json, 503, ['Content-Type' => 'application/json']);
        }
        
        if ($e instanceof DecryptionException || $e instanceof ProtocolException) {
            $json = json_encode(['error' => 'invalid_request']);
            return new Response($json, 400, ['Content-Type' => 'application/json']);
        }
        
        if ($e instanceof SignatureException) {
            $json = json_encode(['error' => 'invalid_signature']);
            return new Response($json, 401, ['Content-Type' => 'application/json']);
        }
        
        if ($e instanceof ScopeException) {
            $json = json_encode(['error' => 'access_denied']);
            return new Response($json, 403, ['Content-Type' => 'application/json']);
        }
        
        if ($e instanceof ConfigurationException) {
            // 配置错误属于服务端缺陷：不泄露细节，仅记录日志。
            $json = json_encode(['error' => 'internal_error']);
            return new Response($json, 500, ['Content-Type' => 'application/json']);
        }
        
        $json = json_encode(['error' => 'invalid_authentication']);
        return new Response($json, 401, ['Content-Type' => 'application/json']);
    }
    
    /**
     * 记录内部原因码日志。
     *
     * 使用范围：securityFailureResponse 与 handle 兜底分支调用。
     * 适用场景：排障需要精确失败原因，而对外响应必须保持脱敏——双轨信息在此分流。
     *
     * 函数逻辑：
     * 1. 未注入 logger 静默返回；否则按 level 输出 reason_code 与异常类名（不含消息体，避免敏感值）。
     *
     * @param string $level 日志级别｜PSR-3 方法名。示例："warning" / "error"
     * @param string $reasonCode 内部原因码｜稳定错误码。示例："replay_detected"
     * @param Throwable $e 原始异常｜仅取类名入日志。示例：new InvalidSignatureException()
     * @return void 无返回值。
     */
    private function log(string $level, string $reasonCode, Throwable $e)
    {
        if ($this->logger === null) {
            return;
        }
        
        $this->logger->{$level}('tozo_security inbound rejected', [
            'reason_code' => $reasonCode,
            'exception'   => get_class($e),
        ]);
    }
}
