<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * OutboundSignerMiddleware
 *
 * 文件功能：
 * - 出站安全中间件：为当前应用代理转发的出站请求附加 Protocol v1 安全处理
 * - 流程：可选加密（Body 替换为信封）→ 对最终 Body 签名 → 写入 X-Tozo-* Header → 附加 Token
 *
 * 安全边界：
 * - 仅接受 outbound Profile；入站 Profile 直接拒绝
 * - 签名/加密/Token 任一失败直接抛类型化异常，不吞异常、不降级放行
 */

namespace Tozo\Security\Laravel\Middleware;

use Closure;
use Tozo\Security\Payload;
use Tozo\Security\Profile;
use Illuminate\Http\Request;
use Tozo\Security\Protocol\ProtocolVersion;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Contracts\TokenIssuerInterface;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Exceptions\ConfigurationException;

class OutboundSignerMiddleware
{
    /**
     * 已校验的 Profile 注册表，含出站与入站两类，按名称检索。
     * 本中间件只会使用其中的出站 Profile——取到入站 Profile 时必须拒绝，
     * 因为入站 Profile 描述的是「别人怎么调我」，拿它签名会把方向搞反，
     * 产生一个对端永远验不过的签名。
     *
     * @var array<string,Profile>
     */
    private $profiles;
    
    /**
     * 默认出站 Profile 名称，来自配置的 default_profile；未配置时为 null。
     * 中间件参数未显式指定 Profile 时回退到它。
     * 为 null 且参数也未指定时直接失败，不猜测目标——猜错会把请求签往错误的服务，
     * 且该错误在调用端不会报错，只会在对端表现为验签失败。
     *
     * @var string|null
     */
    private $defaultProfile;
    
    /**
     * 请求签名器。signed_request 与 token_plus_request_signature 模式必需；
     * token_only 模式不签名，此时可为 null。
     * 签名对象必须是加密之后的最终 Body，顺序不可颠倒。
     * Profile 要求签名而这里为 null 时抛 ConfigurationException，不发出无签名请求。
     *
     * @var SignerInterface|null
     */
    private $signer;
    
    /**
     * 载荷加密器。仅在 Profile 显式开启 encryption 时使用，
     * 把明文 Body 替换为 AES-256-GCM 信封（Encrypt-then-Sign 的第一步）。
     * 开启了加密而这里为 null 时抛 ConfigurationException——
     * 静默发送明文会让本应加密的敏感数据以明文上线，且不产生任何告警。
     *
     * @var PayloadCipherInterface|null
     */
    private $cipher;
    
    /**
     * Token 签发器。仅在 Profile 的 token.attach_enabled=true 时使用。
     * 默认为 null 是有意的安全边界：不开启 attach 就不注册该绑定，
     * 使未授权签发的系统连私钥都不会被加载。
     * attach 已开启而这里为 null 时抛异常，不降级为无 Token 请求——
     * 降级会让 plus 模式静默退化成 signed_request，绕过 AND 语义。
     *
     * @var TokenIssuerInterface|null
     */
    private $tokenIssuer;
    
    /**
     * 构造出站中间件并注入依赖。
     *
     * 使用范围：ServiceProvider 注册容器绑定 tozo.middleware.outbound 时调用。
     * 适用场景：宿主应用向内部服务代理转发请求前，统一附加签名/加密/令牌。
     *
     * 函数逻辑：
     * 1. 保存注册表、默认出站项与三个能力实现（cipher/tokenIssuer 可空，按需校验）。
     *
     * @param array $profiles Profile 注册表｜全量已校验对象。示例：['svc_to_order'=>$profile]
     * @param string|null $defaultProfile 默认出站 Profile 名｜缺省目标。示例："svc_to_order"
     * @param SignerInterface|null $signer 签名器｜signed/plus Profile 必需，token_only 可为 null。
     * @param PayloadCipherInterface|null $cipher 加解密器｜加密 Profile 必需。示例：new AesGcmCipher($keys)
     * @param TokenIssuerInterface|null $tokenIssuer Token 签发器｜attach 必需。示例：new JwtTokenIssuer(...)
     * @return void 无返回值。
     */
    public function __construct(
        array                  $profiles,
        string                 $defaultProfile = null,
        SignerInterface        $signer = null,
        PayloadCipherInterface $cipher = null,
        TokenIssuerInterface   $tokenIssuer = null
    )
    {
        $this->profiles       = $profiles;
        $this->defaultProfile = $defaultProfile;
        $this->signer         = $signer;
        $this->cipher         = $cipher;
        $this->tokenIssuer    = $tokenIssuer;
    }
    
    /**
     * 为出站请求执行“加密→签名→Header→Token”四步处理。
     *
     * 使用范围：宿主把本中间件挂到代理转发路由时由框架调用。
     * 适用场景：网关型应用收到外部请求后转发给内部 order-api——转发前补齐调用方身份与完整性证明。
     *
     * 函数逻辑：
     * 1. 解析出站 Profile（显式名优先，回退 default_profile；入站 Profile 拒绝）。
     * 2. 构建出站 Payload（body=当前原始字节）。
     * 3. 加密开启时先加密，Body 替换为信封 JSON。
     * 4. 对最终 Body 签名并写入六个 X-Tozo-* 头（业务自定义头不可覆盖安全头）。
     * 5. attach_enabled 时签发 Token 写 Authorization；加密场景同步替换请求体字节后放行。
     *
     * @param Request $request 待转发请求｜Illuminate 实例。示例：Request::create('/api/orders','POST',...,json_encode($data))
     * @param Closure $next 后续管线｜下一环。示例：function ($req) use ($next) { return $next($req); }
     * @param string|null $profileName 目标出站 Profile｜缺省用 default_profile。示例："svc_to_order"
     * @return mixed 下游响应。
     * @throws ConfigurationException Profile 不存在/方向不符/依赖缺失。
     * @throws \Tozo\Security\Exceptions\SignatureException 签名链路失败。
     * @throws \Tozo\Security\Exceptions\EncryptionException 加密失败。
     * @throws \Tozo\Security\Exceptions\TokenIssuanceException Token 签发失败。
     */
    public function handle(Request $request, Closure $next, string $profileName = null)
    {
        $profile = $this->resolveOutboundProfile($profileName);
        
        // 1. 构建出站 Payload：body 为最终 wire-level 字节。
        $payload = new Payload([
            'method'         => $request->getMethod(),
            'path'           => '/' . ltrim($request->path(), '/'),
            // query 取线上原始字节，与下游服务端 QUERY_STRING 同源，避免数组折叠导致验签失配。
            'query'          => (string)$request->server->get('QUERY_STRING', ''),
            'content_type'   => 'application/json',
            'client_id'      => $profile->getClientId(),
            'target_service' => $profile->getTargetService(),
            'body'           => (string)$request->getContent(),
        ]);
        
        // 2. 可选加密：先加密，Body 替换为信封 JSON。
        if (($profile->getEncryptionConfig()['enabled'] ?? false) === true) {
            if ($this->cipher === null) {
                throw new ConfigurationException('Encryption enabled but cipher binding is missing');
            }
            
            $payload = $this->cipher->encrypt($payload, $profile);
        }
        
        // 3. 只有签名腿开启时才覆盖最终 wire-level Body；token_only 不生成签名元数据。
        if ($profile->isSignatureEnabled()) {
            if ($this->signer === null) {
                throw new ConfigurationException('Signature enabled but signer binding is missing');
            }
            
            $payload = $this->signer->sign($payload, $profile);
        }
        
        // 4. 先保存最终负载；Request::initialize() 会重建 Header，安全 Header 必须在重建后写入。
        $data = $payload->getData();
        
        // 5. 加密场景下替换请求体为最终信封字节，同时保留请求上下文。
        if (isset($data['body']) && is_string($data['body'])) {
            $request->initialize(
                $request->query->all(),
                $request->request->all(),
                $request->attributes->all(),
                $request->cookies->all(),
                [],
                $request->server->all(),
                $data['body']
            );
        }
        
        // 6. initialize() 已完成后再写入安全 Header，避免 Token 和签名元数据被清除。
        $request->headers->set('X-Tozo-Protocol-Version', ProtocolVersion::getCurrent());
        $request->headers->set('X-Tozo-Client-Id', (string)($data['client_id'] ?? ''));
        $request->headers->remove('Authorization');
        $request->headers->remove('X-Tozo-Key-Id');
        $request->headers->remove('X-Tozo-Timestamp');
        $request->headers->remove('X-Tozo-Nonce');
        $request->headers->remove('X-Tozo-Signature');
        if ($profile->isSignatureEnabled()) {
            $request->headers->set('X-Tozo-Key-Id', (string)($data['key_id'] ?? ''));
            $request->headers->set('X-Tozo-Timestamp', (string)($data['timestamp'] ?? ''));
            $request->headers->set('X-Tozo-Nonce', (string)($data['nonce'] ?? ''));
            $request->headers->set('X-Tozo-Signature', (string)($data['signature'] ?? ''));
        }
        
        // token_only/plus 出站按 Profile 附加 Token；签发失败不吞异常。
        if ($profile->isTokenAttachEnabled()) {
            if ($this->tokenIssuer === null) {
                throw new ConfigurationException('Token attach enabled but issuer binding is missing');
            }
            
            $request->headers->set('Authorization', 'Bearer ' . $this->tokenIssuer->issue($profile));
        }
        
        // Content-Type 必须与最终 Body 保持一致。
        $request->headers->set('Content-Type', (string)($data['content_type'] ?? 'application/json'));
        
        return $next($request);
    }
    
    /**
     * 解析出站 Profile。
     *
     * 使用范围：handle 第 1 步内部调用。
     * 适用场景：显式指定多目标之一，或回退全局默认出站关系；防止误拿 inbound 配置发起调用。
     *
     * 函数逻辑：
     * 1. 显式名为空则取 default_profile；两者皆无或注册表未命中 → ConfigurationException。
     * 2. 命中对象必须 direction=outbound，否则拒绝。
     *
     * @param string|null $profileName 目标出站 Profile｜注册表键。示例："svc_to_order"
     * @return Profile 唯一出站 Profile 对象。示例：出站 Profile 对象
     * @throws ConfigurationException 未找到或方向不符。
     */
    private function resolveOutboundProfile(string $profileName = null)
    {
        $name = $profileName !== null && $profileName !== '' ? $profileName : $this->defaultProfile;
        
        if ($name === null || $name === '' || !isset($this->profiles[$name])) {
            throw new ConfigurationException("Outbound profile [{$name}] not found");
        }
        
        $profile = $this->profiles[$name];
        
        if (!$profile->isOutbound()) {
            throw new ConfigurationException("Profile [{$name}] is not an outbound profile");
        }
        
        return $profile;
    }
}
