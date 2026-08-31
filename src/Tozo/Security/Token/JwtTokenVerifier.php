<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * JwtTokenVerifier
 *
 * 文件功能：
 * - JWT 验证器：固定算法（由 Profile driver 决定）+ kid 白名单映射 + 全量 claims 绑定
 * - 覆盖：签名、kid、iss、aud、sub 格式与类型白名单、client_id 绑定、Scope 白名单、租户、时间、吊销
 *
 * 安全边界：
 * - 不根据 Header alg 选择算法；Header alg 必须与 Profile 固定算法一致
 * - kid 必须命中 Profile allowed_kids 白名单后才能取得候选公钥
 * - 吊销查询故障 fail-closed（RevocationStoreUnavailableException），已吊销抛 TokenRevokedException
 * - 底层密码学异常保留原始语义映射为 SDK 类型，不统一包装吞掉
 */

namespace Tozo\Security\Token;

use stdClass;
use Throwable;
use DomainException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use UnexpectedValueException;
use Tozo\Security\Key\KeyUsage;
use Firebase\JWT\ExpiredException;
use Tozo\Security\Identity\Subject;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;
use Tozo\Security\Contracts\ClockInterface;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Profile;
use Tozo\Security\Exceptions\TokenFormatException;
use Tozo\Security\Contracts\TokenVerifierInterface;
use Tozo\Security\Exceptions\InvalidTokenException;
use Tozo\Security\Exceptions\TokenExpiredException;
use Tozo\Security\Exceptions\TokenRevokedException;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\ScopeMismatchException;
use Tozo\Security\Exceptions\TenantMismatchException;
use Tozo\Security\Exceptions\AudienceMismatchException;
use Tozo\Security\Exceptions\ClientIdMismatchException;
use Tozo\Security\Contracts\TokenRevocationStoreInterface;
use Tozo\Security\Exceptions\SubjectTypeMismatchException;
use Tozo\Security\Exceptions\RevocationStoreUnavailableException;
use Tozo\Security\Exceptions\IssuerMismatchException;

class JwtTokenVerifier implements TokenVerifierInterface
{
    /**
     * 验证器族标识（jwt）。具体算法由 Profile 的 token.driver 经 ALGORITHMS 映射固定，
     * 绝不读取 Token Header 的 alg —— 这是算法混淆攻击的关键防线。
     */
    public const DRIVER = 'jwt';
    
    /**
     * driver 到固定算法的映射。算法**只由 Profile 的 token.driver 决定**，
     * 绝不读取令牌 Header 的 alg——这是算法混淆攻击的关键防线：
     * 若信任 Header，攻击者可把 RS256 令牌的 alg 改成 HS256，
     * 诱使服务端把公开的 RSA 公钥当作 HMAC 共享密钥来验签，从而伪造任意令牌。
     * 与签发端 JwtTokenIssuer::ALGORITHMS 保持同一事实来源。
     */
    private const ALGORITHMS = [
        Profile::DEFAULT_TOKEN_DRIVER => 'RS256',
        'jwt_hs256'                   => 'HS256',
    ];
    
    /**
     * sub claim 的合法格式：subject_type:subject_id。
     * 强制类型前缀的原因：同名 id 在不同主体类型间不产生等价关系，
     * 缺少前缀会让 user:42 与 service:42 无法区分，
     * 攻击者可用某类型的低权限身份冒充另一类型的同名主体。
     * 不匹配该格式的令牌一律拒绝，不做兼容性放宽。
     */
    private const SUBJECT_PATTERN = '/^(service|partner|user):[A-Za-z0-9._-]{1,128}$/';
    
    /**
     * 密钥提供器。RS256 按 Profile 的 allowed_kids 白名单映射后检索公钥，
     * HS256 按 token.signing_key_id 检索共享密钥。
     * 关键约束：kid 来自不可信的令牌内容，**绝不能直接当作 key_id 使用**，
     * 必须先经 Profile 的白名单映射——否则攻击者可指定任意 kid，
     * 诱使服务端用错误的密钥验签。
     *
     * @var KeyProviderInterface
     */
    private $keys;
    
    /**
     * 吊销存储。为 null 表示未装配，此时跳过吊销查询以省去一次无必要的往返。
     * 一旦注入就必须按 jti 查询，且**存储不可用时一律拒绝请求**（fail-closed）：
     * 查不到吊销记录与查不通存储是两件事，后者若放行等于吊销机制在故障期失效。
     * 只有 features.token_revocation 与 Profile 的 token_revocation.enabled 同时开启时
     * 容器才注入它。
     *
     * @var TokenRevocationStoreInterface|null
     */
    private $revocations;
    
    /**
     * 时钟。exp/nbf/iat 的判定实际由 firebase/php-jwt 内部用真实 time() 完成，
     * 本属性是预留注入点，用于本类自身需要当前时刻的判定分支。
     * 时钟偏差容忍不在这里施加，而是把 Profile 的 clock_skew_seconds 作为 leeway
     * 传给 firebase——那是该库唯一接受偏差参数的入口。
     *
     * @var ClockInterface
     */
    private $clock;
    
    /**
     * 构造验证器并注入三大协作依赖。
     *
     * 使用范围：ServiceProvider 门控注册 TokenVerifierInterface 单例时调用一次。
     * 适用场景：入站系统装配“验签+kid 白名单+claims 绑定+吊销”完整验证能力，吊销可选。
     *
     * 函数逻辑：
     * 1. 保存密钥提供器（buildKeyMap 按 kid/key_id 检索公钥或共享密钥）。
     * 2. 保存时钟（预留；当前 leeway 由 firebase 静态值承载）。
     * 3. 保存吊销存储可空引用（assertNotRevoked 按需使用）。
     *
     * @param KeyProviderInterface $keys 密钥提供器｜检索 RS256 公钥 PEM 或 HS256 共享密钥。示例：new ArrayKeyProvider(['jwt-public-2026-08'=>$pem])
     * @param ClockInterface $clock 时钟接口｜时间源注入点。示例：new SystemClock()
     * @param TokenRevocationStoreInterface|null $revocations 吊销存储｜jti 查询适配器；未启用吊销传 null。示例：new LaravelCacheTokenRevocationStore($cache)
     * @return void 无返回值；依赖保存到私有属性供 verify 及私有步骤使用。
     */
    public function __construct(
        KeyProviderInterface          $keys,
        ClockInterface                $clock,
        TokenRevocationStoreInterface $revocations = null
    )
    {
        $this->keys        = $keys;
        $this->clock       = $clock;
        $this->revocations = $revocations;
    }
    
    /**
     * 执行 Token 全量验证并返回认证主体。
     *
     * 使用范围：JwtAuthenticator.authenticate 委托调用；入站中间件 token_only/plus 模式经认证器进入。
     * 适用场景：order-api 校验 product-center 的 Bearer Token——签名、kid、iss/aud/sub/client/scope、吊销全部通过才放行。
     *
     * 函数逻辑：
     * 1. 前置校验 Profile token.verify_enabled=true 且 driver 在算法表内。
     * 2. buildKeyMap 构造 kid=>Key 白名单（算法固定）。
     * 3. decode 完成签名/时间/kid 校验并把底层异常映射为 SDK 类型。
     * 4. assertClaimsBoundToProfile 逐项绑定 iss/aud/sub/client/scope/tenant。
     * 5. assertNotRevoked 执行 fail-closed 吊销检查。
     * 6. 组装 Subject（含 jti/exp）返回。
     *
     * @param string $token JWT 串｜紧凑三段式令牌。示例："eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9.eyJpc3MiOiJ0b3pvLWF1dGgiLi4ufQ.sig"
     * @param Profile $profile 入站 Profile｜提供 verify_enabled/driver/issuer/audience/allowed_kids 等全部基准。示例：Profile::fromConfig('order_inbound', $cfg, $keys)
     * @return Subject 认证成功后的身份主体｜sub 形如 service:product-center，scope 已通过白名单校验。示例：Subject(sub="service:product-center")
     * @throws ConfigurationException 验证未启用或 driver 不支持。
     * @throws InvalidTokenException 签名不符/nbf 未生效/sub 格式错/jti 缺失。
     * @throws TokenFormatException 结构非法（含 kid 缺失形态以外的解析失败）。
     * @throws TokenExpiredException exp 已过期（含 leeway 判定）。
     * @throws IssuerMismatchException iss 与 Profile 不符。
     * @throws AudienceMismatchException aud 无交集。
     * @throws SubjectTypeMismatchException 主体类型不在白名单。
     * @throws ClientIdMismatchException client_id/azp 与 expected_client_id 不符。
     * @throws ScopeMismatchException scope 超出白名单。
     * @throws TenantMismatchException tenant_id 缺失或不在白名单。
     * @throws TokenRevokedException jti 已吊销。
     * @throws RevocationStoreUnavailableException 吊销存储不可用（fail-closed）。
     */
    public function verify(string $token, Profile $profile)
    {
        if (!$profile->isTokenVerifyEnabled()) {
            throw new ConfigurationException(
                "Profile [{$profile->getName()}] has token.verify_enabled=false"
            );
        }
        
        $driver = $profile->getTokenDriver();
        if (!isset(self::ALGORITHMS[$driver])) {
            throw new ConfigurationException("Unsupported token driver [{$driver}]");
        }
        
        $keyMap = $this->buildKeyMap($profile, $driver);
        
        $claims = $this->decode($token, $keyMap, $profile);
        
        $this->assertClaimsBoundToProfile($claims, $profile);
        
        $this->assertNotRevoked($claims, $profile);
        
        return new Subject([
            'sub'          => $claims['sub'],
            'iss'          => $claims['iss'],
            'aud'          => $claims['aud'],
            'client_id'    => isset($claims['client_id']) ? $claims['client_id'] : null,
            'azp'          => isset($claims['azp']) ? $claims['azp'] : null,
            'subject_type' => $claims['subject_type'],
            'scope'        => isset($claims['scope']) ? $claims['scope'] : [],
            'jti'          => isset($claims['jti']) ? $claims['jti'] : null,
            'exp'          => isset($claims['exp']) ? $claims['exp'] : null,
            'tenant_id'    => isset($claims['tenant_id']) && is_string($claims['tenant_id'])
                ? $claims['tenant_id']
                : null,
            'act'          => isset($claims['act']) && is_array($claims['act']) ? $claims['act'] : null,
        ]);
    }
    
    /**
     * 按 Profile 构造 kid=>Key 验证白名单。
     *
     * 使用范围：verify() 第 2 步内部调用。
     * 适用场景：RS256 多公钥轮换并存（allowed_kids）；HS256 单共享密钥（kid=signing_key_id）。
     *
     * 函数逻辑：
     * 1. 由 driver 查固定算法（RS256/HS256）。
     * 2. RS256：遍历 allowed_kids，逐个断言状态 active|verify_only 后装入 Key 映射；空映射属配置错误。
     * 3. HS256：要求 signing_key_id 存在，断言状态后构造单条目映射。
     *
     * @param Profile $profile 入站 Profile｜提供 driver、allowed_kids、signing_key_id。示例：Profile::fromConfig(...)
     * @param string $driver Token driver｜jwt_rs256 或 jwt_hs256。示例："jwt_rs256"
     * @return array<string,Key> kid=>Firebase Key 映射｜decode 按此选择候选并强制算法一致。示例：["tozo-auth-2026-08"=>new Key($pem,"RS256")]
     * @throws ConfigurationException RS256 白名单为空 / HS256 缺 signing_key_id。
     * @throws \Tozo\Security\Exceptions\KeyNotFoundException 密钥缺失或状态不允许 verify。
     */
    private function buildKeyMap(Profile $profile, string $driver)
    {
        $algorithm = self::ALGORITHMS[$driver];
        $map       = [];
        
        if ($driver === 'jwt_rs256') {
            foreach ($profile->getAllowedKids() as $kid => $keyId) {
                // 验证方向接受 active + verify_only 迁移期公钥。
                KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_VERIFY);
                $map[$kid] = new Key($this->keys->getKey($keyId), $algorithm);
            }
            
            if ($map === []) {
                throw new ConfigurationException(
                    "Profile [{$profile->getName()}] token.allowed_kids must not be empty for jwt_rs256"
                );
            }
            
            return $map;
        }
        
        // HS256 共享密钥场景：单一用途密钥，kid 即 signing_key_id。
        $keyId = $profile->getTokenSigningKeyId();
        if ($keyId === null) {
            throw new ConfigurationException(
                "Profile [{$profile->getName()}] token.signing_key_id is required for jwt_hs256"
            );
        }
        
        KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_VERIFY);
        $map[$keyId] = new Key($this->keys->getKey($keyId), $algorithm);
        
        return $map;
    }
    
    /**
     * 解码 JWT 并完成签名/时间/kid 校验，异常精确映射为 SDK 类型。
     *
     * 使用范围：verify() 第 3 步内部调用。
     * 适用场景：把 firebase 的 Expired/BeforeValid/SignatureInvalid/UnexpectedValue(Domain) 分别翻译为
     *           TokenExpired/InvalidToken(nbf)/InvalidToken(签名)/unknown_kid/TokenFormat，避免语义被吞。
     *
     * 函数逻辑：
     * 1. 备份并设置 JWT::$leeway 为 Profile token.clock_skew_seconds（finally 恢复）。
     * 2. JWT::decode 按 keyMap 选 kid 并强制 Header alg 与 Key 算法一致。
     * 3. 按 instanceof 逐一捕获转换；UnexpectedValue 且消息含 kid → unknown_kid。
     * 4. stdClass 结果经 JSON 往返转为关联数组返回。
     *
     * @param string $token JWT 串｜原始紧凑令牌。示例："eyJhbGciOi..."
     * @param array $keyMap 验证白名单｜kid=>Key 映射。示例：["tozo-auth-2026-08"=>new Key($pem,"RS256")]
     * @param Profile $profile 入站 Profile｜提供 clock_skew_seconds 作为 leeway。示例：Profile::fromConfig(...)
     * @return array 解码后的 claims 关联数组｜包含 iss/aud/sub/exp/jti 等。示例：["iss"=>"tozo-auth","sub"=>"service:x","exp"=>1700000900]
     * @throws InvalidTokenException 签名不符/未生效/未知 kid。
     * @throws TokenFormatException 结构非法。
     * @throws TokenExpiredException 已过期。
     */
    private function decode(string $token, array $keyMap, Profile $profile)
    {
        $previousLeeway = JWT::$leeway;
        // 时间校验偏差仅作用于 exp/nbf/iat 判定。
        JWT::$leeway = $profile->getTokenClockSkewSeconds();
        
        try {
            /** @var stdClass $decoded */
            $decoded = JWT::decode($token, $keyMap);
        } catch (ExpiredException $e) {
            throw new TokenExpiredException('Token has expired', 401, $e);
        } catch (BeforeValidException $e) {
            throw new InvalidTokenException('Token not yet valid', 401, $e);
        } catch (SignatureInvalidException $e) {
            throw new InvalidTokenException('Invalid token signature', 401, $e, 'invalid_token_signature');
        } catch (UnexpectedValueException $e) {
            // kid 缺失或不在白名单时 firebase 返回包含 kid 的 UnexpectedValueException。
            if (strpos($e->getMessage(), 'kid') !== false) {
                throw new InvalidTokenException('Unknown or missing kid', 401, $e, 'unknown_kid');
            }
            
            throw new TokenFormatException('Malformed token', 401, $e);
        } catch (DomainException $e) {
            throw new TokenFormatException('Malformed token', 401, $e);
        } finally {
            JWT::$leeway = $previousLeeway;
        }
        
        $claims = json_decode((string)json_encode($decoded), true);
        
        // decode 成功但 payload 不是 JSON 对象时不能继续按数组取 claims。
        return is_array($claims) ? $claims : [];
    }
    
    /**
     * 将解码 claims 与入站 Profile 逐项强绑定比对。
     *
     * 使用范围：verify() 第 4 步内部调用，位于签名验证之后、吊销之前。
     * 适用场景：攻击者持其他系统合法 Token 调用本服务——签名虽真但 iss/aud/client 不属于本 Profile，必须拒绝。
     *
     * 函数逻辑：
     * 1. iss 必须全等 Profile issuer。
     * 2. aud 与允许列表至少一个交集（标准 JWT aud 语义）。
     * 3. sub 必须匹配 type:id 正则，且 type ∈ allowed_subject_types；
     *    校验通过后把 subject_type 写回 claims，作为 Subject 的唯一可信来源。
     * 4. client_id（回退 azp）必须全等 expected_client_id。
     * 5. scope 逐项 ⊆ Profile allowed_scopes，越权即拒。
     * 6. 配置租户白名单时 tenant_id 必须存在且命中。
     *
     * @param array $claims 解码 claims｜来自 decode() 的关联数组，按引用写回 subject_type。示例：["iss"=>"tozo-auth","aud"=>["order-api"],"sub"=>"service:product-center"]
     * @param Profile $profile 入站 Profile｜六项绑定的全部基准值来源。示例：Profile::fromConfig(...)
     * @return void 全部通过无返回值；任一失败抛对应类型化异常。
     * @throws IssuerMismatchException issuer 不符。
     * @throws AudienceMismatchException audience 无交集。
     * @throws InvalidTokenException sub 格式非法。
     * @throws SubjectTypeMismatchException 主体类型越权。
     * @throws ClientIdMismatchException 客户端绑定不符。
     * @throws ScopeMismatchException scope 超出白名单。
     * @throws TenantMismatchException 租户缺失或不在白名单。
     */
    private function assertClaimsBoundToProfile(array &$claims, Profile $profile)
    {
        if (!isset($claims['iss']) || $claims['iss'] !== $profile->getTokenIssuer()) {
            throw new IssuerMismatchException('Token issuer does not match profile');
        }
        
        $audience = isset($claims['aud']) && is_array($claims['aud'])
            ? $claims['aud']
            : [(string)($claims['aud'] ?? '')];
        
        // 至少一个 audience 命中 Profile 允许列表（标准 JWT aud 语义）。
        if ($profile->getTokenAudience() === [] || array_intersect($audience, $profile->getTokenAudience()) === []) {
            throw new AudienceMismatchException('Token audience does not match profile');
        }
        
        $sub = isset($claims['sub']) && is_string($claims['sub']) ? $claims['sub'] : '';
        if (preg_match(self::SUBJECT_PATTERN, $sub) !== 1) {
            throw new InvalidTokenException('Invalid subject format');
        }
        
        $subjectType = substr($sub, 0, (int)strpos($sub, ':'));
        if (!in_array($subjectType, $profile->getAllowedSubjectTypes(), true)) {
            throw new SubjectTypeMismatchException(
                "Subject type [{$subjectType}] not allowed for profile [{$profile->getName()}]"
            );
        }
        
        // 主体类型只以 sub 前缀为准：不信任 Token 自带的 subject_type 声明，
        // 避免同一 Token 出现 sub 与 subject_type 不一致时按后者放行。
        $claims['subject_type'] = $subjectType;
        
        $clientId = isset($claims['client_id']) && is_string($claims['client_id']) && $claims['client_id'] !== ''
            ? $claims['client_id']
            : (isset($claims['azp']) && is_string($claims['azp']) ? $claims['azp'] : '');
        
        if ($clientId !== $profile->getExpectedClientId()) {
            throw new ClientIdMismatchException('Token client identity does not match profile');
        }
        
        $scopes = isset($claims['scope']) && is_array($claims['scope'])
            ? array_map('strval', $claims['scope'])
            : [];
        
        // granted ⊆ Profile 白名单：任何越权 Scope 直接拒绝。
        $allowed = $profile->getAllowedScopes();
        foreach ($scopes as $scope) {
            if (!in_array($scope, $allowed, true)) {
                throw new ScopeMismatchException("Token scope [{$scope}] exceeds profile allowance");
            }
        }
        
        // 租户绑定：配置白名单后 tenant_id 必须存在且命中，防止跨租户令牌横向使用。
        $allowedTenants = $profile->getAllowedTenants();
        if ($allowedTenants !== []) {
            $tenantId = isset($claims['tenant_id']) && is_string($claims['tenant_id']) ? $claims['tenant_id'] : '';
            if ($tenantId === '' || !in_array($tenantId, $allowedTenants, true)) {
                throw new TenantMismatchException('Token tenant is missing or not allowed');
            }
        }
    }
    
    /**
     * 执行 fail-closed 吊销检查。
     *
     * 使用范围：verify() 第 5 步内部调用，仅当 Profile 启用吊销时实际查询。
     * 适用场景：用户退出/风控封禁后，即使 Token 未过期也必须在剩余有效期内立即失效。
     *
     * 函数逻辑：
     * 1. 未启用吊销直接返回。
     * 2. 启用但无存储绑定 → RevocationStoreUnavailableException（运行期兜底拒绝）。
     * 3. jti 缺失 → InvalidTokenException（吊销语义依赖唯一标识）。
     * 4. 查询异常包装为 RevocationStoreUnavailableException；命中吊销抛 TokenRevokedException。
     *
     * @param array $claims 解码 claims｜用于提取 jti。示例：["jti"=>"9f8b7c6d5e4f3210", ...]
     * @param Profile $profile 入站 Profile｜提供 token_revocation.enabled 开关。示例：Profile::fromConfig(...)
     * @return void 未吊销时静默通过。
     * @throws InvalidTokenException 吊销启用但 jti 缺失。
     * @throws RevocationStoreUnavailableException 绑定缺失或查询故障（fail-closed）。
     * @throws TokenRevokedException jti 已吊销。
     */
    private function assertNotRevoked(array $claims, Profile $profile)
    {
        if (!$profile->isTokenRevocationEnabled()) {
            return;
        }
        
        if ($this->revocations === null) {
            // 启用吊销却缺少存储绑定属于启动期应拦截的配置错误；运行期兜底拒绝。
            throw new RevocationStoreUnavailableException('Revocation store binding missing');
        }
        
        $jti = isset($claims['jti']) && is_string($claims['jti']) && $claims['jti'] !== ''
            ? $claims['jti']
            : null;
        
        if ($jti === null) {
            throw new InvalidTokenException('Token jti is required when revocation enabled');
        }
        
        try {
            $revoked = $this->revocations->isRevoked($jti);
        } catch (Throwable $e) {
            // 存储不可用时必须拒绝 Token，防止已吊销 Token 逃逸。
            throw new RevocationStoreUnavailableException('Revocation store unavailable', 503, $e);
        }
        
        if ($revoked) {
            throw new TokenRevokedException();
        }
    }
    
    /**
     * 返回验证 driver 名称。
     *
     * 使用范围：日志标注与容器诊断时调用。
     * 适用场景：排障确认当前为 jwt 族验证实现。
     *
     * 函数逻辑：
     * 1. 直接返回类常量 DRIVER（'jwt'）。
     *
     * @return string 验证 driver 标识，恒为 "jwt"。示例："jwt"
     */
    public function getDriver()
    {
        return self::DRIVER;
    }
}
