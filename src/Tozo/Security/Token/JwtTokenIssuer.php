<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * JwtTokenIssuer
 *
 * 文件功能：
 * - JWT 受限签发器：支持 jwt_rs256（推荐）与 jwt_hs256
 * - claims 固定包含 iss/aud/sub/client_id/subject_type/scope/jti/iat/nbf/exp
 * - Header 携带 kid = token.signing_key_id，供验证端白名单映射
 *
 * 安全边界：
 * - 仅当 Profile token.issue_enabled=true 时可用；默认安装不注册本接口
 * - granted_scopes = Profile allowed_scopes，签发不得扩大权限
 * - issuer/audience/signing_key_id 为安全必填项，缺失直接失败，不使用静默默认值
 */

namespace Tozo\Security\Token;

use Throwable;
use Firebase\JWT\JWT;
use Tozo\Security\Key\KeyUsage;
use Tozo\Security\Contracts\ClockInterface;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Contracts\TokenIssuerInterface;
use Tozo\Security\Profile;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\TokenIssuanceException;

class JwtTokenIssuer implements TokenIssuerInterface
{
    /**
     * 签发器族标识（jwt）。具体算法由 Profile 的 token.driver 经 ALGORITHMS 映射决定，
     * 本常量只用于日志标注与容器诊断，不参与算法选择。
     */
    public const DRIVER = 'jwt';
    
    /**
     * driver 到签发算法的映射。与验证端 JwtTokenVerifier::ALGORITHMS 保持同一事实来源，
     * 两处取值必须一致——不一致会产生「签发用 RS256、验证按 HS256」这类算法错配，
     * 表现为所有令牌验证失败，而错误信息通常只说签名无效，难以定位到映射表。
     * 算法由 Profile 的 token.driver 决定，绝不由令牌 Header 的 alg 决定。
     */
    private const ALGORITHMS = [
        Profile::DEFAULT_TOKEN_DRIVER => 'RS256',
        'jwt_hs256'                   => 'HS256',
    ];
    
    /**
     * extraClaims 禁止覆盖的受保护键；身份/时间/权限语义只能由 Profile 派生。
     */
    private const PROTECTED_CLAIMS = [
        'iss', 'aud', 'sub', 'client_id', 'subject_type',
        'scope', 'iat', 'nbf', 'exp', 'jti',
    ];
    
    /**
     * 密钥提供器。按 Profile 的 token.signing_key_id 检索签名密钥：
     * RS256 检索 PEM 私钥，HS256 检索共享密钥。
     * 这是签发能力的安全边界所在——只有 features.token_issuer 开启时容器才注册本类，
     * 因此未授权签发的系统连私钥都不会被加载（设计 §13）。
     *
     * @var KeyProviderInterface
     */
    private $keys;
    
    /**
     * 时钟。提供 iat/nbf/exp 三个时间 claim 的基准时刻。
     * 注入而非直接调用 time()：令牌有效期边界必须能被用例精确复现，
     * 靠真实时间流逝验证「刚好过期」既慢又会间歇性失败。
     *
     * @var ClockInterface
     */
    private $clock;
    
    /**
     * 构造签发器并注入密钥来源与时钟。
     *
     * 使用范围：ServiceProvider 在 features.token_issuer=true 且存在引用 Profile 时注册单例。
     * 适用场景：授权签发系统（如 tozo-auth）装配 Token 发放能力；普通系统不注册以避免加载私钥。
     *
     * 函数逻辑：
     * 1. 保存密钥提供器（issue 按 signing_key_id 检索 RS256 私钥 PEM 或 HS256 共享密钥）。
     * 2. 保存时钟（claims 的 iat/nbf/exp 全部以此为基准）。
     *
     * @param KeyProviderInterface $keys 密钥提供器｜检索签名私钥材料。示例：new EnvKeyProvider()（TOZO_SECURITY_KEY_TOZO_AUTH_JWT_PRIVATE）
     * @param ClockInterface $clock 时钟接口｜生产传 SystemClock，测试传固定时钟。示例：new SystemClock()
     * @return void 无返回值；依赖保存到私有属性供 issue 使用。
     */
    public function __construct(KeyProviderInterface $keys, ClockInterface $clock)
    {
        $this->keys  = $keys;
        $this->clock = $clock;
    }
    
    /**
     * 为指定 Profile 签发 Access Token。
     *
     * 使用范围：TozoHttpClient 出站附加 Token、OutboundSignerMiddleware attach、授权系统登录/服务间发证流程。
     * 适用场景：tozo-auth 为 product-center 签发 audience=order-api 的服务令牌，scope 取 Profile 白名单交集且不可扩大。
     *
     * 函数逻辑：
     * 1. 前置校验 token.issue_enabled=true，否则拒绝（默认关闭原则）。
     * 2. driver 映射固定算法；signing_key_id 必填校验。
     * 3. KeyUsage 断言轮换状态 active 后检索私钥/共享密钥。
     * 4. 组装九项标准 claims：iss/aud/sub(type:id)/client_id/subject_type/scope/iat/nbf/exp/jti(CSPRNG)。
     * 5. JWT::encode 携带 kid Header 输出紧凑令牌；编码异常包装为 TokenIssuanceException。
     *
     * @param Profile $profile 签发方 Profile｜提供 issuer/audience/ttl/scopes/signing_key_id 与主体三元组。示例：Profile::fromConfig('tozo_auth_issue', $cfg, $keys)
     * @param array $extraClaims 附加自定义 claims｜业务扩展字段；PROTECTED_CLAIMS 内的身份/时间/权限键禁止出现，命中即抛异常。示例：["device_id"=>"d-01","tenant_id"=>"t01"]
     * @return string JWT 紧凑序列化串｜三段式带 kid Header。示例："eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9..."
     * @throws TokenIssuanceException 功能未启用、附加 claims 试图覆盖受保护键或 JWT 编码失败。
     * @throws ConfigurationException driver 不支持 / signing_key_id 缺失 / subject_id 缺失（validate 阶段已拦截）。
     * @throws KeyNotFoundException 密钥缺失或轮换状态非 active。
     */
    public function issue(Profile $profile, array $extraClaims = [])
    {
        if (!$profile->isTokenIssueEnabled()) {
            throw new TokenIssuanceException(
                "Profile [{$profile->getName()}] has token.issue_enabled=false"
            );
        }
        
        $driver = $profile->getTokenDriver();
        if (!isset(self::ALGORITHMS[$driver])) {
            throw new ConfigurationException("Unsupported token driver [{$driver}]");
        }
        
        $keyId = $profile->getTokenSigningKeyId();
        if ($keyId === null) {
            throw new ConfigurationException(
                "Profile [{$profile->getName()}] token.signing_key_id is required for issuance"
            );
        }
        
        // 签发仅允许 active 私钥；私钥只存在于授权签发方。
        KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_ISSUE);
        $key = $this->keys->getKey($keyId);
        
        $now = $this->clock->now();
        
        $claims = [
            'iss'          => (string)$profile->getTokenIssuer(),
            'aud'          => $profile->getTokenAudience(),
            'sub'          => $profile->getSubjectType() . ':' . (string)$profile->getSubjectId(),
            'client_id'    => $profile->getClientId(),
            'subject_type' => $profile->getSubjectType(),
            'scope'        => $profile->getAllowedScopes(),
            'iat'          => $now,
            'nbf'          => $now,
            'exp'          => $now + $profile->getTokenTtlSeconds(),
            // jti 用于吊销与审计，不等同于请求级防重放。
            'jti'          => bin2hex(random_bytes(16)),
        ];
        
        try {
            // 附加 claims 合并：受保护键禁止覆盖，防止调用方篡改身份/时间/权限语义。
            foreach ($extraClaims as $claimKey => $claimValue) {
                if (in_array($claimKey, self::PROTECTED_CLAIMS, true)) {
                    throw new TokenIssuanceException("Protected claim [{$claimKey}] cannot be overridden");
                }
                $claims[$claimKey] = $claimValue;
            }
            
            return JWT::encode($claims, $key, self::ALGORITHMS[$driver], $keyId);
        } catch (TokenIssuanceException $e) {
            throw $e;
        } catch (Throwable $e) {
            // 编码失败不泄露密钥信息，仅保留异常链用于内部日志。
            throw new TokenIssuanceException('JWT encoding failed', 500, $e);
        }
    }
    
    /**
     * 返回签发 driver 名称。
     *
     * 使用范围：日志标注与容器诊断时调用。
     * 适用场景：排障确认当前为 jwt 族签发实现。
     *
     * 函数逻辑：
     * 1. 直接返回类常量 DRIVER（'jwt'）。
     *
     * @return string 签发 driver 标识，恒为 "jwt"。示例："jwt"
     */
    public function getDriver()
    {
        return self::DRIVER;
    }
}
