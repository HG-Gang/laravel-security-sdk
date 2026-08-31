<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Tozo Security Facade
 *
 * 文件功能：
 * - 提供静态访问入口，委托容器中的接口绑定
 * - profile()/defaultProfile() 返回已校验的 Profile 对象（非原始数组）
 *
 * 安全边界：
 * - 仅暴露能力入口，不暴露配置数组与密钥材料
 * - 核心代码仍应依赖接口注入，而非本 Facade（设计 §16）
 */

namespace Tozo\Security;

use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Contracts\HttpClientInterface;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Contracts\ReplayStoreInterface;
use Tozo\Security\Contracts\TokenIssuerInterface;
use Tozo\Security\Profile;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Contracts\TokenVerifierInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Illuminate\Support\Facades\Facade as IlluminateFacade;
use Tozo\Security\Contracts\TokenRevocationStoreInterface;

/**
 * 静态调用入口；未在本类显式定义的方法代理到容器中的 'tozo_security' 绑定。
 *
 * 该绑定由 ServiceProvider 在 features.http_client=true 时指向安全 HttpClient；
 * 功能关闭时代理调用会解析失败，属于预期的尽早暴露配置错误行为。
 * 本类显式定义的静态方法（profile/keyProvider/signer 等）不经过代理，始终可用。
 *
 * @method static \Tozo\Security\Http\TozoResponse get(string $url, array $options = [], Profile|null $profile = null)
 * @method static \Tozo\Security\Http\TozoResponse post(string $url, array $data = [], array $options = [], Profile|null $profile = null)
 * @method static \Tozo\Security\Http\TozoResponse put(string $url, array $data = [], array $options = [], Profile|null $profile = null)
 * @method static \Tozo\Security\Http\TozoResponse patch(string $url, array $data = [], array $options = [], Profile|null $profile = null)
 * @method static \Tozo\Security\Http\TozoResponse delete(string $url, array $options = [], Profile|null $profile = null)
 * @method static \Tozo\Security\Http\TozoHttpClient to(string $service)
 *
 * @see \Tozo\Security\ServiceProvider
 */
class Facade extends IlluminateFacade
{
    /**
     * 返回默认出站 Profile。
     *
     * 使用范围：调用端快速获取缺省信任关系。
     * 适用场景：单目标系统应用的简化取用入口。
     *
     * 函数逻辑：
     * 1. 委托 profile(null) 走 default_profile 解析。
     *
     * @return Profile 默认出站 Profile 对象。示例：default_profile="svc_to_order" 对应的 Profile 实例
     * @throws ConfigurationException default_profile 未配置或无效。
     */
    public static function defaultProfile()
    {
        return static::profile(null);
    }
    
    /**
     * 按名称返回已校验 Profile 对象。
     *
     * 使用范围：业务层显式选择信任关系、HttpClient 请求级覆盖时调用。
     * 适用场景：同一应用对接多个目标系统时按名取用对应出站/入站配置。
     *
     * 函数逻辑：
     * 1. name 为空回退 default_profile 配置。
     * 2. 从注册表取对象；不存在或未启用抛 ConfigurationException。
     *
     * @param string|null $name Profile 名称｜注册表键。示例："svc_to_order"
     * @return Profile 已通过结构校验的 Profile 对象。示例：app('tozo_security.profiles')['svc_to_order']
     * @throws ConfigurationException Profile 不存在或被禁用。
     */
    public static function profile(string $name = null)
    {
        $resolved = $name !== null && $name !== ''
            ? $name
            : (string)config('tozo_security.default_profile');
        
        /** @var array<string,Profile> $profiles */
        $profiles = app('tozo_security.profiles');
        
        if (!isset($profiles[$resolved])) {
            throw new ConfigurationException("Profile [{$resolved}] not found or disabled");
        }
        
        return $profiles[$resolved];
    }
    
    /**
     * 读取应用级功能开关。
     *
     * 使用范围：业务判断某能力是否注册后再使用对应接口。
     * 适用场景：条件化依赖（如仅签发系统走 tokenIssuer 分支）。
     *
     * 函数逻辑：
     * 1. 读取 tozo_security.features.{feature} 布尔值，缺省 false。
     *
     * @param string $feature 功能键｜features 配置键。示例："token_issuer"
     * @return bool true=已开启。示例：true
     */
    public static function featureEnabled(string $feature)
    {
        return (bool)config("tozo_security.features.{$feature}", false);
    }
    
    /**
     * 从容器解析密钥提供器。
     *
     * 使用范围：需要直接检索密钥材料的高级用法。
     * 适用场景：自定义工具读取同源密钥，避免绕过统一来源。
     *
     * 函数逻辑：
     * 1. app(KeyProviderInterface::class) 解析单例。
     *
     * @return KeyProviderInterface 密钥提供器实例。示例：EnvKeyProvider 单例
     */
    public static function keyProvider()
    {
        return app(KeyProviderInterface::class);
    }
    
    /**
     * 从容器解析认证器。
     *
     * 使用范围：非中间件场景的手动认证。
     * 适用场景：队列/命令行中验证已捕获的载荷。
     *
     * 函数逻辑：
     * 1. app(AuthenticatorInterface::class) 解析单例。
     *
     * @return AuthenticatorInterface 认证器实例。示例：JwtAuthenticator
     */
    public static function authentication()
    {
        return app(AuthenticatorInterface::class);
    }
    
    /**
     * 从容器解析签名器。
     *
     * 使用范围：手动签发/验证非 HTTP 载体。
     * 适用场景：消息队列消息的签名与验签复用同一实现。
     *
     * 函数逻辑：
     * 1. app(SignerInterface::class) 解析单例。
     *
     * @return SignerInterface 签名器实例。示例：HmacSha256Signer
     */
    public static function signer()
    {
        return app(SignerInterface::class);
    }
    
    /**
     * 从容器解析加解密器。
     *
     * 使用范围：对非 HTTP 载体做信封加解密。
     * 适用场景：落库敏感字段的 AEAD 加解密复用。
     *
     * 函数逻辑：
     * 1. app(PayloadCipherInterface::class) 解析单例。
     *
     * @return PayloadCipherInterface 加解密器实例。示例：AesGcmCipher
     */
    public static function cipher()
    {
        return app(PayloadCipherInterface::class);
    }
    
    /**
     * 从容器解析 Token 签发器。
     *
     * 使用范围：授权系统发证流程。
     * 适用场景：feature 关闭时容器无绑定，解析即失败以防私钥误加载。
     *
     * 函数逻辑：
     * 1. app(TokenIssuerInterface::class) 解析单例。
     *
     * @return TokenIssuerInterface 签发器实例。示例：JwtTokenIssuer
     */
    public static function tokenIssuer()
    {
        return app(TokenIssuerInterface::class);
    }
    
    /**
     * 从容器解析 Token 验证器。
     *
     * 使用范围：直接验证令牌的高级用法。
     * 适用场景：WebSocket 握手等非中间件链路验证。
     *
     * 函数逻辑：
     * 1. app(TokenVerifierInterface::class) 解析单例。
     *
     * @return TokenVerifierInterface 验证器实例。示例：JwtTokenVerifier
     */
    public static function tokenVerifier()
    {
        return app(TokenVerifierInterface::class);
    }
    
    /**
     * 从容器解析防重放存储。
     *
     * 使用范围：自定义流程需要原子登记语义时。
     * 适用场景：幂等键等业务级一次性约束复用同一后端。
     *
     * 函数逻辑：
     * 1. app(ReplayStoreInterface::class) 解析单例。
     *
     * @return ReplayStoreInterface 防重放存储实例。示例：LaravelCacheReplayStore
     */
    public static function replayStore()
    {
        return app(ReplayStoreInterface::class);
    }
    
    /**
     * 从容器解析吊销存储。
     *
     * 使用范围：登出/封禁流程写入吊销记录。
     * 适用场景：业务侧主动失效已发放令牌。
     *
     * 函数逻辑：
     * 1. app(TokenRevocationStoreInterface::class) 解析单例。
     *
     * @return TokenRevocationStoreInterface 吊销存储实例。示例：LaravelCacheTokenRevocationStore
     */
    public static function tokenRevocationStore()
    {
        return app(TokenRevocationStoreInterface::class);
    }
    
    /**
     * 从容器解析审计接收器。
     *
     * 使用范围：业务安全事件补充记录。
     * 适用场景：与 SDK 审计共用脱敏管道与后端。
     *
     * 函数逻辑：
     * 1. app(AuditSinkInterface::class) 解析单例。
     *
     * @return AuditSinkInterface 审计接收器实例。示例：LaravelCacheAuditSink
     */
    public static function auditSink()
    {
        return app(AuditSinkInterface::class);
    }
    
    /**
     * 从容器解析安全 HTTP 客户端。
     *
     * 使用范围：业务发起出站服务间调用。
     * 适用场景：替代原生 Http 门面，自动完成加密签名与响应验证。
     *
     * 函数逻辑：
     * 1. app(HttpClientInterface::class) 解析单例。
     *
     * @return HttpClientInterface 安全客户端实例。示例：TozoHttpClient
     */
    public static function httpClient()
    {
        return app(HttpClientInterface::class);
    }
    
    /**
     * 返回容器访问器标识。
     *
     * 使用范围：Laravel Facade 机制解析静态调用时调用。
     * 适用场景：保留未来把静态入口整体切换为服务对象的替换能力。
     *
     * 函数逻辑：
     * 1. 返回 'tozo_security' 访问器名。
     *
     * @return string 容器绑定标识｜固定访问器名。示例："tozo_security"
     */
    protected static function getFacadeAccessor()
    {
        return 'tozo_security';
    }
}
