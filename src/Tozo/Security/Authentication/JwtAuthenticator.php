<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * JwtAuthenticator
 *
 * 文件功能：
 * - API 认证策略（driver=jwt）：从 Payload 提取 Bearer/JWT 并委托 TokenVerifier
 * - 认证成功返回 Subject；失败抛出类型化异常
 *
 * 安全边界：
 * - 仅接受 Middleware 或 Signature 模块提供的 Payload，不从普通 input 重新取值
 * - 认证成功不代表请求完整性验证成功；token_only 模式必须由路由策略限定
 */

namespace Tozo\Security\Authentication;

use Tozo\Security\Payload;
use Tozo\Security\Profile;
use Tozo\Security\Identity\Subject;
use Tozo\Security\Exceptions\TokenFormatException;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Contracts\TokenVerifierInterface;
use Tozo\Security\Exceptions\AuthenticationException;

class JwtAuthenticator implements AuthenticatorInterface
{
	/**
	 * 认证 driver 标识。必须与 Profile 的 authentication.driver 一致，
	 * AuthenticatorRouter 以此为键选择实现，不遍历尝试。
	 */
	public const DRIVER = 'jwt';
	
	/**
	 * @var TokenVerifierInterface 验证器：承载全部密码学与绑定校验的委托目标。
	 */
	private $verifier;
	
	/**
	 * 构造认证器并注入验证器。
	 *
	 * 使用范围：ServiceProvider 在 features.token_verifier 门控下注册 AuthenticatorInterface 单例。
	 * 适用场景：入站中间件按 security_mode 调用认证器，认证器只做载体提取、验证细节全部下沉验证器。
	 *
	 * 函数逻辑：
	 * 1. 保存验证器实例（authenticate 直接委托）。
	 *
	 * @param TokenVerifierInterface $verifier Token 验证器｜执行固定算法+kid+全量绑定的实现。示例：new JwtTokenVerifier($keys, $clock, $revocations)
	 * @return void 无返回值；依赖保存到私有属性供 authenticate 使用。
	 */
	public function __construct(TokenVerifierInterface $verifier)
	{
		$this->verifier = $verifier;
	}
	
	/**
	 * 从可信 Payload 提取 Bearer Token 并委托验证器完成认证。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware.authenticateByMode 在 token_only / token_plus_request_signature 模式调用。
	 * 适用场景：order-api 收到携带 Authorization: Bearer <jwt> 的请求，提取令牌换取 Subject 供 Scope 授权与业务使用。
	 *
	 * 函数逻辑：
	 * 1. Profile 必填校验（无信任关系即拒绝认证）。
	 * 2. 从 Payload 提取载体：优先 authorization_bearer（中间件预解析），回退 jwt 字段。
	 * 3. 载体缺失/空串抛 TokenFormatException。
	 * 4. 委托 verifier->verify；Expired/Revoked/kid 等类型化异常原样向上传播，不做消息字符串匹配。
	 *
	 * @param Payload $payload 可信负载｜由中间件构建，含 authorization_bearer 或 jwt 字段。示例：new Payload(['authorization_bearer'=>'eyJhbGciOi...'])
	 * @param Profile|null $profile 入站 Profile｜提供 verify_enabled 与全部绑定基准。示例：Profile::fromConfig('order_inbound', ...)
	 * @return Subject 认证成功后的身份主体。示例：Subject(sub="service:product-center", scope=["order.read"])
	 * @throws AuthenticationException 未提供 Profile。
	 * @throws TokenFormatException 载体缺失或非字符串。
	 * @throws \Tozo\Security\Exceptions\TokenExpiredException 等｜由验证器透传的全部类型化失败。
	 */
	public function authenticate(Payload $payload, Profile $profile = null)
	{
		if ($profile === null) {
			throw new AuthenticationException('Profile is required for JWT authentication');
		}
		
		$data = $payload->getData();
		
		// 只信任中间件写入的载体字段；Authorization 原始头由 Middleware 预解析。
		$token = null;
		if (isset($data['authorization_bearer']) && is_string($data['authorization_bearer'])) {
			$token = $data['authorization_bearer'];
		} elseif (isset($data['jwt']) && is_string($data['jwt'])) {
			$token = $data['jwt'];
		}
		
		if ($token === null || $token === '') {
			throw new TokenFormatException('Missing bearer token in payload');
		}
		
		// 类型化验证异常原样向上传播（Expired/Revoked/kid 等），不做消息字符串匹配。
		return $this->verifier->verify($token, $profile);
	}
	
	/**
	 * 返回认证 driver 名称。
	 *
	 * 使用范围：日志标注与容器诊断时调用。
	 * 适用场景：排障确认当前认证策略为 jwt 而非 hmac_bearer_sha256。
	 *
	 * 函数逻辑：
	 * 1. 直接返回类常量 DRIVER（'jwt'）。
	 *
	 * @return string 认证 driver 标识，恒为 "jwt"。示例："jwt"
	 */
	public function getDriver()
	{
		return self::DRIVER;
	}
}
