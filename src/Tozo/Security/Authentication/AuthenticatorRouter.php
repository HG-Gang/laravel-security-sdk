<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * AuthenticatorRouter
 *
 * 文件功能：
 * - 按当前入站 Profile 声明的 authentication.driver 分派具体认证器。
 * - 支持同一应用同时使用 JWT 与 HMAC-Bearer 两种认证策略。
 *
 * 安全边界：
 * - 不遍历认证器直到某个实现成功，Profile driver 是唯一选择依据。
 * - Profile 缺失、driver 未注册或 driver 重复时直接失败，不自动降级。
 */

namespace Tozo\Security\Authentication;

use Tozo\Security\Payload;
use Tozo\Security\Profile;
use Tozo\Security\Identity\Subject;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\AuthenticationException;

class AuthenticatorRouter implements AuthenticatorInterface
{
	/**
	 * 按 driver 名建立的认证器映射，键为 driver 标识，值为具体实现。
	 *
	 * 用映射而非列表的原因：分派必须是**按键精确查找**，不能遍历列表逐个尝试。
	 * 遍历式「哪个成功算哪个」会产生模糊的认证语义——同一个请求可能因认证器注册顺序
	 * 不同而被不同策略放行，且攻击者可针对最弱的那个实现构造输入。
	 * 构造期强制 driver 唯一，保证这里的每个键只对应一个确定实现。
	 *
	 * @var array<string,AuthenticatorInterface>
	 */
	private $authenticators = [];
	
	/**
	 * 构造按 driver 分派的认证路由器。
	 *
	 * 使用范围：ServiceProvider 注册统一 AuthenticatorInterface 时调用。
	 * 适用场景：多个 Profile 分别声明 jwt 与 hmac_bearer_sha256，避免按注册顺序固定实现。
	 *
	 * 函数逻辑：
	 * 1. 逐个校验列表元素确实实现了 AuthenticatorInterface，非法元素立即抛异常。
	 * 2. 取每个实现的 driver 作为键；driver 为空或重复即抛异常——
	 *    重复会让后者静默覆盖前者，使实际生效的实现与配置意图不一致。
	 *
	 * @param array $authenticators 认证器列表｜每个实现必须提供唯一 driver。示例：[$jwt, $hmac]
	 * @throws ConfigurationException 列表含非法实现，或 driver 重复或为空。
	 */
	public function __construct(array $authenticators)
	{
		foreach ($authenticators as $authenticator) {
			if (!$authenticator instanceof AuthenticatorInterface) {
				throw new ConfigurationException('Authenticator list contains an invalid implementation');
			}
			
			$driver = $authenticator->getDriver();
			if (!is_string($driver) || $driver === '' || isset($this->authenticators[$driver])) {
				throw new ConfigurationException('Authenticator driver must be unique and non-empty');
			}
			
			$this->authenticators[$driver] = $authenticator;
		}
	}
	
	/**
	 * 返回路由器自身的标识。
	 *
	 * 使用范围：诊断日志与审计事件记录「哪个认证组件处理了本次请求」时调用。
	 * 适用场景：本类是分派器而非具体策略，返回固定标识可让日志区分
	 *           「请求走到了路由器」与「请求最终由 jwt/hmac_bearer 哪个实现处理」。
	 *
	 * 函数逻辑：
	 * 1. 返回固定字符串；本类不代表任何具体认证策略，因此该值不参与分派判定。
	 *
	 * @return string 固定路由器标识。示例："profile_router"
	 */
	public function getDriver()
	{
		return 'profile_router';
	}
	
	/**
	 * 按当前 Profile 声明的 driver 委托给对应认证器。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware 在解析出入站 Profile 之后调用。
	 * 适用场景：同一应用内不同对端使用不同认证策略时，由 Profile 唯一决定用哪个实现，
	 *           而不是由注册顺序或「谁先成功」决定。
	 *
	 * 函数逻辑：
	 * 1. Profile 缺失即抛异常——没有 Profile 就没有认证依据，不允许无 Profile 认证。
	 * 2. 取 Profile 的 authentication.driver；未声明或无对应实现即抛配置异常，
	 *    不回退到任意已注册认证器（回退会让请求被按错误策略放行）。
	 * 3. 委托给命中的实现，其返回的 Subject 直接透传，本类不修改身份内容。
	 *
	 * @param Payload $payload 共享认证负载｜由入站中间件从当前 HTTP 请求构建。示例：new Payload([...])
	 * @param Profile|null $profile 入站 Profile｜提供唯一认证 driver。示例：Profile::fromConfig(...)
	 * @return Subject 具体认证器返回的已验证主体。示例：new Subject(['sub'=>'service:pc'])
	 * @throws AuthenticationException Profile 缺失。
	 * @throws ConfigurationException 未声明 driver 或 driver 没有对应的已注册认证器。
	 */
	public function authenticate(Payload $payload, Profile $profile = null)
	{
		if ($profile === null) {
			throw new AuthenticationException('Profile is required for authentication');
		}
		
		$driver = $profile->getAuthenticationDriver();
		if ($driver === null || !isset($this->authenticators[$driver])) {
			throw new ConfigurationException(
				"No authenticator is registered for profile driver [{$driver}]"
			);
		}
		
		return $this->authenticators[$driver]->authenticate($payload, $profile);
	}
}
