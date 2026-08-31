<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * AuthenticatorInterface
 *
 * 文件功能：
 * - 定义统一认证契约：接受 Middleware/Signature 模块提供的 Payload，返回认证主体
 * - 认证策略（jwt/hmac_bearer_sha256）各自实现；失败必须抛类型化异常
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Payload;
use Tozo\Security\Profile;
use Tozo\Security\Identity\Subject;
use Tozo\Security\Exceptions\AuthenticationException;

interface AuthenticatorInterface
{
	/**
	 * 认证契约：校验可信载体并返回主体。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware.authenticateByMode 按 security_mode 调用。
	 * 适用场景：order-api 将 Bearer JWT 或 HMAC-Bearer 证明换取 Subject 的统一入口。
	 *
	 * 函数逻辑：
	 * 1. 实现方从 Payload 约定键提取凭证载体。
	 * 2. 委托底层验证；任何失败抛 AuthenticationException 族异常，禁止返回 false/null。
	 *
	 * @param Payload $payload 可信负载｜由中间件构建。示例：new Payload(['authorization_bearer'=>'eyJhbGciOi...'])
	 * @param Profile|null $profile 入站 Profile｜绑定基准。示例：Profile::fromConfig('order_inbound', ...)
	 * @return Subject 认证成功后的身份主体。示例：Subject(sub="service:product-center")
	 * @throws AuthenticationException 认证失败（含其子类）。
	 */
	public function authenticate(Payload $payload, Profile $profile = null);
	
	/**
	 * 返回认证 driver 名称契约。
	 *
	 * 使用范围：日志标注与容器诊断。
	 * 适用场景：排障确认当前策略为 jwt 或 hmac_bearer_sha256。
	 *
	 * 函数逻辑：
	 * 1. 返回实现类常量 DRIVER。
	 *
	 * @return string driver 标识。示例："jwt"
	 */
	public function getDriver();
}
