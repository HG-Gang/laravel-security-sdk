<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ScopeAuthorizer
 *
 * 文件功能：
 * - Scope 授权判定：required_scopes ⊆ granted_scopes（granted = Token scope ∩ Profile 白名单）
 * - 主体类型必须在 Profile allowed_subject_types 白名单内
 *
 * 安全边界：
 * - 首版禁止通配符 Scope，防止 product.* 类越权
 * - 用户/服务/合作方同名 Scope 不互相替代：类型校验先行
 * - 授权失败抛出 ScopeDeniedException，不返回 false
 */

namespace Tozo\Security\Scope;

use Tozo\Security\Profile;
use Tozo\Security\Identity\Subject;
use Tozo\Security\Exceptions\ScopeDeniedException;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Contracts\ScopeAuthorizerInterface;
use Tozo\Security\Exceptions\SubjectTypeMismatchException;

class ScopeAuthorizer implements ScopeAuthorizerInterface
{
	/**
	 * 执行授权判定。
	 *
	 * 使用范围：InboundAuthenticatorMiddleware.handle 第 5 步，在认证通过后调用。
	 * 适用场景：接口声明 order.write 时，主体必须已持有该 Scope 且 Profile 白名单允许。
	 *
	 * 函数逻辑：
	 * 1. required 中出现通配符直接视为配置错误（首版禁越权通配）。
	 * 2. 主体类型必须命中入站 Profile allowed_subject_types（三类主体权限互不可替代）。
	 * 3. required 为空仅完成类型校验（granted⊆白名单已在 Token 验证阶段保证）。
	 * 4. 逐项校验 required 同时属于主体已授权集合与 Profile 白名单，否则拒绝。
	 *
	 * @param Subject $subject 已验证主体｜认证器产出。示例：Subject(sub="service:pc", scope=["order.read"])
	 * @param Profile $profile 入站 Profile｜提供类型与 Scope 白名单。示例：Profile::fromConfig('order_inbound', ...)
	 * @param array $requiredScopes 必需权限列表｜路由声明的最小集合。示例：["order.read"]
	 * @return void 通过无返回值。
	 * @throws ConfigurationException required 含通配符。
	 * @throws SubjectTypeMismatchException 主体类型不在白名单。
	 * @throws ScopeDeniedException 必需权限未授予或不在白名单。
	 */
	public function authorize(Subject $subject, Profile $profile, array $requiredScopes = [])
	{
		// 首版禁止通配符：required 中出现 * 直接视为配置错误。
		foreach ($requiredScopes as $required) {
			if ($required === '*' || strpos((string)$required, '*') !== false) {
				throw new ConfigurationException(
					"Wildcard scope [{$required}] is not allowed in first version"
				);
			}
		}
		
		// 主体类型必须命中入站 Profile 白名单；用户/服务/合作方权限互不可替代。
		$allowedTypes = $profile->getAllowedSubjectTypes();
		if ($allowedTypes !== [] && !in_array($subject->getSubjectType(), $allowedTypes, true)) {
			throw new SubjectTypeMismatchException(
				"Subject type [{$subject->getSubjectType()}] not allowed for profile [{$profile->getName()}]"
			);
		}
		
		if ($requiredScopes === []) {
			// 未声明 required_scopes 时仅完成主体类型校验；
			// granted ⊆ 白名单已在 Token 验证阶段由 ScopeMismatch 保证。
			return;
		}
		
		$profileAllowed = $profile->getAllowedScopes();
		
		foreach ($requiredScopes as $required) {
			$required = (string)$required;
			
			// required 必须同时属于主体已授权集合与 Profile 白名单。
			if (!$subject->hasScope($required)) {
				throw new ScopeDeniedException("Required scope [{$required}] not granted to subject");
			}
			
			if (!in_array($required, $profileAllowed, true)) {
				throw new ScopeDeniedException(
					"Required scope [{$required}] not allowed by profile [{$profile->getName()}]"
				);
			}
		}
	}
}
