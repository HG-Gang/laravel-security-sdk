<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ScopeAuthorizerInterface
 *
 * 文件功能：
 * - 定义 Scope 授权判定契约：required_scopes ⊆ granted_scopes 且主体类型在白名单内
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Identity\Subject;
use Tozo\Security\Profile;
use Tozo\Security\Exceptions\ScopeException;

interface ScopeAuthorizerInterface
{
    /**
     * 授权判定契约。
     *
     * 使用范围：InboundAuthenticatorMiddleware.handle 第 5 步调用。
     * 适用场景：接口声明 order.write 时，主体必须已持有该 Scope 且 Profile 白名单允许。
     *
     * 函数逻辑：
     * 1. 实现方校验主体类型 ∈ Profile allowed_subject_types。
     * 2. 逐项校验 requiredScopes ⊆ subject scopes ∩ Profile allowed_scopes。
     * 3. 通配符视为配置错误；失败抛 ScopeException 族异常。
     *
     * @param Subject $subject 已验证主体｜认证器产出。示例：Subject(sub="service:pc", scope=["order.read"])
     * @param Profile $profile 入站 Profile｜提供类型与 Scope 白名单。示例：Profile::fromConfig(...)
     * @param array $requiredScopes 必需权限列表｜接口声明的最小集合。示例：["order.read"]
     * @return void 通过无返回值。
     * @throws ScopeException 类型越权或授权不足（含其子类）。
     */
    public function authorize(Subject $subject, Profile $profile, array $requiredScopes = []);
}
