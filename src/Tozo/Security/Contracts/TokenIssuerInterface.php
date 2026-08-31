<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenIssuerInterface
 *
 * 文件功能：
 * - 定义 Token 受限签发契约
 * - 仅在 features.token_issuer=true 且 Profile token.issue_enabled=true 的系统可用
 *
 * 安全边界：
 * - 默认安装不注册该接口的容器绑定，避免无意加载私钥
 * - granted_scopes = profile.allowed_scopes ∩ issuer 允许范围，不得扩大权限
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Profile;
use Tozo\Security\Exceptions\TokenIssuanceException;

interface TokenIssuerInterface
{
	/**
	 * 为指定 Profile 签发 Access Token。
	 *
	 * 使用范围：授权签发系统发证流程、HttpClient 出站附加 Token、OutboundSignerMiddleware attach。
	 * 适用场景：tozo-auth 为服务间调用签发短时效 audience 限定令牌；普通系统不实现/不注册。
	 *
	 * 函数逻辑：
	 * 1. 前置校验 Profile issue_enabled 与 driver/key_id 配置。
	 * 2. 检索签名密钥并组装标准 claims（iss/aud/sub/client/scope/时间/jti）。
	 * 3. 合并 extraClaims（受保护键拒绝覆盖）后编码输出。
	 *
	 * @param Profile $profile 签发方 Profile｜提供 issuer/audience/ttl/scopes/signing_key_id 与主体信息。示例：Profile::fromConfig('tozo_auth_issue', $cfg, $keys)
	 * @param array $extraClaims 附加 claims｜扩展字段键值对；iss/aud/sub/exp 等受保护键禁止覆盖。示例：["tenant_id"=>"t01", "act"=>["sub"=>"service:gateway"]]
	 * @return string JWT 紧凑序列化串｜三段式带 kid Header。示例："eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9..."
	 * @throws TokenIssuanceException 功能未启用、配置缺失、受保护键覆盖或编码失败时抛出。
	 */
	public function issue(Profile $profile, array $extraClaims = []);
	
	/**
	 * 返回 Token driver 名称。
	 *
	 * 使用范围：日志标注与容器诊断时调用。
	 * 适用场景：排障确认当前签发实现所属 driver 族。
	 *
	 * 函数逻辑：
	 * 1. 返回实现类常量 DRIVER（如 'jwt'）。
	 *
	 * @return string driver 标识。示例："jwt"
	 */
	public function getDriver();
}
