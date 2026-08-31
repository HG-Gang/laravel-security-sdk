<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TokenVerifierInterface
 *
 * 文件功能：
 * - 定义 Token 验证契约：固定算法、kid 白名单、issuer/audience/主体/Scope 绑定与吊销检查
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Identity\Subject;
use Tozo\Security\Profile;
use Tozo\Security\Exceptions\TokenVerificationException;

interface TokenVerifierInterface
{
    /**
     * 全量验证契约。
     *
     * 使用范围：JwtAuthenticator.authenticate 委托调用（token_only/plus 模式）。
     * 适用场景：入站系统校验签名+kid+iss/aud/sub/client/scope/吊销后发放 Subject。
     *
     * 函数逻辑：
     * 1. 实现方按 Profile driver 固定算法，kid 白名单映射候选密钥。
     * 2. 解码并逐项绑定 claims；执行 fail-closed 吊销检查。
     * 3. 成功返回 Subject；失败抛对应类型化异常。
     *
     * @param string $token JWT 串｜紧凑三段式。示例："eyJhbGciOi..."
     * @param Profile $profile 入站 Profile｜全部绑定基准。示例：Profile::fromConfig(...)
     * @return Subject 认证成功后的身份主体。示例：true
     * @throws TokenVerificationException 前置条件不满足。
     * @throws \Tozo\Security\Exceptions\TokenExpiredException 已过期。
     * @throws \Tozo\Security\Exceptions\TokenRevokedException 已吊销。
     * @throws \Tozo\Security\Exceptions\RevocationStoreUnavailableException 吊销存储不可用。
     */
    public function verify(string $token, Profile $profile);
    
    /**
     * 返回验证 driver 名称契约。
     *
     * 使用范围：日志标注与容器诊断。
     * 适用场景：确认当前为 jwt 族验证实现。
     *
     * 函数逻辑：
     * 1. 返回实现类常量 DRIVER。
     *
     * @return string driver 标识。示例："jwt"
     */
    public function getDriver();
}
