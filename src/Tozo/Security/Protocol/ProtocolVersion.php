<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ProtocolVersion
 *
 * 文件功能：
 * - 通信协议版本管理；SDK 版本与协议版本相互独立
 * - 未支持的协议必须明确拒绝，不能猜测或静默兼容
 */

namespace Tozo\Security\Protocol;

use Tozo\Security\Exceptions\ProtocolException;

class ProtocolVersion
{
    /**
     * 当前通信协议版本。与 SDK 语义化版本相互独立：
     * 升级 SDK 不必升级协议，一个 SDK 也可在迁移期支持多个协议版本。
     * 出站写入 X-Tozo-Protocol-Version 头，声明本端实现的协议基线。
     */
    public const CURRENT = '1';
    
    /**
     * 协议版本白名单，迁移期可同时接受多个版本。
     * 请求携带的版本不在白名单内一律以 400 拒绝，不做「尽力兼容」的猜测——
     * 协议字段含义在版本间可能不同，猜测解析会产出错误的签名原文。
     * 首版只有 '1'；新增版本必须同时更新冻结向量并保证旧版本仍可验证。
     *
     * @var string[]
     */
    public const SUPPORTED = ['1'];
    
    /**
     * 返回当前协议版本常量。
     *
     * 使用范围：出站 Header X-Tozo-Protocol-Version 与文档引用。
     * 适用场景：调用端声明自身实现的协议基线版本。
     *
     * 函数逻辑：
     * 1. 返回类常量 CURRENT。
     *
     * @return string 当前协议版本。示例："1"
     */
    public static function getCurrent()
    {
        return self::CURRENT;
    }
    
    /**
     * 强制校验协议版本，不支持即抛异常。
     *
     * 使用范围：InboundAuthenticatorMiddleware.handle 第 2 步。
     * 适用场景：对端升级到未支持协议时，服务端必须显式拒绝而非猜测兼容。
     *
     * 函数逻辑：
     * 1. isSupported 为假 → 抛 ProtocolException(reason=unsupported_protocol_version)。
     *
     * @param string|null $version 协议版本｜Header 提供值；null 视为不支持。示例："2"
     * @return void 无返回值。
     * @throws ProtocolException 版本不在白名单。
     */
    public static function requireSupported(string $version = null)
    {
        if ($version === null || !self::isSupported($version)) {
            throw new ProtocolException("Unsupported protocol version [{$version}]");
        }
    }
    
    /**
     * 判断协议版本是否在支持白名单内。
     *
     * 使用范围：入站中间件与出站 Header 组装前的快速判定。
     * 适用场景：未来出现 v2 时，旧 SDK 对 "2" 的请求在此直接判否。
     *
     * 函数逻辑：
     * 1. in_array 严格比对 SUPPORTED 白名单。
     *
     * @param string $version 协议版本｜待判定版本号。示例："1"
     * @return bool true=支持；false=不支持。示例：true
     */
    public static function isSupported(string $version)
    {
        return in_array($version, self::SUPPORTED, true);
    }
}
