<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 02:10
 */

/**
 * Tozo Security Configuration
 *
 * 文件功能：
 * - 唯一配置文件：本系统身份、运行环境、对端名单三项即可跑通四系统两两互调
 * - 每声明一个对端，自动生成 outbound_to_{对端} 与 inbound_from_{对端} 两个 Profile
 * - 协议版本、签名算法、加密算法、时间窗、防重放、审计后端由 SDK 固化，不在本文件出现
 *
 * 为什么只有三个键：
 * - 四系统实测 48 个 Profile 中有 19 个字段取值完全相同，真变量只有方向与对端两项
 * - 展开逻辑见 Support\ConfigNormalizer；展开结果仍受 Profile 全量校验，未放宽任何约束
 *
 * 安全边界：
 * - 本文件不含任何密钥，可随代码一起提交与审计
 * - 密钥从受控目录按 storage/app/tozo/keys/{key_id}.key 读取，不经过 .env
 * - 默认不签发 Token：仅在某条关系显式升级为 token_plus_request_signature 时才装配签发器
 */

return [
	// service string｜本系统身份；参与签名原文绑定，是全部配置推导的起点。
	// 留空表示尚未接入：SDK 装上即可启动，但不建立任何信任关系、不加载任何密钥。
	// 示例："tozo-app-api" / "app-admin-api" / "pmc-api" / "pos-api"
	'service'     => '',
	
	// environment string｜运行环境；作为密钥命名空间前缀，使 testing 与 production 不共用任何密钥。
	// 同一份代码换环境只改这一处；production 下禁用测试密钥源（array provider）。
	// 示例："production" / "testing"
	'environment' => 'production',
	
	// peers array｜对端名单；键为对端服务标识，值为其 HTTPS 根地址。
	// 声明即建立双向信任，自动生成两个 Profile 与四个用途密钥标识（请求/响应各两端）。
	// 互调时把除自己以外的对端全部列出即可，无需再写 Profile、features、defaults。
	//
	// 域名是本文件唯一需要填真实值的地方，SDK 内部不含任何硬编码地址。
	// 键名（服务标识）参与签名原文绑定，两端必须一致，不可为了好看而改动；
	// 值（base_uri）只做出站选路，改域名不影响签名结果，迁移换域名只改这里。
	//
	// 要用的时候——取消注释并把域名替换为本环境实际地址（测试与生产各填自己的）：
	//     'peers' => [
	//         'app-admin-api' => 'https://app-admin-api.example.com',
	//         'pmc-api'       => 'https://api-pms.example.com',
	//         'pos-api'       => 'https://pos-api.example.com',
	//     ],
	//   注：example.com / example.test 是 RFC 2606 保留域名，不会解析到真实主机，
	//   照抄会在出站时连接失败——这是有意为之，防止占位值被误当成可用配置上线。
	//
	// 不用的时候——整条注释掉或从数组移除即可，该对端不生成 Profile、不需要其密钥，
	// 其余关系不受影响；下面这样保留成注释，是记住服务标识拼写的最省事做法：
	//     'peers' => [
	//         'app-admin-api' => 'https://app-admin-api.example.com',
	//         // 'pos-api'    => 'https://pos-api.example.com',  // 暂不与 POS 互调
	//     ],
	//
	// 单条关系需要升级安全等级时改用数组形态，其余关系保持字符串形态不受影响：
	//     'pos-api' => [
	//         'base_uri'      => 'https://pos-api.example.com',
	//         'security_mode' => 'token_plus_request_signature',  // Token 与签名同时校验
	//         'encryption'    => true,                            // 请求体 AES-256-GCM 加密
	//     ],
	//
	// 默认空表示未声明任何对端，此时不生成 Profile、不引用任何密钥。
	'peers'       => [],
];

/*
|--------------------------------------------------------------------------
| 快速开始（三步接入，无需 .env）
|--------------------------------------------------------------------------
|
| 1. 填上面三个键：service 写本系统标识，peers 写另外三个系统。
|
| 2. 生成本系统需要的全部密钥（自动推导 key_id，自动写 .gitignore）：
|
|        php artisan tozo:security:install
|
|    该命令按 peers 推导出 12 个 key_id 并生成密钥文件，同时输出需要
|    同步给对端的密钥清单——同一条关系两端必须持有相同内容的密钥文件。
|
| 3. 体检确认配置与密钥自洽后再接流量：
|
|        php artisan tozo:security:check-config --runtime
|
| 出站调用（按目标服务选路，不必记 Profile 名）：
|
|        app('tozo.http')->to('pos-api')->post('/api/orders', ['id' => 1]);
|
| 入站防护（在 routes 中挂载，Profile 名由 install 命令输出）：
|
|        Route::middleware(['tozo.inbound', 'tozo.response'])
|            ->defaults('tozo_profile', 'tozo_app_api_inbound_from_pos_api')
|            ->post('/api/callback', [CallbackController::class, 'handle']);
|
| 完整说明见 docs/Tozo-Security-SDK-各模块使用说明书。
|
*/
