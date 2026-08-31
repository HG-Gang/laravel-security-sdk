<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 04:10
 */

/**
 * 后台管理 API（app-admin-api）生产环境安全接口示例控制器
 *
 * 文件功能：
 * - handle：入站侧范例，返回中间件已验证的调用方身份
 * - callPeer：出站侧范例，演示按对端服务名选路发起签名请求
 *
 * 安全边界：
 * - 只读取 request attributes 中由中间件写入的已验证值；
 *   绝不从 input/query 重新取 client_id 之类的身份字段，那些值未经验签
 * - 响应体由 tozo.response 中间件统一附加完整性保护，业务无需自行签名
 */

namespace App\Http\Controllers\Internal;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\Http\Controllers\Controller;

class TozoSecurityController extends Controller
{
    /**
     * 返回入站验证结果，用于两两互调的连通性确认。
     *
     * @param Request $request 已通过 tozo.inbound 验证的请求｜身份信息在 attributes 中。
     * @return JsonResponse 健康检查响应｜由 tozo.response 中间件附加完整性保护。
     */
    public function handle(Request $request)
    {
        // 这两个值由 InboundAuthenticatorMiddleware 在验签通过后写入，可信。
        $profile = $request->attributes->get('tozo_security_profile');
        $subject = $request->attributes->get('tozo_security_subject');

        return response()->json([
            'status'  => 'ok',
            'service' => 'app-admin-api',
            'profile' => $profile === null ? null : $profile->getName(),
            'caller'  => $subject === null ? null : $subject->getClientId(),
        ]);
    }

    /**
     * 向对端发起一次签名请求。
     *
     * 加密、签名、附加 Token、响应验证全部由 SDK 完成；
     * 调用方只需要提供对端服务标识与相对路径。
     *
     * @return JsonResponse 对端返回的已验证响应内容。
     */
    public function callPeer()
    {
        // to() 按 config/tozo_security.php 的 peers 声明选路，
        // 未声明的对端会抛 ConfigurationException 而不是静默回退。
        $response = app('tozo.http')
            ->to('tozo-app-api')
            ->post('/api/internal/tozo-security/from-app-admin-api/health', ['ping' => 1]);

        return response()->json([
            'status' => $response->getStatus(),
            'body'   => $response->json(),
        ]);
    }
}
