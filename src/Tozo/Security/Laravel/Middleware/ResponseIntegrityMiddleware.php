<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ResponseIntegrityMiddleware
 *
 * 文件功能：
 * - 服务端（被调用方）响应保护中间件：业务响应写出前按 Profile 固定 mode 生成完整性保护
 * - encrypted 模式：Body 替换为响应专用密钥加密的 AEAD 信封，Content-Type 固定 application/json
 * - signed 模式：Body 保持明文，追加 X-Tozo-Response-Signature 方向绑定签名头
 *
 * 链路位置（设计 §16 服务端流程最后两步）：
 *   业务 Controller 返回响应
 *     → 本中间件按 response_integrity 生成保护
 *     → 写出响应
 *   调用端 TozoHttpClient.verifyResponse 完成对应验证
 *
 * 安全边界：
 * - Profile 必须由 InboundAuthenticatorMiddleware 认证通过后写入 request attributes；
 *   未认证请求不生成任何保护，避免为伪造请求签发有效响应证明
 * - required=false 时原样放行；required=true 但生成失败一律返回 500，
 *   绝不退化为未受保护的明文响应
 * - 仅处理 2xx 成功响应；错误响应保持安全类别码原样，不因加密而掩盖状态语义
 */

namespace Tozo\Security\Laravel\Middleware;

use Closure;
use Throwable;
use Tozo\Security\Profile;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Illuminate\Http\Response;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Contracts\ResponseIntegrityInterface;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

class ResponseIntegrityMiddleware
{
    /**
     * 响应保护生成器。被调用方用它按 Profile 声明的固定 mode 为响应体生成保护
     * （signed 生成方向绑定的 HMAC，encrypted 生成 AEAD 信封）。
     * 它与调用端的验证器构成闭环：本端不生成，对端就会因 required 而拒收整个响应。
     * 未启用该功能时为 null，此时中间件原样放行——因此 Profile 声明 required
     * 的关系必须确保该绑定存在，否则闭环在被调用方这一侧断开。
     *
     * @var ResponseIntegrityInterface|null
     */
    private $integrity;
    
    /**
     * 日志器，只记录生成失败的原因码与响应元数据。
     * 绝不记录响应 Body 与密钥：响应体常含业务敏感数据，
     * 而日志的读取面通常远宽于接口本身。
     * 为 null 时静默跳过日志，不影响响应保护的生成结果。
     *
     * @var LoggerInterface|null
     */
    private $logger;
    
    /**
     * 构造响应保护中间件。
     *
     * 使用范围：ServiceProvider 注册容器绑定 tozo.middleware.response 时调用。
     * 适用场景：被调用方在受保护路由上挂载本中间件，使响应侧与调用端的
     *           response_integrity.required 形成闭环。
     *
     * 函数逻辑：
     * 1. 保存响应保护生成器（可空：功能未启用时解析为 null，运行期按 Profile 判定是否必需）。
     * 2. 保存日志器（可空）。
     *
     * @param ResponseIntegrityInterface|null $integrity 响应保护生成器｜required Profile 必需。示例：new ResponseIntegrityChecker($cipher, $keys)
     * @param LoggerInterface|null $logger 日志器｜PSR-3 实例。示例：Log::channel('security')
     * @return void 无返回值。
     */
    public function __construct(
        ResponseIntegrityInterface $integrity = null,
        LoggerInterface            $logger = null
    )
    {
        $this->integrity = $integrity;
        $this->logger    = $logger;
    }
    
    /**
     * 按 Profile 固定 mode 为业务响应生成完整性保护。
     *
     * 使用范围：宿主路由在 InboundAuthenticatorMiddleware 之后挂载本中间件。
     * 适用场景：调用端 Profile 声明 response_integrity.required=true 时，
     *           被调用方必须产出对应保护，否则调用端会拒绝该响应。
     *
     * 函数逻辑：
     * 1. 先执行后续管线取得业务响应。
     * 2. 从 request attributes 读取已认证 Profile；缺失说明未经认证链路，原样放行。
     * 3. required!==true 原样放行（无保护要求）。
     * 4. 非 2xx 响应原样放行：错误响应保持安全类别码语义。
     * 5. 按 mode 分派 encrypted（替换 Body）或 signed（追加签名头）。
     * 6. 生成失败记录原因码并返回 500，绝不写出未受保护响应。
     *
     * @param Request $request HTTP 请求对象｜提供已认证 Profile attribute。示例：Request::create(...)
     * @param Closure $next 后续管线｜业务控制器。示例：function ($req) { return $next($req); }
     * @return mixed 已保护响应，或原样业务响应，或 500 安全响应。
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);
        
        // 只为已通过入站认证的请求生成保护；未认证请求不得获得有效响应证明。
        $profile = $request->attributes->get('tozo_security_profile');
        if (!$profile instanceof Profile) {
            return $response;
        }
        
        $config = $profile->getResponseIntegrityConfig();
        if (($config['required'] ?? false) !== true) {
            return $response;
        }
        
        if (!$response instanceof SymfonyResponse) {
            // 非标准响应对象无法安全改写 Body；视为服务端缺陷而不是放行。
            $this->log('error', 'response_integrity_unsupported_response');
            
            return $this->failure();
        }
        
        // 错误响应保留原状态与安全类别码；加密会掩盖 4xx/5xx 的可观测语义。
        $status = $response->getStatusCode();
        if ($status < 200 || $status > 299) {
            return $response;
        }
        
        try {
            return $this->protect($response, $profile, (string)($config['mode'] ?? ''));
        } catch (Throwable $e) {
            // 无法生成保护时不能退化为明文响应；统一失败关闭。
            $this->log('error', 'response_integrity_generation_failed', $e);
            
            return $this->failure();
        }
    }
    
    /**
     * 记录内部原因码日志。
     *
     * 使用范围：handle 的失败分支调用。
     * 适用场景：排障需要精确原因，而对外响应必须保持脱敏。
     *
     * 函数逻辑：
     * 1. 未注入 logger 静默返回；否则输出原因码与异常类名（不含消息体与 Body）。
     *
     * @param string $level 日志级别｜PSR-3 方法名。示例："error"
     * @param string $reasonCode 内部原因码｜稳定错误码。示例："response_integrity_generation_failed"
     * @param Throwable|null $e 原始异常｜仅取类名入日志。示例：new ResponseIntegrityException()
     * @return void 无返回值。
     */
    private function log(string $level, string $reasonCode, Throwable $e = null)
    {
        if ($this->logger === null) {
            return;
        }
        
        $this->logger->{$level}('tozo_security response integrity failed', [
            'reason_code' => $reasonCode,
            'exception'   => $e === null ? null : get_class($e),
        ]);
    }
    
    /**
     * 构造统一的服务端失败响应。
     *
     * 使用范围：handle 在保护生成失败时调用。
     * 适用场景：对外只暴露 internal_error，不泄露 mode、key_id 或底层异常细节。
     *
     * 函数逻辑：
     * 1. 返回 500 JSON 响应，内容固定为 internal_error。
     *
     * @return Response 500 JSON 响应。示例：{"error":"internal_error"}
     */
    private function failure()
    {
        return new Response(
            (string)json_encode(['error' => 'internal_error']),
            500,
            ['Content-Type' => 'application/json']
        );
    }
    
    /**
     * 按固定 mode 执行实际保护动作。
     *
     * 使用范围：handle 内部调用（已确认 required=true 且响应为 2xx）。
     * 适用场景：encrypted 需要同时替换 Body 与 Content-Type；signed 只追加签名头。
     *
     * 函数逻辑：
     * 1. integrity 绑定缺失属于配置错误（Profile 要求保护但功能未启用）。
     * 2. encrypted：生成信封替换 Body，Content-Type 固定 application/json。
     * 3. signed：生成签名值写入 Header，Body 不变。
     * 4. 未知 mode 抛配置异常（Profile 校验已拦截，此处兜底）。
     *
     * @param SymfonyResponse $response 业务响应｜将被就地改写。示例：new Response('{"ok":true}', 200)
     * @param Profile $profile 已认证入站 Profile｜提供 mode 与响应密钥。示例：Profile::fromConfig(...)
     * @param string $mode 固定保护模式｜encrypted 或 signed。示例："encrypted"
     * @return SymfonyResponse 已保护的同一响应实例。
     * @throws ConfigurationException 绑定缺失或 mode 不支持。
     */
    private function protect(SymfonyResponse $response, Profile $profile, string $mode)
    {
        if ($this->integrity === null) {
            throw new ConfigurationException(
                "Profile [{$profile->getName()}] requires response integrity but checker binding is missing"
            );
        }
        
        $body = (string)$response->getContent();
        
        if ($mode === 'encrypted') {
            // Body 替换为信封 JSON；Content-Type 必须与最终字节一致。
            $response->setContent($this->integrity->protectEncryptedResponse($body, $profile));
            $response->headers->set('Content-Type', 'application/json');
            
            return $response;
        }
        
        if ($mode === 'signed') {
            // 明文 Body 不变，仅追加方向绑定签名头供调用端先验后用。
            $response->headers->set(
                $this->integrity->getSignatureHeaderName(),
                $this->integrity->protectSignedResponse($body, $profile)
            );
            
            return $response;
        }
        
        throw new ConfigurationException("Unsupported response_integrity.mode [{$mode}]");
    }
}
