<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 全链路闭环测试
 *
 * 文件功能：
 * - 单个用例串起完整往返：
 *   调用端加密+签名 → 入站中间件验签+解密 → 业务 → 响应保护中间件生成保护
 *   → 调用端验证响应完整性 → 业务拿到明文
 * - 覆盖 encrypted 与 signed 两种响应模式
 *
 * 安全边界：
 * - 双端共享同一容器（同密钥、同 ReplayStore），模拟真实互通
 * - 任一环节失败即整体失败，不允许"半保护"通过
 */

namespace Tozo\Security\Tests\Integration;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Http\TozoHttpClient;
use Tozo\Security\Scope\ScopeAuthorizer;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Profile;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Contracts\ResponseIntegrityInterface;
use Tozo\Security\Laravel\Middleware\ResponseIntegrityMiddleware;
use Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware;

class FullLoopTest extends TestCase
{
    /**
     * 响应签名用途 key_id。与请求签名密钥（HMAC_KEY）分开，
     * 用于验证 signed 模式下响应密钥的独立用途约束。
     */
    public const RESP_SIGN_KEY = 'order-response-signing';
    
    /**
     * encrypted 响应模式：请求加密验签 + 响应加密验证的完整往返。
     */
    public function test_encrypted_full_round_trip()
    {
        $result = $this->runLoop('encrypted');
        
        $this->assertTrue($result['business_reached'], '入站验证未通过，业务未被执行');
        $this->assertSame(200, $result['client_status']);
        // 调用端拿到的是解密后的明文业务响应。
        $this->assertSame(['order_id' => 42], $result['client_json']);
        // 线上响应体必须是信封，不含明文。
        $this->assertStringNotContainsString('order_id', $result['wire_response_body']);
    }
    
    /**
     * 执行一次完整往返。
     *
     * @param string $mode 响应保护模式｜encrypted 或 signed。示例："encrypted"
     * @param bool $skipResponseProtection 是否跳过服务端响应保护｜用于负向用例。示例：false
     * @return array 往返结果快照。
     */
    private function runLoop(string $mode, bool $skipResponseProtection = false)
    {
        $container = $this->makeContainer([], [self::RESP_SIGN_KEY => str_repeat('d', 32)]);
        $keys      = $container->make(KeyProviderInterface::class);
        
        $outbound = Profile::fromConfig('svc_to_order', $this->outboundFor($mode), $keys);
        $inbound  = Profile::fromConfig('order_inbound', $this->inboundFor($mode), $keys);
        
        $businessReached = false;
        $wireResponse    = ['body' => '', 'headers' => []];
        
        // 服务端管线：入站验证 → 业务 → 响应保护。
        $serverPipeline = function (string $method, string $url, array $headers, string $body)
        use ($container, $inbound, &$businessReached, &$wireResponse, $skipResponseProtection) {
            $request = Request::create($url, $method, [], [], [], [], $body);
            foreach ($headers as $name => $value) {
                $request->headers->set($name, $value);
            }
            
            $inboundMiddleware = new InboundAuthenticatorMiddleware(
                ['order_inbound' => $inbound],
                $container->make(SignerInterface::class),
                null,
                new ScopeAuthorizer(),
                $container->make(PayloadCipherInterface::class),
                null
            );
            
            $response = $inboundMiddleware->handle(
                $request,
                function (Request $verified) use (&$businessReached, $skipResponseProtection, $container) {
                    $businessReached = true;
                    
                    // 解密后业务读到的必须是明文请求体。
                    $this->assertSame('{"sku":"A-1"}', (string)$verified->getContent());
                    
                    $business = new Response('{"order_id":42}', 200, ['Content-Type' => 'application/json']);
                    
                    if ($skipResponseProtection) {
                        // 负向路径：不挂响应保护中间件，直接返回未受保护响应。
                        return $business;
                    }
                    
                    return (new ResponseIntegrityMiddleware(
                        $container->make(ResponseIntegrityInterface::class)
                    ))->handle($verified, function () use ($business) {
                        return $business;
                    });
                }
            );
            
            $wireResponse = [
                'body'    => (string)$response->getContent(),
                'headers' => $this->flattenHeaders($response),
            ];
            
            return [
                'status'  => $response->getStatusCode(),
                'headers' => $wireResponse['headers'],
                'body'    => $wireResponse['body'],
            ];
        };
        
        $client = new TozoHttpClient(
            $container->make(AuditSinkInterface::class),
            $container->make(SignerInterface::class),
            $container->make(PayloadCipherInterface::class),
            $container->make(ResponseIntegrityInterface::class),
            null,
            $serverPipeline
        );
        $client->setProfile($outbound);
        
        $response = $client->post('https://order-api.internal/api/orders', ['sku' => 'A-1']);
        
        return [
            'business_reached'      => $businessReached,
            'client_status'         => $response->getStatus(),
            'client_json'           => $response->json(),
            'wire_response_body'    => $wireResponse['body'],
            'wire_response_headers' => $wireResponse['headers'],
        ];
    }
    
    /**
     * 出站 Profile：signed_request + 请求加密 + 指定响应保护模式。
     */
    private function outboundFor(string $mode)
    {
        $config                            = $this->outboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['token']['attach_enabled'] = false;
        $config['encryption']['enabled']   = true;
        $config['response_integrity']      = $this->responseIntegrityFor($mode);
        
        return $config;
    }
    
    /**
     * 按模式生成响应完整性配置段（响应密钥与请求密钥严格分离）。
     */
    private function responseIntegrityFor(string $mode)
    {
        if ($mode === 'signed') {
            return [
                'required'  => true,
                'mode'      => 'signed',
                'signature' => ['key_id' => self::RESP_SIGN_KEY],
            ];
        }
        
        return [
            'required'   => true,
            'mode'       => 'encrypted',
            'encryption' => ['key_id' => self::RESP_ENC_KEY],
        ];
    }
    
    /**
     * 入站 Profile：与出站配对，response_integrity 必须完全一致。
     */
    private function inboundFor(string $mode)
    {
        $config                  = $this->inboundProfile();
        $config['security_mode'] = 'signed_request';
        unset($config['token']);
        $config['encryption']         = [
            'enabled' => true,
            'driver'  => 'aes_256_gcm',
            'key_id'  => self::ENC_KEY,
        ];
        $config['response_integrity'] = $this->responseIntegrityFor($mode);
        
        return $config;
    }
    
    /**
     * 把 Symfony ResponseHeaderBag 摊平为「名称=>单值」映射，模拟真实传输层交付形态。
     */
    private function flattenHeaders(Response $response)
    {
        $flat = [];
        foreach ($response->headers->all() as $name => $values) {
            $flat[$name] = is_array($values) ? (string)reset($values) : (string)$values;
        }
        
        // 保留标准大小写，便于断言签名头存在。
        $signatureHeader = 'X-Tozo-Response-Signature';
        $value           = $response->headers->get($signatureHeader);
        if ($value !== null) {
            $flat[$signatureHeader] = $value;
        }
        
        return $flat;
    }
    
    /**
     * signed 响应模式：响应保持明文但必须携带方向绑定签名。
     */
    public function test_signed_full_round_trip()
    {
        $result = $this->runLoop('signed');
        
        $this->assertTrue($result['business_reached']);
        $this->assertSame(200, $result['client_status']);
        $this->assertSame(['order_id' => 42], $result['client_json']);
        // signed 模式响应体是明文，但签名头必须存在。
        $this->assertStringContainsString('order_id', $result['wire_response_body']);
        $this->assertNotEmpty($result['wire_response_headers']['X-Tozo-Response-Signature'] ?? null);
    }
    
    /**
     * 服务端不生成响应保护时，调用端必须拒绝该响应（不接受未受保护数据）。
     */
    public function test_client_rejects_unprotected_response()
    {
        $this->expectException(\Tozo\Security\Exceptions\ResponseIntegrityException::class);
        
        // 传输桩直接返回未受保护的明文，绕过响应保护中间件。
        $this->runLoop('signed', true);
    }
}
