<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Integration;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Identity\Subject;
use Tozo\Security\Contracts\HttpClientInterface;
use Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware;

/**
 * 端到端闭环：出站 Client 签名 → 入站 Middleware 验签/验 Token → 业务拿到 Subject。
 * 共享同一容器（同一密钥与 ReplayStore），模拟真实双端互通。
 */
class EndToEndTest extends TestCase
{
    /**
     * 传输桩捕获的出站请求，结构为 {method,url,headers,body}。
     * 端到端用例的观察点：调用端签名后的**实际发送字节**在此落地，
     * 随后原样喂给入站中间件，从而在不起真实 HTTP 服务的前提下验证双端闭环。
     * 为 null 表示尚未发出任何请求，可用于断言某分支确实没有触发调用。
     *
     * @var array|null
     */
    private $captured;
    
    public function test_outbound_request_passes_inbound_verification()
    {
        [$client, $container] = $this->client();
        
        // 出站 Profile 未启用 token attach（默认安装），签名模式为 plus → 需要入站同步关闭 token 验证？
        // 为保持 AND 语义一致，本用例使用 signed_request 双端配置。
        $outboundConfig                                   = $this->outboundProfile();
        $outboundConfig['security_mode']                  = 'signed_request';
        $outboundConfig['token']['attach_enabled']        = false;
        $outboundConfig['encryption']['enabled']          = false;
        $outboundConfig['response_integrity']['required'] = false;
        $inboundConfig                                    = $this->inboundProfile();
        $inboundConfig['security_mode']                   = 'signed_request';
        $inboundConfig['token']['verify_enabled']         = false;
        
        $client->setProfile(\Tozo\Security\Profile::fromConfig(
            'svc_to_order',
            $outboundConfig,
            $container->make(\Tozo\Security\Contracts\KeyProviderInterface::class)
        ));
        
        $response = $client->post('https://order-api.internal/api/orders', ['sku' => 'A-1']);
        
        $this->assertSame(200, $response->getStatus());
        $this->assertSame(['ok' => true], $response->json());
        
        // 捕获的请求必须携带完整 Protocol v1 Header 集。
        $this->assertArrayHasKey('X-Tozo-Signature', $this->captured['headers']);
        $this->assertArrayHasKey('X-Tozo-Nonce', $this->captured['headers']);
        $this->assertSame('1', $this->captured['headers']['X-Tozo-Protocol-Version']);
        
        // 构造等价入站 Request 并走中间件。
        $request = Request::create(
            'https://order-api.internal/api/orders',
            'POST',
            [],
            [],
            [],
            [],
            $this->captured['body']
        );
        foreach ($this->captured['headers'] as $name => $value) {
            $request->headers->set($name, $value);
        }
        
        $middleware = new InboundAuthenticatorMiddleware(
            [
                'order_inbound' => \Tozo\Security\Profile::fromConfig(
                    'order_inbound',
                    $inboundConfig,
                    $container->make(\Tozo\Security\Contracts\KeyProviderInterface::class)
                ),
            ],
            $container->make(\Tozo\Security\Contracts\SignerInterface::class),
            $container->make(\Tozo\Security\Contracts\AuthenticatorInterface::class),
            new \Tozo\Security\Scope\ScopeAuthorizer()
        );
        
        $reachedBusiness = false;
        $response        = $middleware->handle($request, function (Request $req) use (&$reachedBusiness) {
            $reachedBusiness = true;
            /** @var Subject $subject */
            $subject = $req->attributes->get('tozo_security_subject');
            
            // signed_request 模式下主体来自签名 key_id 归属。
            $this->assertSame('product-center', $subject->getClientId());
            
            return new Response('{"ok":true}', 200);
        });
        
        $this->assertTrue($reachedBusiness);
        $this->assertSame(200, $response->getStatusCode());
    }
    
    private function client()
    {
        $container = $this->makeContainer();
        $holder    = &$this->captured;
        
        /** @var HttpClientInterface $client */
        $client = $container->make(HttpClientInterface::class);
        
        // 注入测试传输：捕获请求并返回 200 响应（不依赖网络）。
        $client = new \Tozo\Security\Http\TozoHttpClient(
            $container->make(\Tozo\Security\Contracts\AuditSinkInterface::class),
            $container->make(\Tozo\Security\Contracts\SignerInterface::class),
            $container->make(\Tozo\Security\Contracts\PayloadCipherInterface::class),
            $container->make(\Tozo\Security\Contracts\ResponseIntegrityInterface::class),
            null,
            function (string $method, string $url, array $headers, string $body) use (&$holder) {
                $holder = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];
                
                return ['status' => 200, 'headers' => [], 'body' => '{"ok":true}'];
            }
        );
        
        return [$client, $container];
    }
    
    public function test_tampered_body_is_rejected_with_safe_error()
    {
        [$client, $container] = $this->client();
        
        $outboundConfig                                   = $this->outboundProfile();
        $outboundConfig['security_mode']                  = 'signed_request';
        $outboundConfig['token']['attach_enabled']        = false;
        $outboundConfig['encryption']['enabled']          = false;
        $outboundConfig['response_integrity']['required'] = false;
        
        $client->setProfile(\Tozo\Security\Profile::fromConfig(
            'svc_to_order',
            $outboundConfig,
            $container->make(\Tozo\Security\Contracts\KeyProviderInterface::class)
        ));
        
        $client->post('https://order-api.internal/api/orders', ['sku' => 'A-1']);
        
        $request = Request::create(
            'https://order-api.internal/api/orders',
            'POST',
            [],
            [],
            [],
            [],
            '{"sku":"B-2"}'
        );
        foreach ($this->captured['headers'] as $name => $value) {
            $request->headers->set($name, $value);
        }
        
        $inboundConfig                            = $this->inboundProfile();
        $inboundConfig['security_mode']           = 'signed_request';
        $inboundConfig['token']['verify_enabled'] = false;
        
        $middleware = new InboundAuthenticatorMiddleware(
            ['order_inbound' => \Tozo\Security\Profile::fromConfig(
                'order_inbound',
                $inboundConfig,
                $container->make(\Tozo\Security\Contracts\KeyProviderInterface::class)
            )],
            $container->make(\Tozo\Security\Contracts\SignerInterface::class),
            $container->make(\Tozo\Security\Contracts\AuthenticatorInterface::class),
            new \Tozo\Security\Scope\ScopeAuthorizer()
        );
        
        $response = $middleware->handle($request, function () {
            $this->fail('Business must not be reached');
        });
        
        // 对外只暴露安全类别码，不泄露内部原因。
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(['error' => 'invalid_signature'], json_decode($response->getContent(), true));
    }
    
    public function test_replayed_request_is_rejected_on_second_submission()
    {
        [$client, $container] = $this->client();
        
        $outboundConfig                                   = $this->outboundProfile();
        $outboundConfig['security_mode']                  = 'signed_request';
        $outboundConfig['token']['attach_enabled']        = false;
        $outboundConfig['encryption']['enabled']          = false;
        $outboundConfig['response_integrity']['required'] = false;
        
        $client->setProfile(\Tozo\Security\Profile::fromConfig(
            'svc_to_order',
            $outboundConfig,
            $container->make(\Tozo\Security\Contracts\KeyProviderInterface::class)
        ));
        
        $client->post('https://order-api.internal/api/orders', ['sku' => 'A-1']);
        
        $buildRequest = function () {
            $request = Request::create(
                'https://order-api.internal/api/orders',
                'POST',
                [],
                [],
                [],
                [],
                $this->captured['body']
            );
            foreach ($this->captured['headers'] as $name => $value) {
                $request->headers->set($name, $value);
            }
            
            return $request;
        };
        
        $inboundConfig                            = $this->inboundProfile();
        $inboundConfig['security_mode']           = 'signed_request';
        $inboundConfig['token']['verify_enabled'] = false;
        
        $profiles = ['order_inbound' => \Tozo\Security\Profile::fromConfig(
            'order_inbound',
            $inboundConfig,
            $container->make(\Tozo\Security\Contracts\KeyProviderInterface::class)
        )];
        
        $middleware = new InboundAuthenticatorMiddleware(
            $profiles,
            $container->make(\Tozo\Security\Contracts\SignerInterface::class),
            $container->make(\Tozo\Security\Contracts\AuthenticatorInterface::class),
            new \Tozo\Security\Scope\ScopeAuthorizer()
        );
        
        // 第一次提交通过（共享 ArrayStore 防重放状态）。
        $first = $middleware->handle($buildRequest(), function () {
            return new Response('ok', 200);
        });
        $this->assertSame(200, $first->getStatusCode());
        
        // 完全相同的原始请求第二次提交必须拒绝。
        $second = $middleware->handle($buildRequest(), function () {
            $this->fail('Replay must not reach business');
        });
        $this->assertSame(401, $second->getStatusCode());
    }
}
