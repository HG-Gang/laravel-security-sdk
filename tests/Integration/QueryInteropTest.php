<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Query 互通端到端测试
 *
 * 文件功能：
 * - 用真实 HttpClient 签名 → 真实入站中间件验签的完整链路，
 *   验证带重复键、方括号键和特殊编码的 query 不会被误判为 invalid_signature
 * - 这是修复前必然失败的场景：调用端按原始字节签名，
 *   服务端若从 PHP 数组重建 query 会得到不同原文
 *
 * 安全边界：
 * - 用例只允许「合法请求通过、被篡改请求拒绝」两种结论，不接受降级放行
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
use Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware;

class QueryInteropTest extends TestCase
{
    /**
     * 传输桩捕获的出站请求，结构为 {method,url,headers,body}。
     * 本用例专查 query 规范化：断言的关键是 URL 中的 query 字节与签名原文
     * 使用的字节完全一致——两者若来自不同渲染路径，服务端按 QUERY_STRING 验签必然失败。
     * 因此这里捕获的必须是最终发送的 URL 原文，不能是重新拼装的结果。
     *
     * @var array
     */
    private $captured = [];
    
    /**
     * 各类 query 形态都必须能通过真实双端验签。
     *
     * @dataProvider queryProvider
     */
    public function test_signed_request_with_query_passes_inbound_verification(array $options, string $urlSuffix)
    {
        [$client, $container] = $this->client();
        
        $client->get('https://order-api.internal/api/orders' . $urlSuffix, $options);
        
        $request = $this->inboundRequestFrom($this->captured);
        
        $reached  = false;
        $response = $this->middleware($container)->handle($request, function () use (&$reached) {
            $reached = true;
            
            return new Response('{"ok":true}', 200);
        });
        
        $this->assertTrue(
            $reached,
            'query 形态导致验签失败，响应体：' . (string)$response->getContent()
        );
        $this->assertSame(200, $response->getStatusCode());
    }
    
    public function queryProvider()
    {
        return [
            'no query'                     => [[], ''],
            'simple options'               => [['query' => ['b' => 'two', 'a' => 'one']], ''],
            'repeated key in url'          => [[], '?tags=x&tags=y'],
            'repeated key list in options' => [['query' => ['tags' => ['x', 'y']]], ''],
            'bracketed key in options'     => [['query' => ['filter' => ['status' => 'open']]], ''],
            'url query plus options'       => [['query' => ['page' => '2']], '?tags=x&tags=y'],
            'space value'                  => [['query' => ['q' => 'hello world']], ''],
            'literal plus value'           => [['query' => ['q' => 'a+b']], ''],
            'utf8 value'                   => [['query' => ['q' => '中文']], ''],
            'empty value'                  => [['query' => ['flag' => '']], ''],
        ];
    }
    
    /**
     * 传输途中被改写 query 的请求必须验签失败（签名确实绑定了 query）。
     */
    public function test_query_tampering_is_rejected()
    {
        [$client, $container] = $this->client();
        
        $client->get('https://order-api.internal/api/orders', ['query' => ['tags' => ['x', 'y']]]);
        
        // 攻击者删掉一个重复键值后转发。
        $tampered        = $this->captured;
        $tampered['url'] = str_replace('tags=x&tags=y', 'tags=x', (string)$this->captured['url']);
        $this->assertNotSame($this->captured['url'], $tampered['url']);
        
        $response = $this->middleware($container)->handle(
            $this->inboundRequestFrom($tampered),
            function () {
                return new Response('{"ok":true}', 200);
            }
        );
        
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('{"error":"invalid_signature"}', (string)$response->getContent());
    }
    
    /**
     * 实际发送的 URL 必须就是签名覆盖的 query，不存在第二套渲染结果。
     */
    public function test_transport_url_matches_signed_query()
    {
        [$client] = $this->client();
        
        $client->get('https://order-api.internal/api/orders?tags=y', ['query' => ['page' => '2']]);
        
        $this->assertSame(
            'https://order-api.internal/api/orders?page=2&tags=y',
            $this->captured['url']
        );
    }
    
    /**
     * 构造共享同一容器（同密钥、同 ReplayStore）的出站客户端。
     *
     * 传输桩把请求写入 $this->captured，供用例在发起请求后读取实际发送的 URL 与 Header。
     *
     * @return array{0:TozoHttpClient,1:\Illuminate\Container\Container}
     */
    private function client()
    {
        $container      = $this->makeContainer();
        $this->captured = [];
        
        $client = new TozoHttpClient(
            $container->make(AuditSinkInterface::class),
            $container->make(SignerInterface::class),
            null,
            null,
            null,
            function (string $method, string $url, array $headers, string $body) {
                $this->captured = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];
                
                return ['status' => 200, 'headers' => [], 'body' => '{"ok":true}'];
            }
        );
        
        $client->setProfile(Profile::fromConfig(
            'svc_to_order',
            $this->signedOnlyOutbound(),
            $container->make(KeyProviderInterface::class)
        ));
        
        return [$client, $container];
    }
    
    /**
     * 用捕获到的出站请求重建等价入站 Request（含 QUERY_STRING）。
     */
    private function inboundRequestFrom(array $captured)
    {
        $request = Request::create(
            (string)$captured['url'],
            (string)$captured['method'],
            [],
            [],
            [],
            [],
            (string)$captured['body']
        );
        
        foreach ($captured['headers'] as $name => $value) {
            $request->headers->set($name, $value);
        }
        
        return $request;
    }
    
    private function middleware($container)
    {
        return new InboundAuthenticatorMiddleware(
            [
                'order_inbound' => Profile::fromConfig(
                    'order_inbound',
                    $this->signedOnlyInbound(),
                    $container->make(KeyProviderInterface::class)
                ),
            ],
            $container->make(SignerInterface::class),
            null,
            new ScopeAuthorizer()
        );
    }
    
    /**
     * 出站：仅签名（signed_request），排除 Token 与加密以聚焦 query 契约。
     */
    private function signedOnlyOutbound()
    {
        $config                            = $this->outboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['token']['attach_enabled'] = false;
        $config['encryption']['enabled']   = false;
        unset($config['response_integrity']);
        
        return $config;
    }
    
    /**
     * 入站：与出站配对的 signed_request 验证配置。
     */
    private function signedOnlyInbound()
    {
        $config                  = $this->inboundProfile();
        $config['security_mode'] = 'signed_request';
        unset($config['token']);
        
        return $config;
    }
}
