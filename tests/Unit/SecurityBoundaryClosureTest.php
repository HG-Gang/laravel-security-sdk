<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Payload;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Identity\Subject;
use Tozo\Security\Http\TozoHttpClient;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Scope\ScopeAuthorizer;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Signature\HmacSha256Signer;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Exceptions\ProtocolException;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Profile;
use Tozo\Security\Storage\LaravelCacheReplayStore;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Laravel\Middleware\OutboundSignerMiddleware;
use Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware;

/**
 * 跨模块安全边界回归测试。
 *
 * 文件功能：
 * - 固化协议 Header、Profile 方向、主体类型、出站 Content-Type 和传输结果契约。
 * - 防止单模块测试通过但模块连接处仍存在隐式默认或半实现状态。
 */
class SecurityBoundaryClosureTest extends TestCase
{
    public function test_inbound_request_rejects_missing_protocol_version_header()
    {
        $profile    = $this->signedInboundProfile('service');
        $middleware = $this->inboundMiddleware(['inbound' => $profile]);
        $request    = Request::create('/orders', 'GET');
        $request->headers->set('X-Tozo-Client-Id', $profile->getClientId());
        
        $response = $middleware->handle($request, function () {
            return new Response('business-reached', 200);
        });
        
        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame(['error' => 'invalid_request'], json_decode($response->getContent(), true));
    }
    
    private function signedInboundProfile(string $subjectType)
    {
        $config                                   = $this->inboundProfile();
        $config['security_mode']                  = 'signed_request';
        $config['subject_type']                   = $subjectType;
        $config['token']['verify_enabled']        = false;
        $config['token']['allowed_subject_types'] = [$subjectType];
        
        return Profile::fromConfig('inbound', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    private function inboundMiddleware(array $profiles)
    {
        return new InboundAuthenticatorMiddleware(
            $profiles,
            $this->createMock(SignerInterface::class),
            $this->createMock(AuthenticatorInterface::class),
            new ScopeAuthorizer()
        );
    }
    
    public function test_explicit_route_profile_must_be_inbound()
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'signed_request';
        $config['token']['attach_enabled']        = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $profile                                  = Profile::fromConfig('outbound', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $middleware = $this->inboundMiddleware(['outbound' => $profile]);
        $request    = Request::create('/orders', 'GET');
        $request->setRouteResolver(function () {
            return new class {
                public function parameter($name, $default = null)
                {
                    return $name === 'tozo_profile' ? 'outbound' : $default;
                }
            };
        });
        
        $response = $middleware->handle($request, function () {
            return new Response('business-reached', 200);
        });
        
        $this->assertSame(401, $response->getStatusCode());
        $this->assertNotSame('business-reached', $response->getContent());
    }
    
    public function test_signed_request_subject_type_follows_profile()
    {
        $profile    = $this->signedInboundProfile('partner');
        $middleware = $this->inboundMiddleware(['partner' => $profile]);
        $request    = Request::create('/orders', 'GET');
        $request->headers->set('X-Tozo-Client-Id', $profile->getClientId());
        $request->headers->set('X-Tozo-Protocol-Version', '1');
        
        $response = $middleware->handle($request, function (Request $verifiedRequest) {
            $subject = $verifiedRequest->attributes->get('tozo_security_subject');
            
            return new Response($subject->getSubjectType() . '|' . $subject->getSub(), 200);
        });
        
        $this->assertSame('partner|partner:product-center', $response->getContent());
    }
    
    public function test_explicit_route_profile_rejects_client_id_mismatch()
    {
        $container = $this->makeContainer();
        $keys      = $container->make(KeyProviderInterface::class);
        
        $outboundConfig                                   = $this->outboundProfile();
        $outboundConfig['security_mode']                  = 'signed_request';
        $outboundConfig['token']['attach_enabled']        = false;
        $outboundConfig['encryption']['enabled']          = false;
        $outboundConfig['response_integrity']['required'] = false;
        $outbound                                         = Profile::fromConfig('outbound', $outboundConfig, $keys);
        
        $inboundConfig                  = $this->inboundProfile();
        $inboundConfig['security_mode'] = 'signed_request';
        unset($inboundConfig['token']);
        $inbound = Profile::fromConfig('inbound', $inboundConfig, $keys);
        
        $signer = new HmacSha256Signer(
            $keys,
            new LaravelCacheReplayStore($container->make(\Illuminate\Contracts\Cache\Repository::class)),
            new \Tozo\Security\Clock\SystemClock()
        );
        $signed = $signer->sign(new Payload([
            'method'         => 'GET',
            'path'           => '/orders',
            'query'          => '',
            'content_type'   => 'application/json',
            'client_id'      => 'forged-client',
            'target_service' => 'order-api',
            'body'           => '',
        ]), $outbound);
        
        $request = Request::create('https://order-api.internal/orders', 'GET');
        $request->setRouteResolver(function () {
            return new class {
                public function parameter($name, $default = null)
                {
                    return $name === 'tozo_profile' ? 'inbound' : $default;
                }
            };
        });
        $request->headers->set('X-Tozo-Protocol-Version', '1');
        $request->headers->set('X-Tozo-Client-Id', 'forged-client');
        $request->headers->set('Content-Type', 'application/json');
        $request->headers->set('X-Tozo-Key-Id', $signed->get('key_id'));
        $request->headers->set('X-Tozo-Timestamp', (string)$signed->get('timestamp'));
        $request->headers->set('X-Tozo-Nonce', $signed->get('nonce'));
        $request->headers->set('X-Tozo-Signature', $signed->get('signature'));
        
        $reachedBusiness = false;
        $response        = (new \Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware(
            ['inbound' => $inbound],
            $signer,
            null,
            new ScopeAuthorizer()
        ))->handle($request, function () use (&$reachedBusiness) {
            $reachedBusiness = true;
            
            return new Response('business-reached', 200);
        });
        
        $this->assertFalse($reachedBusiness);
        $this->assertSame(401, $response->getStatusCode());
    }
    
    public function test_outbound_middleware_sets_content_type_used_by_signature()
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'signed_request';
        $config['token']['attach_enabled']        = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $profile                                  = Profile::fromConfig('outbound', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $signer = $this->createMock(SignerInterface::class);
        $signer->method('sign')->willReturnCallback(function (Payload $payload) {
            $payload->set('key_id', 'order-signing');
            $payload->set('timestamp', (string)time());
            $payload->set('nonce', str_repeat('a', 32));
            $payload->set('signature', 'proof');
            
            return $payload;
        });
        
        $middleware = new OutboundSignerMiddleware(['outbound' => $profile], 'outbound', $signer);
        $request    = Request::create('/orders', 'POST', [], [], [], [], '{"sku":"A-1"}');
        $request->headers->set('Content-Type', 'text/plain');
        
        $response = $middleware->handle($request, function (Request $signedRequest) {
            return new Response((string)$signedRequest->headers->get('Content-Type'), 200);
        });
        
        $this->assertSame('application/json', $response->getContent());
    }
    
    public function test_token_only_outbound_client_does_not_call_signature_service()
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'token_only';
        $config['signature']['enabled']           = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $profile                                  = Profile::fromConfig('token-only', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $transportCalls = 0;
        $client         = new TozoHttpClient(
            $this->createMock(AuditSinkInterface::class),
            null,
            null,
            null,
            $this->createMock(\Tozo\Security\Contracts\TokenIssuerInterface::class),
            function () use (&$transportCalls) {
                $transportCalls++;
                
                return ['status' => 200, 'headers' => [], 'body' => '{}'];
            }
        );
        $client->setProfile($profile);
        
        $response = $client->get('https://order-api.internal/orders');
        
        $this->assertSame(200, $response->getStatus());
        $this->assertSame(1, $transportCalls);
    }
    
    public function test_token_only_outbound_client_removes_caller_signature_headers()
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'token_only';
        $config['signature']['enabled']           = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $profile                                  = Profile::fromConfig('token-only', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $capturedHeaders = [];
        $client          = new TozoHttpClient(
            $this->createMock(AuditSinkInterface::class),
            null,
            null,
            null,
            $this->createMock(\Tozo\Security\Contracts\TokenIssuerInterface::class),
            function ($method, $url, $headers) use (&$capturedHeaders) {
                $capturedHeaders = $headers;
                
                return ['status' => 200, 'headers' => [], 'body' => '{}'];
            }
        );
        $client->setProfile($profile);
        $client->get('https://order-api.internal/orders', [
            'headers' => [
                'X-Tozo-Key-Id'    => 'stale',
                'X-Tozo-Timestamp' => 'stale',
                'X-Tozo-Nonce'     => 'stale',
                'X-Tozo-Signature' => 'stale',
            ],
        ]);
        
        $this->assertArrayNotHasKey('X-Tozo-Key-Id', $capturedHeaders);
        $this->assertArrayNotHasKey('X-Tozo-Timestamp', $capturedHeaders);
        $this->assertArrayNotHasKey('X-Tozo-Nonce', $capturedHeaders);
        $this->assertArrayNotHasKey('X-Tozo-Signature', $capturedHeaders);
    }
    
    public function test_http_options_are_forwarded_to_custom_transport()
    {
        $capturedOptions = null;
        $client          = $this->httpClient(function ($method, $url, $headers, $body, $options) use (&$capturedOptions) {
            $capturedOptions = $options;
            
            return ['status' => 200, 'headers' => [], 'body' => '{}'];
        });
        
        $client->get('https://order-api.internal/orders', [
            'http_options' => [
                'timeout'         => 12,
                'connect_timeout' => 4,
                'verify'          => true,
            ],
        ]);
        
        $this->assertSame([
            'timeout'         => 12,
            'connect_timeout' => 4,
            'verify'          => true,
        ], $capturedOptions);
    }
    
    private function httpClient(callable $transport)
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'signed_request';
        $config['token']['attach_enabled']        = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $profile                                  = Profile::fromConfig('outbound', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $signer = $this->createMock(SignerInterface::class);
        $signer->method('sign')->willReturnCallback(function (Payload $payload) {
            $payload->set('key_id', self::HMAC_KEY);
            $payload->set('timestamp', (string)time());
            $payload->set('nonce', str_repeat('b', 32));
            $payload->set('signature', 'proof');
            
            return $payload;
        });
        
        $audit  = $this->createMock(AuditSinkInterface::class);
        $client = new TozoHttpClient($audit, $signer, null, null, null, $transport);
        $client->setProfile($profile);
        
        return $client;
    }
    
    public function test_http_options_forward_only_supported_transport_keys()
    {
        $capturedOptions = null;
        $client          = $this->httpClient(function ($method, $url, $headers, $body, $options) use (&$capturedOptions) {
            $capturedOptions = $options;
            
            return ['status' => 200, 'headers' => [], 'body' => '{}'];
        });
        
        $client->get('https://order-api.internal/orders', [
            'http_options' => [
                'timeout'          => 12,
                'verify'           => true,
                'arbitrary_option' => 'must-not-cross-boundary',
            ],
        ]);
        
        $this->assertSame(['timeout' => 12, 'verify' => true], $capturedOptions);
    }
    
    public function test_token_only_outbound_middleware_does_not_emit_signature_headers()
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'token_only';
        $config['signature']['enabled']           = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $profile                                  = Profile::fromConfig('token-only', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $issuer = $this->createMock(\Tozo\Security\Contracts\TokenIssuerInterface::class);
        $issuer->expects($this->once())->method('issue')->with($profile)->willReturn('token-value');
        
        $middleware = new OutboundSignerMiddleware(
            ['token-only' => $profile],
            'token-only',
            null,
            null,
            $issuer
        );
        $request    = Request::create('/orders', 'GET');
        
        $response = $middleware->handle($request, function (Request $securedRequest) {
            $signatureHeaders = [
                $securedRequest->headers->has('X-Tozo-Key-Id'),
                $securedRequest->headers->has('X-Tozo-Timestamp'),
                $securedRequest->headers->has('X-Tozo-Nonce'),
                $securedRequest->headers->has('X-Tozo-Signature'),
            ];
            
            return new Response(json_encode([
                'authorization'     => $securedRequest->headers->get('Authorization'),
                'signature_headers' => $signatureHeaders,
            ]), 200);
        });
        
        $result = json_decode($response->getContent(), true);
        $this->assertSame('Bearer token-value', $result['authorization']);
        $this->assertSame([false, false, false, false], $result['signature_headers']);
    }
    
    public function test_token_only_outbound_middleware_removes_caller_signature_headers()
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'token_only';
        $config['signature']['enabled']           = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $profile                                  = Profile::fromConfig('token-only', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $issuer = $this->createMock(\Tozo\Security\Contracts\TokenIssuerInterface::class);
        $issuer->method('issue')->willReturn('token-value');
        $middleware = new OutboundSignerMiddleware(['token-only' => $profile], 'token-only', null, null, $issuer);
        $request    = Request::create('/orders', 'GET');
        $request->headers->set('X-Tozo-Key-Id', 'stale');
        $request->headers->set('X-Tozo-Timestamp', 'stale');
        $request->headers->set('X-Tozo-Nonce', 'stale');
        $request->headers->set('X-Tozo-Signature', 'stale');
        
        $response = $middleware->handle($request, function (Request $securedRequest) {
            return new Response(json_encode([
                'key'       => $securedRequest->headers->has('X-Tozo-Key-Id'),
                'timestamp' => $securedRequest->headers->has('X-Tozo-Timestamp'),
                'nonce'     => $securedRequest->headers->has('X-Tozo-Nonce'),
                'signature' => $securedRequest->headers->has('X-Tozo-Signature'),
            ]), 200);
        });
        
        $this->assertSame([
            'key'       => false,
            'timestamp' => false,
            'nonce'     => false,
            'signature' => false,
        ], json_decode($response->getContent(), true));
    }
    
    public function test_signed_request_inbound_does_not_require_authenticator()
    {
        $profile = $this->signedInboundProfile('service');
        $signer  = $this->createMock(SignerInterface::class);
        $signer->expects($this->once())->method('verify')->willReturn(true);
        
        $middleware = new InboundAuthenticatorMiddleware(
            ['signed' => $profile],
            $signer,
            null,
            new ScopeAuthorizer()
        );
        $request    = Request::create('/orders', 'GET');
        $request->headers->set('X-Tozo-Client-Id', $profile->getClientId());
        $request->headers->set('X-Tozo-Protocol-Version', '1');
        
        $response = $middleware->handle($request, function () {
            return new Response('business-reached', 200);
        });
        
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('business-reached', $response->getContent());
    }
    
    public function test_token_only_inbound_does_not_require_signer()
    {
        $config                         = $this->inboundProfile();
        $config['security_mode']        = 'token_only';
        $config['signature']['enabled'] = false;
        $config['authentication']       = [
            'driver' => 'hmac_bearer_sha256',
            'key_id' => self::HMAC_KEY,
        ];
        $profile                        = Profile::fromConfig('token-only', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->expects($this->once())->method('authenticate')->willReturn(new Subject([
            'sub'          => 'service:product-center',
            'client_id'    => 'product-center',
            'iss'          => 'hmac_bearer:' . self::HMAC_KEY,
            'aud'          => ['order-api'],
            'subject_type' => 'service',
            'scope'        => [],
        ]));
        
        $middleware = new InboundAuthenticatorMiddleware(
            ['token-only' => $profile],
            null,
            $authenticator,
            new ScopeAuthorizer()
        );
        $request    = Request::create('/orders', 'GET');
        $request->headers->set('X-Tozo-Client-Id', $profile->getClientId());
        $request->headers->set('X-Tozo-Protocol-Version', '1');
        
        $response = $middleware->handle($request, function () {
            return new Response('business-reached', 200);
        });
        
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('business-reached', $response->getContent());
    }
    
    public function test_outbound_hmac_bearer_profile_is_rejected_as_unsupported()
    {
        $config                            = $this->outboundProfile();
        $config['security_mode']           = 'token_only';
        $config['signature']['enabled']    = false;
        $config['authentication']          = [
            'driver' => 'hmac_bearer_sha256',
            'key_id' => self::HMAC_KEY,
        ];
        $config['token']['attach_enabled'] = false;
        $config['token']['issue_enabled']  = false;
        
        $this->expectException(ConfigurationException::class);
        Profile::fromConfig('unsupported-outbound-bearer', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_http_client_rejects_json_serialization_failure_before_transport()
    {
        $transportCalls = 0;
        $client         = $this->httpClient(function () use (&$transportCalls) {
            $transportCalls++;
            
            return ['status' => 200, 'headers' => [], 'body' => '{}'];
        });
        
        $this->expectException(ProtocolException::class);
        try {
            $client->post('https://order-api.internal/orders', ['invalid_utf8' => "\xB1\x31"]);
        } finally {
            $this->assertSame(0, $transportCalls);
        }
    }
    
    public function test_http_client_rejects_malformed_custom_transport_result()
    {
        $client = $this->httpClient(function () {
            return ['status' => 200];
        });
        
        $this->expectException(ProtocolException::class);
        $client->post('https://order-api.internal/orders', ['ok' => true]);
    }
    
    public function test_http_client_sends_the_same_query_that_it_signs()
    {
        $capturedUrl = null;
        $client      = $this->httpClient(function ($method, $url) use (&$capturedUrl) {
            $capturedUrl = $url;
            
            return ['status' => 200, 'headers' => [], 'body' => '{}'];
        });
        
        $client->get('https://order-api.internal/orders', [
            'query' => ['b' => 'two', 'a' => 'one'],
        ]);
        
        $this->assertSame('https://order-api.internal/orders?a=one&b=two', $capturedUrl);
    }
    
    public function test_http_client_merges_url_query_into_the_signed_query()
    {
        $capturedUrl = null;
        $client      = $this->httpClient(function ($method, $url) use (&$capturedUrl) {
            $capturedUrl = $url;
            
            return ['status' => 200, 'headers' => [], 'body' => '{}'];
        });
        
        $client->get('https://order-api.internal/orders?from=url&same=old', [
            'query' => ['same' => 'new', 'from_option' => 'yes'],
        ]);
        
        $this->assertSame(
            'https://order-api.internal/orders?from=url&from_option=yes&same=new',
            $capturedUrl
        );
    }
    
    public function test_http_client_preserves_array_query_between_signature_and_transport()
    {
        $capturedUrl                              = null;
        $signedQuery                              = null;
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'signed_request';
        $config['token']['attach_enabled']        = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $profile                                  = Profile::fromConfig('array-query', $config, new ArrayKeyProvider($this->defaultKeys()));
        
        $signer = $this->createMock(SignerInterface::class);
        $signer->method('sign')->willReturnCallback(function (Payload $payload) use (&$signedQuery) {
            $signedQuery = $payload->get('query');
            $payload->set('key_id', self::HMAC_KEY);
            $payload->set('timestamp', (string)time());
            $payload->set('nonce', str_repeat('c', 32));
            $payload->set('signature', 'proof');
            
            return $payload;
        });
        
        $client = new TozoHttpClient(
            $this->createMock(AuditSinkInterface::class),
            $signer,
            null,
            null,
            null,
            function ($method, $url) use (&$capturedUrl) {
                $capturedUrl = $url;
                
                return ['status' => 200, 'headers' => [], 'body' => '{}'];
            }
        );
        $client->setProfile($profile);
        $client->get('https://order-api.internal/orders?tag=one&tag=two', [
            'query' => ['filter' => ['open', 'paid']],
        ]);
        
        $this->assertSame(
            'https://order-api.internal/orders?filter=open&filter=paid&tag=one&tag=two',
            $capturedUrl
        );
        
        // 签名 query 必须是线上原始字节而不是 PHP 数组：数组形态会把重复键折叠成
        // 最后一个值，使调用端与服务端推导出不同的签名原文。
        $this->assertSame('filter=open&filter=paid&tag=one&tag=two', $signedQuery);
    }
}
