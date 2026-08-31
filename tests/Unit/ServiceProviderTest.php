<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Contracts\HttpClientInterface;
use Tozo\Security\Contracts\ReplayStoreInterface;
use Tozo\Security\Contracts\TokenIssuerInterface;
use Tozo\Security\Profile;
use Tozo\Security\Support\ConfigNormalizer;
use Tozo\Security\Contracts\AuthenticatorInterface;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Contracts\TokenVerifierInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Authentication\AuthenticatorRouter;
use Tozo\Security\Contracts\ResponseIntegrityInterface;
use Tozo\Security\Contracts\TokenRevocationStoreInterface;

class ServiceProviderTest extends TestCase
{
    public function test_feature_gated_bindings_are_registered()
    {
        $container = $this->makeContainer();
        
        foreach ([
                     SignerInterface::class,
                     PayloadCipherInterface::class,
                     ResponseIntegrityInterface::class,
                     TokenVerifierInterface::class,
                     AuthenticatorInterface::class,
                     ReplayStoreInterface::class,
                     HttpClientInterface::class,
                 ] as $abstract) {
            $this->assertTrue($container->bound($abstract), "Binding [{$abstract}] missing");
        }
    }
    
    public function test_http_client_resolves_when_encryption_and_response_integrity_are_unused()
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'signed_request';
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        $config['token']['attach_enabled']        = false;
        
        $container = $this->makeContainer([
            'features.encryption'         => false,
            'features.response_integrity' => false,
            'profiles.svc_to_order'       => $config,
        ]);
        
        $this->assertInstanceOf(HttpClientInterface::class, $container->make(HttpClientInterface::class));
    }
    
    public function test_token_only_outbound_bindings_resolve_without_signature_service()
    {
        $config                                   = $this->outboundProfile();
        $config['security_mode']                  = 'token_only';
        $config['signature']['enabled']           = false;
        $config['encryption']['enabled']          = false;
        $config['response_integrity']['required'] = false;
        
        $container = $this->makeContainer([
            'features.signature'             => false,
            'profiles.svc_to_order'          => $config,
            'profiles.order_inbound.enabled' => false,
        ]);
        
        $this->assertInstanceOf(HttpClientInterface::class, $container->make(HttpClientInterface::class));
        $this->assertInstanceOf(
            \Tozo\Security\Laravel\Middleware\OutboundSignerMiddleware::class,
            $container->make('tozo.middleware.outbound')
        );
    }
    
    public function test_signed_request_inbound_middleware_resolves_without_authenticator()
    {
        $config                            = $this->inboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['authentication']          = [];
        $config['token']['verify_enabled'] = false;
        
        $container = $this->makeContainer([
            'features.authentication'       => false,
            'profiles.svc_to_order.enabled' => false,
            'profiles.order_inbound'        => $config,
        ]);
        
        $this->assertInstanceOf(
            \Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware::class,
            $container->make('tozo.middleware.inbound')
        );
    }
    
    public function test_signed_request_inbound_middleware_resolves_without_scope_service_when_no_scope_is_required()
    {
        $config                            = $this->inboundProfile();
        $config['security_mode']           = 'signed_request';
        $config['authentication']          = [];
        $config['token']['verify_enabled'] = false;
        
        $container = $this->makeContainer([
            'features.authentication'       => false,
            'features.scope'                => false,
            'profiles.svc_to_order.enabled' => false,
            'profiles.order_inbound'        => $config,
        ]);
        
        $this->assertFalse($container->bound(\Tozo\Security\Contracts\ScopeAuthorizerInterface::class));
        $this->assertInstanceOf(
            \Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware::class,
            $container->make('tozo.middleware.inbound')
        );
    }
    
    public function test_hmac_bearer_inbound_middleware_resolves_without_signature_service()
    {
        $config                         = $this->inboundProfile();
        $config['security_mode']        = 'token_only';
        $config['signature']['enabled'] = false;
        $config['authentication']       = [
            'driver' => 'hmac_bearer_sha256',
            'key_id' => self::HMAC_KEY,
        ];
        
        $container = $this->makeContainer([
            'features.signature'            => false,
            'profiles.svc_to_order.enabled' => false,
            'profiles.order_inbound'        => $config,
        ]);
        
        $this->assertInstanceOf(
            \Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware::class,
            $container->make('tozo.middleware.inbound')
        );
    }
    
    public function test_authenticator_is_not_registered_for_outbound_only_profiles()
    {
        $container = $this->makeContainer([
            'profiles.order_inbound.enabled' => false,
            'features.token_verifier'        => false,
        ]);
        
        $this->assertFalse($container->bound(AuthenticatorInterface::class));
    }
    
    /**
     * 关闭吊销与审计功能时不得残留对应接口绑定。
     *
     * @return void 两个功能接口均未注册。
     */
    public function test_disabled_storage_features_do_not_register_bindings()
    {
        $container = $this->makeContainer([
            'features.token_revocation' => false,
            'features.audit'            => false,
            'features.http_client'      => false,
        ]);
        
        $this->assertFalse($container->bound(TokenRevocationStoreInterface::class));
        $this->assertFalse($container->bound(AuditSinkInterface::class));
        $this->assertFalse($container->bound(HttpClientInterface::class));
    }
    
    public function test_boot_rejects_outbound_profile_when_audit_feature_is_disabled()
    {
        $container = $this->makeContainer(['features.audit' => false]);
        $provider  = new \Tozo\Security\ServiceProvider($container);
        $provider->register();
        
        $this->expectException(ConfigurationException::class);
        $provider->boot();
    }
    
    public function test_boot_rejects_outbound_profile_when_http_client_feature_is_disabled()
    {
        $container = $this->makeContainer(['features.http_client' => false]);
        $provider  = new \Tozo\Security\ServiceProvider($container);
        $provider->register();
        
        $this->expectException(ConfigurationException::class);
        $provider->boot();
    }
    
    public function test_boot_rejects_inbound_scope_usage_when_scope_feature_is_disabled()
    {
        $container = $this->makeContainer(['features.scope' => false]);
        $provider  = new \Tozo\Security\ServiceProvider($container);
        $provider->register();
        
        $this->expectException(ConfigurationException::class);
        $provider->boot();
    }
    
    public function test_replay_store_is_not_registered_without_signature_or_hmac_bearer()
    {
        $outbound                            = $this->outboundProfile();
        $outbound['security_mode']           = 'token_only';
        $outbound['signature']['enabled']    = false;
        $outbound['token']['attach_enabled'] = true;
        
        $inbound                            = $this->inboundProfile();
        $inbound['security_mode']           = 'token_only';
        $inbound['signature']['enabled']    = false;
        $inbound['token']['verify_enabled'] = true;
        
        $container = $this->makeContainer([
            'features.signature'     => false,
            'profiles.svc_to_order'  => $outbound,
            'profiles.order_inbound' => $inbound,
        ]);
        
        $this->assertFalse($container->bound(ReplayStoreInterface::class));
        $this->assertFalse($container->bound(TokenRevocationStoreInterface::class));
    }
    
    public function test_conflicting_outbound_audit_drivers_are_rejected()
    {
        $second                   = $this->outboundProfile();
        $second['client_id']      = 'product-center-2';
        $second['target_service'] = 'billing-api';
        $second['audit']          = ['driver' => 'log'];
        
        $this->expectException(ConfigurationException::class);
        $this->makeContainer(['profiles.billing_outbound' => $second]);
    }
    
    /**
     * HttpClient 功能开启但没有启用出站 Profile 时不应注册客户端。
     *
     * @return void HttpClient 接口保持不可解析。
     */
    public function test_http_client_is_not_registered_without_enabled_outbound_profile()
    {
        $container = $this->makeContainer([
            'profiles.svc_to_order.enabled'  => false,
            'profiles.order_inbound.enabled' => false,
        ]);
        
        $this->assertFalse($container->bound(HttpClientInterface::class));
        $this->assertFalse($container->bound('tozo_security'));
    }
    
    public function test_authenticator_binding_supports_mixed_profile_drivers()
    {
        $hmacConfig                         = $this->inboundProfile();
        $hmacConfig['security_mode']        = 'token_only';
        $hmacConfig['signature']['enabled'] = false;
        $hmacConfig['authentication']       = [
            'driver' => 'hmac_bearer_sha256',
            'key_id' => self::HMAC_KEY,
        ];
        
        $container = $this->makeContainer([
            'profiles.hmac_inbound' => $hmacConfig,
        ]);
        
        $this->assertInstanceOf(
            AuthenticatorRouter::class,
            $container->make(AuthenticatorInterface::class)
        );
    }
    
    public function test_token_issuer_is_not_bound_when_feature_disabled()
    {
        $container = $this->makeContainer([
            'features.token_issuer' => false,
        ]);
        
        $this->assertFalse($container->bound(TokenIssuerInterface::class));
    }
    
    public function test_token_issuer_binds_only_when_feature_enabled_and_profile_uses_it()
    {
        $config                            = $this->outboundProfile();
        $config['token']['attach_enabled'] = true;
        
        $container = $this->makeContainer([
            'features.token_issuer' => true,
            'profiles.svc_to_order' => $config,
        ]);
        
        $this->assertTrue($container->bound(TokenIssuerInterface::class));
        
        // 默认安装（feature 关闭）即使 Profile 误配 attach 也不注册。
        $strict = $this->makeContainer([
            'features.token_issuer' => false,
            'profiles.svc_to_order' => $config,
        ]);
        $this->assertFalse($strict->bound(TokenIssuerInterface::class));
    }
    
    public function test_boot_fails_when_profile_uses_disabled_feature()
    {
        $container = $this->makeContainer([
            'features.signature' => false, // Profile 引用了签名但功能关闭
        ]);
        
        $provider = new \Tozo\Security\ServiceProvider($container);
        $provider->register();
        
        $this->expectException(ConfigurationException::class);
        $provider->boot();
    }
    
    public function test_boot_fails_when_default_profile_missing()
    {
        $container = $this->makeContainer([
            'default_profile' => 'not-exists',
        ]);
        
        $provider = new \Tozo\Security\ServiceProvider($container);
        $provider->register();
        
        $this->expectException(ConfigurationException::class);
        $provider->boot();
    }
    
    public function test_profile_registry_returns_validated_profile_objects()
    {
        $container = $this->makeContainer();
        
        /** @var array<string,Profile> $profiles */
        $profiles = $container->make('tozo_security.profiles');
        
        $this->assertArrayHasKey('svc_to_order', $profiles);
        $this->assertArrayHasKey('order_inbound', $profiles);
        $this->assertInstanceOf(Profile::class, $profiles['svc_to_order']);
        $this->assertSame('product-center', $profiles['order_inbound']->getClientId());
    }
    
    public function test_shipped_config_file_matches_v002_contract()
    {
        $config = include dirname(__DIR__, 2) . '/config/tozo_security.php';

        // 配置精简后包内只声明身份三要素，其余全部由展开器推导。
        $this->assertArrayHasKey('service', $config);
        $this->assertArrayHasKey('environment', $config);
        $this->assertArrayHasKey('peers', $config);
        $this->assertSame([], $config['peers'], '包内默认不声明对端，装上即可启动');

        // 密钥不得写入配置文件：任何键名不得包含 secret 字样。
        array_walk_recursive($config, function ($value, $key) {
            $this->assertStringNotContainsString('secret', strtolower((string)$key));
        });

        // 展开后仍须守住协议版本与「默认不签发」这两条设计约束（设计 §13）。
        $normalized = ConfigNormalizer::normalize(array_merge($config, [
            'service' => 'tozo-app-api',
            'peers'   => ['pos-api' => 'https://pos-api.example.com'],
        ]));

        $this->assertSame('1', $normalized['protocol_version']);
        $this->assertFalse($normalized['features']['token_issuer']);
        $this->assertArrayHasKey('key_providers', $normalized);
    }
}
