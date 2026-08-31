<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 全新安装可用性测试
 *
 * 文件功能：
 * - 站在下游项目视角固化"装上即可启动"这一发布承诺
 * - 用包内真实 config/tozo_security.php（而非测试夹具）驱动 Provider 全流程
 * - 覆盖模板 Profile 启用后的最小可用路径，确保不出现连环配置错误
 *
 * 为什么必须固化：
 * - 此前包内默认配置存在模式矩阵矛盾（security_mode 要求 Token 腿但默认关闭），
 *   下游 composer require + vendor:publish 后首次请求即 ConfigurationException；
 *   全部既有测试都用 tests/TestCase 的夹具配置，因此无法发现该问题
 *
 * 安全边界：
 * - 不因"让测试通过"而放宽任何校验：模板启用后仍必须满足全部安全必填项
 */

namespace Tozo\Security\Tests\Unit;

use Illuminate\Cache\ArrayStore;
use Tozo\Security\Tests\TestCase;
use Illuminate\Container\Container;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Contracts\HttpClientInterface;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository as ConfigRepository;
use Tozo\Security\ServiceProvider;

class FreshInstallTest extends TestCase
{
    /**
     * 包内默认配置必须能直接 register + boot，不得让宿主应用启动失败。
     */
    public function test_shipped_default_config_boots_without_any_change()
    {
        $provider = $this->providerFor($this->shippedConfig());
        
        $provider->register();
        $provider->boot();
        
        // 走到这里说明未抛异常；断言注册表存在且默认不启用任何 Profile。
        $this->assertTrue($provider->getContainerForTest()->bound('tozo_security.profiles'));
        $this->assertSame(
            [],
            $provider->getContainerForTest()->make('tozo_security.profiles'),
            '默认配置不应启用任何 Profile：模板引用的密钥尚未注入'
        );
    }
    
    /**
     * 构造带最小容器的 Provider。
     *
     * @param array $config tozo_security 配置树。
     * @param array $keys 额外注入的 key_id => 密钥内容。
     * @return ServiceProvider 可 register/boot 的 Provider 实例。
     */
    private function providerFor(array $config, array $keys = [])
    {
        $container = new Container();
        $container->instance('config', new ConfigRepository(['tozo_security' => $config]));
        $container->singleton(\Illuminate\Contracts\Cache\Repository::class, function () {
            return new CacheRepository(new ArrayStore());
        });
        $container->singleton(KeyProviderInterface::class, function () use ($keys) {
            return new ArrayKeyProvider($keys);
        });
        
        return new class($container) extends ServiceProvider {
            /**
             * 暴露容器供断言使用；生产代码无需该入口。
             *
             * @return \Illuminate\Container\Container 当前容器实例。
             */
            public function getContainerForTest()
            {
                return $this->app;
            }
        };
    }
    
    /**
     * 加载包内真实配置文件。
     *
     * @return array 配置数组。
     */
    private function shippedConfig()
    {
        // 直接 require 包内文件，确保测的是下游 vendor:publish 得到的那份内容。
        return require dirname(__DIR__, 2) . '/config/tozo_security.php';
    }
    
    /**
     * 只填 service 与 peers 就必须得到一对自洽的 Profile。
     * 这是配置精简后「三个键跑通互调」这一承诺的最小验证。
     */
    public function test_declaring_one_peer_yields_a_self_consistent_profile_pair()
    {
        $config                = $this->shippedConfig();
        $config['service']     = 'tozo-app-api';
        $config['environment'] = 'testing';
        $config['peers']       = ['app-admin-api' => 'https://app-admin-api.example.com'];

        $provider = $this->providerFor($config);
        $provider->register();
        $provider->boot();

        $profiles = $provider->getContainerForTest()->make('tozo_security.profiles');

        // 一个对端展开为出站与入站两个 Profile，命名保持当前服务视角。
        $this->assertCount(2, $profiles);
        $this->assertArrayHasKey('tozo_app_api_outbound_to_app_admin_api', $profiles);
        $this->assertArrayHasKey('tozo_app_api_inbound_from_app_admin_api', $profiles);

        $outbound = $profiles['tozo_app_api_outbound_to_app_admin_api'];
        $this->assertSame('signed_request', $outbound->getSecurityMode());
        $this->assertTrue($outbound->isSignatureEnabled());
        $this->assertSame('tozo-app-api', $outbound->getClientId());
        $this->assertSame('app-admin-api', $outbound->getTargetService());

        // 请求与响应必须使用不同用途的密钥，不得复用。
        $this->assertNotSame(
            $outbound->getSignatureKeyId(),
            $outbound->getResponseIntegrityConfig()['signature']['key_id'],
            '响应签名密钥不得复用请求签名密钥'
        );
    }

    /**
     * 声明 peers 后 HttpClient 必须能按目标服务名选路：
     * 调用方不需要记 Profile 名，也不需要配 default_profile。
     */
    public function test_declared_peers_are_routable_by_target_service_name()
    {
        $config                = $this->shippedConfig();
        $config['service']     = 'tozo-app-api';
        $config['environment'] = 'testing';
        $config['peers']       = ['pos-api' => 'https://pos-api.example.com'];

        $provider = $this->providerFor($config);
        $provider->register();
        $provider->boot();

        /** @var HttpClientInterface $client */
        $client = $provider->getContainerForTest()->make(HttpClientInterface::class);

        // 未声明 default_profile 时不做默认绑定，避免请求被签往意料之外的目标。
        $this->assertNull($client->getProfile());

        $routed = $client->to('pos-api');

        $this->assertNotNull($routed->getProfile());
        $this->assertSame('tozo_app_api_outbound_to_pos_api', $routed->getProfile()->getName());
        $this->assertTrue($routed->getProfile()->isOutbound());

        // 选路返回新实例，原实例不被污染。
        $this->assertNull($client->getProfile());
    }

    /**
     * 未声明的对端必须被明确拒绝，不能回退到任意 Profile。
     */
    public function test_routing_to_an_undeclared_peer_fails_loudly()
    {
        $config                = $this->shippedConfig();
        $config['service']     = 'tozo-app-api';
        $config['environment'] = 'testing';
        $config['peers']       = ['pos-api' => 'https://pos-api.example.com'];

        $provider = $this->providerFor($config);
        $provider->register();
        $provider->boot();

        /** @var HttpClientInterface $client */
        $client = $provider->getContainerForTest()->make(HttpClientInterface::class);

        $this->expectException(ConfigurationException::class);
        $client->to('pmc-api');
    }

    /**
     * 单条关系升级为 token_plus_request_signature 时，配置注释承诺的数组形态
     * 必须确实可用——不能出现"照注释改完仍然报错"的情况。
     */
    public function test_documented_per_relation_upgrade_actually_works()
    {
        $config                = $this->shippedConfig();
        $config['service']     = 'tozo-app-api';
        $config['environment'] = 'testing';
        $config['peers']       = [
            // 一条关系升级，另一条保持基线，验证两种声明形态可并存。
            'pos-api' => [
                'base_uri'      => 'https://pos-api.example.com',
                'security_mode' => 'token_plus_request_signature',
                'encryption'    => true,
            ],
            'pmc-api' => 'https://pmc-api.example.com',
        ];

        $provider = $this->providerFor($config);
        $provider->register();
        $provider->boot();

        $profiles = $provider->getContainerForTest()->make('tozo_security.profiles');

        $upgraded = $profiles['tozo_app_api_outbound_to_pos_api'];
        $this->assertSame('token_plus_request_signature', $upgraded->getSecurityMode());
        $this->assertTrue($upgraded->isTokenAttachEnabled());
        $this->assertTrue($upgraded->getEncryptionConfig()['enabled']);

        // 未升级的关系不受影响，仍是基线模式且不加密。
        $baseline = $profiles['tozo_app_api_outbound_to_pmc_api'];
        $this->assertSame('signed_request', $baseline->getSecurityMode());
        $this->assertFalse($baseline->isTokenAttachEnabled());
        $this->assertFalse($baseline->getEncryptionConfig()['enabled']);
    }
    
    /**
     * 三个中间件绑定必须在默认配置下即可解析，
     * 否则宿主在 Kernel 注册别名后才发现无法实例化。
     */
    public function test_middleware_bindings_are_resolvable_on_fresh_install()
    {
        $provider = $this->providerFor($this->shippedConfig());
        $provider->register();
        $provider->boot();
        
        $container = $provider->getContainerForTest();
        
        foreach (['tozo.middleware.inbound', 'tozo.middleware.outbound', 'tozo.middleware.response'] as $binding) {
            $this->assertTrue($container->bound($binding), "{$binding} 未绑定");
            $this->assertNotNull($container->make($binding), "{$binding} 无法解析");
        }
    }
    
    /**
     * 配置文件必须包含快速开始指引：下游看不到启用步骤就只能试错。
     */
    public function test_shipped_config_documents_the_enable_steps()
    {
        $source = (string)file_get_contents(dirname(__DIR__, 2) . '/config/tozo_security.php');
        
        $this->assertStringContainsString('快速开始', $source);
        $this->assertStringContainsString('tozo:security:install', $source);
        $this->assertStringContainsString('tozo:security:check-config', $source);

        // 需求要求彻底摆脱 .env：配置文件不得再出现 env() 调用或 TOZO_ 环境变量名。
        $this->assertStringNotContainsString('env(', $source);
        $this->assertStringNotContainsString('TOZO_SECURITY_', $source);
    }
}
