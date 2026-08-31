<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 四系统实际配置包验收测试
 *
 * 文件功能：
 * - 逐个加载示例包中 testing/production 的 8 套极简配置并展开体检
 * - 验证展开出的 24 个 Profile、12 条有向关系及请求/响应密钥两端一致
 * - 验证路由绑定的 Profile 名与 README 清单均回指同一份展开结果
 * - 校验示例包内 32 个 PHP 文件语法有效（接入方会直接复制它们）
 *
 * 为什么改为校验展开结果：
 * - v0.0.9 配置文件只声明 service/environment/peers 三个键，Profile 由 SDK 推导；
 *   直接断言配置文件内容已无意义，必须先经 ConfigNormalizer 展开再体检
 * - 两端密钥一致性是配置精简能否成立的前提：两个系统各自独立展开，
 *   推导规则若不对称，表现为验签失败而非配置报错
 *
 * 安全边界：
 * - 只读取配置声明与推导出的 key_id 标识，不读取任何真实部署密钥
 * - 配置文件语法通过不等同于真实 Laravel、Redis、TLS 或 staging 互调已通过
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;
use Tozo\Security\Support\ConfigChecker;
use Tozo\Security\Support\ConfigNormalizer;

class FourSystemConfigurationTest extends TestCase
{
    /**
     * v0.0.9 示例包目录名。当前维护版本，新接入一律使用该包。
     */
    private const CURRENT_PACKAGE = '四系统实际配置文件-v0.0.9';

    /**
     * 系统目录名到服务标识的映射。目录名与服务标识同名，
     * 服务标识才是参与签名绑定的权威值。
     */
    private const SERVICE_BY_DIRECTORY = [
        'tozoApp-api'   => 'tozo-app-api',
        'app-admin-api' => 'app-admin-api',
        'pmc-api'       => 'pmc-api',
        'pos-api'       => 'pos-api',
    ];

    /**
     * 8 套配置必须都是极简形态，且展开后各含本系统的 6 个启用 Profile。
     */
    public function test_all_eight_configs_are_compact_and_pass_checker()
    {
        $configs = $this->loadConfigs();

        $this->assertCount(8, $configs);

        foreach ($configs as $file => $config) {
            // 精简后的配置必须只有三个键，出现第四个键说明示例包退回了冗余形态。
            $this->assertSame(
                ['service', 'environment', 'peers'],
                array_keys($config),
                $file . '：示例配置应只声明 service/environment/peers'
            );

            $this->assertTrue(ConfigNormalizer::isCompact($config), $file);
            $this->assertCount(3, $config['peers'], $file . '：应声明另外三个系统');

            $result = (new ConfigChecker())->check(ConfigNormalizer::normalize($config));

            $this->assertTrue($result['ok'], $file . ': ' . implode('; ', $result['errors']));
            $this->assertSame(6, $result['profiles'], $file);
        }
    }

    /**
     * 配置文件不得再依赖 .env：需求要求全部配置写在 tozo_security.php 内。
     */
    public function test_no_config_reads_environment_variables()
    {
        foreach (array_keys($this->loadConfigs()) as $file) {
            $source = (string)file_get_contents($file);

            $this->assertStringNotContainsString('env(', $source, $file);
            $this->assertStringNotContainsString('getenv', $source, $file);
        }

        // 整个示例包不得再出现 .env 或 tozo_services.php。
        $root = dirname(__DIR__, 2) . '/docs/' . self::CURRENT_PACKAGE;

        $this->assertSame([], glob($root . '/*/*/.env') ?: [], '示例包不应再包含 .env');
        $this->assertSame(
            [],
            glob($root . '/*/*/config/tozo_services.php') ?: [],
            '示例包不应再包含 tozo_services.php'
        );
    }

    /**
     * 跨系统配对 12 条有向关系，确保 request/response 密钥在两端完全一致且用途分离。
     */
    public function test_all_directional_relations_have_matching_counterparts()
    {
        $relations = [];
        $keySets   = ['testing' => [], 'production' => []];

        foreach ($this->loadConfigs() as $file => $config) {
            $environment = basename(dirname($file, 2));
            $system      = basename(dirname($file, 3));
            $normalized  = ConfigNormalizer::normalize($config);

            foreach ($normalized['profiles'] as $name => $profile) {
                $relation    = $profile['client_id'] . '>' . $profile['target_service'];
                $requestKey  = $profile['signature']['key_id'];
                $responseKey = $profile['response_integrity']['signature']['key_id'];

                // 请求与响应必须用途分离，否则同一签名可被跨方向重放。
                $this->assertNotSame($requestKey, $responseKey, $file . ':' . $name);

                $keySets[$environment][$requestKey]  = true;
                $keySets[$environment][$responseKey] = true;

                $relations[$environment][$relation][$profile['direction']][] = [
                    'system'   => $system,
                    'request'  => $requestKey,
                    'response' => $responseKey,
                ];
            }
        }

        foreach ($relations as $environment => $items) {
            foreach ($items as $relation => $directions) {
                $label = $environment . ':' . $relation;

                $this->assertCount(1, $directions['outbound'] ?? [], $label);
                $this->assertCount(1, $directions['inbound'] ?? [], $label);

                $outbound = $directions['outbound'][0];
                $inbound  = $directions['inbound'][0];

                $this->assertSame($outbound['request'], $inbound['request'], $label . ' 请求密钥两端不一致');
                $this->assertSame($outbound['response'], $inbound['response'], $label . ' 响应密钥两端不一致');
                $this->assertNotSame($outbound['system'], $inbound['system'], $label . ' 不是跨系统关系');
            }
        }

        $this->assertCount(12, $relations['testing']);
        $this->assertCount(12, $relations['production']);

        // 两个环境不得共用任何密钥：测试环境泄漏不应危及生产。
        $this->assertSame([], array_intersect_key($keySets['testing'], $keySets['production']));
    }

    /**
     * Profile 名称必须从当前服务视角完整表达通信方向与对端服务，
     * 且与目录名声明的系统身份一致。
     */
    public function test_profile_names_follow_current_service_viewpoint()
    {
        foreach ($this->loadConfigs() as $file => $config) {
            $directory = basename(dirname($file, 3));

            $this->assertArrayHasKey($directory, self::SERVICE_BY_DIRECTORY, $file);

            // 目录名与配置声明的 service 必须对得上，否则示例包放错了位置。
            $this->assertSame(self::SERVICE_BY_DIRECTORY[$directory], $config['service'], $file);

            $current = $config['service'];

            foreach (ConfigNormalizer::normalize($config)['profiles'] as $name => $profile) {
                if ($profile['direction'] === 'outbound') {
                    $this->assertSame($current, $profile['client_id'], $file . ':' . $name);
                    $expected = ConfigNormalizer::profileName($current, 'outbound_to', $profile['target_service']);
                } else {
                    $this->assertSame($current, $profile['target_service'], $file . ':' . $name);
                    $expected = ConfigNormalizer::profileName($current, 'inbound_from', $profile['client_id']);
                }

                $this->assertSame($expected, $name, $file . ':' . $name);
            }
        }
    }

    /**
     * 路由绑定的 Profile 名与 README 列出的清单必须都回指展开结果，
     * 否则接入方照抄示例会得到「Profile 不存在」的启动失败。
     */
    public function test_route_and_readme_references_resolve_to_expanded_profiles()
    {
        foreach ($this->loadConfigs() as $file => $config) {
            $environmentRoot = dirname($file, 2);
            $profiles        = ConfigNormalizer::normalize($config)['profiles'];

            $routeSource = (string)file_get_contents($environmentRoot . '/routes/tozo_security.php');

            preg_match_all("/->defaults\\('tozo_profile', '([^']+)'\\)/", $routeSource, $routeMatches);

            // 三个对端各一条入站路由，且不得重复绑定同一 Profile。
            $this->assertCount(3, $routeMatches[1], $file . ':routes');
            $this->assertCount(count($routeMatches[1]), array_unique($routeMatches[1]), $file . ':routes');

            foreach ($routeMatches[1] as $routeProfile) {
                $this->assertArrayHasKey($routeProfile, $profiles, $file . ':route:' . $routeProfile);
                $this->assertSame('inbound', $profiles[$routeProfile]['direction'], $file . ':route:' . $routeProfile);
            }

            // 路由必须覆盖全部入站 Profile：漏挂一条即该对端无法回调本系统。
            $inbound = array_keys(array_filter($profiles, static function (array $profile) {
                return $profile['direction'] === 'inbound';
            }));

            $this->assertEqualsCanonicalizing($inbound, $routeMatches[1], $file . ':routes');

            $readmeSource = (string)file_get_contents($environmentRoot . '/README.md');

            preg_match_all('/^- `([^`]+)`：/m', $readmeSource, $readmeMatches);

            $this->assertCount(6, $readmeMatches[1], $file . ':README');
            $this->assertEqualsCanonicalizing(array_keys($profiles), $readmeMatches[1], $file . ':README');
        }
    }

    /**
     * 示例包不得再包含手写 HTTP Client 样板：
     * 按目标服务选路已由 SDK 的 to() 提供，重新引入样板会退回 v0.0.8 的维护负担。
     */
    public function test_examples_use_sdk_routing_instead_of_hand_written_client()
    {
        $root = dirname(__DIR__, 2) . '/docs/' . self::CURRENT_PACKAGE;

        $this->assertSame(
            [],
            glob($root . '/*/*/app/Services/TozoSecurityClient.php') ?: [],
            '不应再需要手写 TozoSecurityClient'
        );

        $controllers = glob($root . '/*/*/app/Http/Controllers/Internal/TozoSecurityController.php') ?: [];

        $this->assertCount(8, $controllers);

        foreach ($controllers as $file) {
            $source = (string)file_get_contents($file);

            // 出站范例必须演示 to() 选路。
            $this->assertStringContainsString("->to('", $source, $file);

            // 入站范例只能读取中间件写入的已验证身份，不得从原始输入取身份字段。
            $this->assertStringContainsString("attributes->get('tozo_security_profile')", $source, $file);
            $this->assertStringNotContainsString("input('client_id')", $source, $file);
        }
    }

    /**
     * 示例包的全部 PHP 文件都必须通过当前 PHP 二进制的语法检查。
     *
     * 为什么连示例文件也要 lint：这些文件是给接入方直接复制的，
     * 语法错误会让对方在自己项目里才发现问题，且第一反应通常是怀疑自己改错了。
     */
    public function test_all_example_php_files_pass_current_php_lint()
    {
        $root  = dirname(__DIR__, 2) . '/docs/' . self::CURRENT_PACKAGE;
        $files = [];

        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root)) as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        // 4 系统 × 2 环境 × 每套 4 个 PHP 文件 = 32。
        // 数量断言防止生成器少写文件后测试仍然「通过」。
        $this->assertCount(32, $files);

        foreach ($files as $file) {
            $output   = [];
            $exitCode = 1;
            exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file), $output, $exitCode);

            $this->assertSame(0, $exitCode, $file . ': ' . implode(' ', $output));
        }
    }

    /**
     * 加载 v0.0.9 示例包中四个系统的 testing/production 配置。
     *
     * 使用范围：本类各用例的数据来源。
     * 适用场景：8 套配置均为极简形态，调用方按需自行展开。
     *
     * @return array<string,array> 配置文件绝对路径到配置数组的映射。示例：["...\/config\/tozo_security.php"=>["service"=>"pos-api"]]
     */
    private function loadConfigs()
    {
        $root    = dirname(__DIR__, 2) . '/docs/' . self::CURRENT_PACKAGE;
        $files   = glob($root . '/*/*/config/tozo_security.php') ?: [];
        $configs = [];

        foreach ($files as $file) {
            $configs[$file] = include $file;
        }

        return $configs;
    }
}
