<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 03:20
 */

/**
 * 配置展开器测试
 *
 * 文件功能：
 * - 固化极简配置（service + environment + peers）展开为内部完整形态的全部推导规则
 * - 以四系统两两互调为真实场景，验证 12 条有向关系在两端推导出完全一致的密钥标识
 * - 覆盖展开器的全部拒绝路径：环境缺失、对端与自身同名、根地址缺失、安全模式非法
 *
 * 为什么必须固化对称性：
 * - 同一条 A→B 关系由两个系统各自的配置文件独立展开，两端推导结果必须逐字节相同；
 *   一旦推导规则出现方向不对称，表现是签名验证失败而非配置报错，排查成本极高
 * - 请求与响应必须使用不同用途的密钥，否则同一份签名可被跨方向重放
 *
 * 安全边界：
 * - 只验证 key_id 标识的推导结果，不生成也不读取任何真实密钥
 * - 展开结果仍须通过 Profile 全量校验，本测试不替代 ProfileValidationTest
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;
use Tozo\Security\Support\ConfigNormalizer;
use Tozo\Security\Exceptions\ConfigurationException;

class ConfigNormalizerTest extends TestCase
{
    /**
     * 四系统服务标识全集。与 docs 示例包一致，顺序固定以保证用例可复现。
     */
    private const SERVICES = ['tozo-app-api', 'app-admin-api', 'pmc-api', 'pos-api'];

    /**
     * 已是完整形态的配置必须原样返回，保证旧配置继续可用。
     */
    public function test_non_compact_configuration_passes_through_unchanged()
    {
        $full = [
            'default_profile' => 'svc_to_order',
            'environment'     => 'testing',
            'profiles'        => ['svc_to_order' => $this->outboundProfile()],
        ];

        $this->assertFalse(ConfigNormalizer::isCompact($full));
        $this->assertSame($full, ConfigNormalizer::normalize($full));
    }

    /**
     * 只有同时具备非空 service 与数组 peers 才算极简形态。
     * 包内默认配置 service 为空串，必须被判为非极简，否则全新安装会因缺 environment 而启动失败。
     */
    public function test_compact_detection_requires_both_service_and_peers()
    {
        $this->assertTrue(ConfigNormalizer::isCompact([
            'service' => 'pos-api',
            'peers'   => [],
        ]));

        // 包内默认状态：service 留空表示尚未接入。
        $this->assertFalse(ConfigNormalizer::isCompact([
            'service' => '',
            'peers'   => [],
        ]));

        $this->assertFalse(ConfigNormalizer::isCompact(['service' => 'pos-api']));
        $this->assertFalse(ConfigNormalizer::isCompact(['peers' => []]));
        $this->assertFalse(ConfigNormalizer::isCompact([
            'service' => 'pos-api',
            'peers'   => 'not-an-array',
        ]));
    }

    /**
     * 单个对端必须展开为一对方向相反的 Profile，且五个真变量按方向正确镜像。
     */
    public function test_one_peer_expands_into_a_mirrored_profile_pair()
    {
        $config = ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => ['pos-api' => 'https://pos-api.example.com'],
        ]);

        $this->assertCount(2, $config['profiles']);

        $outbound = $config['profiles']['tozo_app_api_outbound_to_pos_api'];
        $inbound  = $config['profiles']['tozo_app_api_inbound_from_pos_api'];

        // 出站：本服务是调用方。
        $this->assertSame('outbound', $outbound['direction']);
        $this->assertSame('tozo-app-api', $outbound['client_id']);
        $this->assertSame('pos-api', $outbound['target_service']);

        // 入站：对端是调用方，本服务是接收方。
        $this->assertSame('inbound', $inbound['direction']);
        $this->assertSame('pos-api', $inbound['client_id']);
        $this->assertSame('tozo-app-api', $inbound['target_service']);

        // subject_id 恒等于 client_id，不是独立变量。
        $this->assertSame($outbound['client_id'], $outbound['subject_id']);
        $this->assertSame($inbound['client_id'], $inbound['subject_id']);

        // 两个方向描述的是不同的有向关系，因此密钥不同。
        $this->assertNotSame($outbound['signature']['key_id'], $inbound['signature']['key_id']);
    }

    /**
     * 请求与响应必须使用不同用途的密钥。
     * 复用同一密钥会让请求签名可被当作响应签名重放，方向绑定失效。
     */
    public function test_request_and_response_use_separate_key_purposes()
    {
        $config = ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => ['pmc-api' => 'https://pmc-api.example.com'],
        ]);

        foreach ($config['profiles'] as $name => $profile) {
            $request  = $profile['signature']['key_id'];
            $response = $profile['response_integrity']['signature']['key_id'];

            $this->assertNotSame($request, $response, $name);
            $this->assertStringEndsWith('_request', $request, $name);
            $this->assertStringEndsWith('_response', $response, $name);
        }
    }

    /**
     * 四系统各自独立展开后，12 条有向关系必须在两端推导出完全一致的密钥标识。
     *
     * 这是配置精简方案能否成立的关键前提：两端不再手写密钥标识，
     * 而是各自从「我是谁 + 跟谁通信 + 什么环境」推导。若推导规则不对称，
     * 表现为签名验证失败而非配置报错，因此必须在单测层面锁死。
     */
    public function test_four_systems_derive_symmetric_keys_for_every_relation()
    {
        $relations = [];

        // 每个系统只知道自己的身份与对端名单，独立展开自己的配置。
        foreach (self::SERVICES as $service) {
            $config = ConfigNormalizer::normalize([
                'service'     => $service,
                'environment' => 'production',
                'peers'       => $this->peersExcluding($service),
            ]);

            // 三个对端 × 两个方向 = 6 个 Profile。
            $this->assertCount(6, $config['profiles'], $service);

            foreach ($config['profiles'] as $name => $profile) {
                // 以有向关系（调用方→接收方）为键聚合两端的推导结果。
                $key = $profile['client_id'] . '>' . $profile['target_service'];

                $relations[$key][$profile['direction']] = [
                    'system'   => $service,
                    'name'     => $name,
                    'request'  => $profile['signature']['key_id'],
                    'response' => $profile['response_integrity']['signature']['key_id'],
                ];
            }
        }

        // 4 个系统两两互调共 12 条有向关系（4×3）。
        $this->assertCount(12, $relations);

        foreach ($relations as $key => $ends) {
            // 每条关系必须恰好被两端各描述一次：调用方的 outbound 与接收方的 inbound。
            $this->assertArrayHasKey('outbound', $ends, $key);
            $this->assertArrayHasKey('inbound', $ends, $key);

            $out = $ends['outbound'];
            $in  = $ends['inbound'];

            $this->assertSame($out['request'], $in['request'], $key . ' 请求密钥两端不一致');
            $this->assertSame($out['response'], $in['response'], $key . ' 响应密钥两端不一致');

            // 同一条关系必须跨两个不同系统，否则说明展开出了自调用关系。
            $this->assertNotSame($out['system'], $in['system'], $key . ' 不是跨系统关系');
        }
    }

    /**
     * 全网密钥总量必须是 24 个，单系统只持有与自己相关的 12 个。
     * 这条断言防止推导规则退化为「所有系统共用一把密钥」这类看似能跑通的错误。
     */
    public function test_key_material_is_scoped_to_each_relation()
    {
        $networkKeys = [];
        $ownKeys     = [];

        foreach (self::SERVICES as $service) {
            $config = ConfigNormalizer::normalize([
                'service'     => $service,
                'environment' => 'production',
                'peers'       => $this->peersExcluding($service),
            ]);

            foreach ($config['profiles'] as $profile) {
                $request  = $profile['signature']['key_id'];
                $response = $profile['response_integrity']['signature']['key_id'];

                $networkKeys[$request]  = true;
                $networkKeys[$response] = true;

                if ($service === 'tozo-app-api') {
                    $ownKeys[$request]  = true;
                    $ownKeys[$response] = true;
                }
            }
        }

        // 12 条有向关系 × 请求/响应两种用途 = 24 个。
        $this->assertCount(24, $networkKeys);

        // 单系统 3 个对端 × 2 个方向 × 2 种用途 = 12 个。
        $this->assertCount(12, $ownKeys);
    }

    /**
     * 环境标识必须进入密钥命名空间，使 testing 与 production 不共用任何密钥。
     * 否则测试环境泄漏的密钥可直接用于伪造生产请求。
     */
    public function test_environments_share_no_key_material()
    {
        $keysByEnvironment = [];

        foreach (['testing', 'production'] as $environment) {
            foreach (self::SERVICES as $service) {
                $config = ConfigNormalizer::normalize([
                    'service'     => $service,
                    'environment' => $environment,
                    'peers'       => $this->peersExcluding($service),
                ]);

                foreach ($config['profiles'] as $profile) {
                    $keysByEnvironment[$environment][$profile['signature']['key_id']]                     = true;
                    $keysByEnvironment[$environment][$profile['response_integrity']['signature']['key_id']] = true;
                }
            }
        }

        $this->assertSame(
            [],
            array_intersect_key($keysByEnvironment['testing'], $keysByEnvironment['production']),
            'testing 与 production 不得共用任何密钥'
        );
    }

    /**
     * features 必须由 Profile 实际引用推导，且默认不开启 Token 签发。
     * 基线关系只用请求签名与响应完整性，不应连带装配 Token 与 Scope 基础设施。
     */
    public function test_features_are_derived_from_actual_profile_usage()
    {
        $config = ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => ['pos-api' => 'https://pos-api.example.com'],
        ]);

        $features = $config['features'];

        // 基线模式实际引用的三项能力。
        $this->assertTrue($features['signature']);
        $this->assertTrue($features['response_integrity']);
        $this->assertTrue($features['http_client']);
        $this->assertTrue($features['audit']);

        // 未被引用的能力一律关闭，避免无意加载私钥或吊销存储（设计 §13）。
        $this->assertFalse($features['token_issuer']);
        $this->assertFalse($features['token_verifier']);
        $this->assertFalse($features['token_revocation']);
        $this->assertFalse($features['authentication']);
        $this->assertFalse($features['encryption']);
        $this->assertFalse($features['scope']);
    }

    /**
     * 单条关系升级为 token_plus_request_signature 时，Token 腿必须按方向装配：
     * 出站附加、入站验证，且两侧都不签发。
     */
    public function test_per_relation_upgrade_wires_token_legs_by_direction()
    {
        $config = ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => [
                'pos-api' => [
                    'base_uri'      => 'https://pos-api.example.com',
                    'security_mode' => 'token_plus_request_signature',
                    'encryption'    => true,
                ],
            ],
        ]);

        $outbound = $config['profiles']['tozo_app_api_outbound_to_pos_api'];
        $inbound  = $config['profiles']['tozo_app_api_inbound_from_pos_api'];

        // 出站只附加，不验证。
        $this->assertTrue($outbound['token']['attach_enabled']);
        $this->assertFalse($outbound['token']['verify_enabled']);

        // 入站只验证，不附加，并绑定期望的调用方身份。
        $this->assertTrue($inbound['token']['verify_enabled']);
        $this->assertFalse($inbound['token']['attach_enabled']);
        $this->assertSame('pos-api', $inbound['token']['expected_client_id']);
        $this->assertSame('jwt', $inbound['authentication']['driver']);

        // 两侧都不签发 Token：签发能力只属于授权系统。
        $this->assertFalse($outbound['token']['issue_enabled']);
        $this->assertFalse($inbound['token']['issue_enabled']);

        // 开启加密后才引用加密密钥，避免体检探测一个无需存在的密钥。
        $this->assertTrue($outbound['encryption']['enabled']);
        $this->assertArrayHasKey('key_id', $outbound['encryption']);

        // features 随之开启对应能力。
        $this->assertTrue($config['features']['encryption']);
        $this->assertTrue($config['features']['token_issuer']);
        $this->assertTrue($config['features']['token_verifier']);
    }

    /**
     * 不加密的关系不得引用加密密钥，否则体检会要求部署一个用不到的密钥文件。
     */
    public function test_baseline_relation_references_no_encryption_key()
    {
        $config = ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => ['pos-api' => 'https://pos-api.example.com'],
        ]);

        foreach ($config['profiles'] as $name => $profile) {
            $this->assertFalse($profile['encryption']['enabled'], $name);
            $this->assertArrayNotHasKey('key_id', $profile['encryption'], $name);
        }
    }

    /**
     * environment 是密钥命名空间的组成部分，缺失时必须启动即失败，
     * 不能用空串代替——那会让 testing 与 production 推导出同一批密钥标识。
     */
    public function test_missing_environment_is_rejected()
    {
        $this->expectException(ConfigurationException::class);

        ConfigNormalizer::normalize([
            'service' => 'tozo-app-api',
            'peers'   => ['pos-api' => 'https://pos-api.example.com'],
        ]);
    }

    /**
     * 对端与本服务同名会展开出自调用关系，必须拒绝。
     */
    public function test_peer_equal_to_local_service_is_rejected()
    {
        $this->expectException(ConfigurationException::class);

        ConfigNormalizer::normalize([
            'service'     => 'pos-api',
            'environment' => 'production',
            'peers'       => ['pos-api' => 'https://pos-api.example.com'],
        ]);
    }

    /**
     * 根地址缺失时必须拒绝：没有它无法按目标服务选路，
     * 而静默跳过会让调用方在运行期才发现该对端不可达。
     */
    public function test_peer_without_base_uri_is_rejected()
    {
        $this->expectException(ConfigurationException::class);

        ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => ['pos-api' => ['security_mode' => 'signed_request']],
        ]);
    }

    /**
     * 安全模式必须命中白名单，拼写错误不得静默退化为基线模式。
     */
    public function test_unknown_security_mode_is_rejected()
    {
        $this->expectException(ConfigurationException::class);

        ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => [
                'pos-api' => [
                    'base_uri'      => 'https://pos-api.example.com',
                    'security_mode' => 'signed_reqeust',
                ],
            ],
        ]);
    }

    /**
     * 传输与日志参数应有内置默认值，同时保留显式覆盖能力，
     * 使 tozo_services.php 删除后不丢任何可调项。
     */
    public function test_transport_defaults_are_supplied_and_overridable()
    {
        $defaults = ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => ['pos-api' => 'https://pos-api.example.com'],
        ]);

        $this->assertSame(ConfigNormalizer::HTTP_TIMEOUT, $defaults['http']['timeout']);
        $this->assertSame(ConfigNormalizer::HTTP_CONNECT_TIMEOUT, $defaults['http']['connect_timeout']);
        $this->assertSame(ConfigNormalizer::TLS_MIN_VERSION, $defaults['http']['min_version']);
        $this->assertTrue($defaults['http']['verify'], 'TLS 证书校验默认必须开启');

        $overridden = ConfigNormalizer::normalize([
            'service'     => 'tozo-app-api',
            'environment' => 'production',
            'peers'       => ['pos-api' => 'https://pos-api.example.com'],
            'http'        => ['timeout' => 30],
        ]);

        $this->assertSame(30, $overridden['http']['timeout']);

        // 未覆盖项仍取内置默认，不因出现 http 段而整段丢失。
        $this->assertSame(ConfigNormalizer::HTTP_CONNECT_TIMEOUT, $overridden['http']['connect_timeout']);
    }

    /**
     * Profile 名称必须把服务标识规范化为 snake_case，
     * 使连字符与驼峰两种命名风格产出同一个可预测的键名。
     */
    public function test_profile_names_normalize_service_identifiers()
    {
        $this->assertSame(
            'tozo_app_api_outbound_to_app_admin_api',
            ConfigNormalizer::profileName('tozo-app-api', 'outbound_to', 'app-admin-api')
        );

        // 驼峰形态的目录名（tozoApp-api）与连字符形态推导出同一片段。
        $this->assertSame(
            'tozo_app_api_inbound_from_pos_api',
            ConfigNormalizer::profileName('tozoApp-api', 'inbound_from', 'pos-api')
        );
    }

    /**
     * 推导出的 key_id 必须落在 ConfigChecker 的字符白名单内，
     * 否则体检阶段会把自己生成的标识判为非法格式。
     */
    public function test_derived_key_ids_satisfy_the_checker_pattern()
    {
        foreach (self::SERVICES as $service) {
            $config = ConfigNormalizer::normalize([
                'service'     => $service,
                'environment' => 'production',
                'peers'       => $this->peersExcluding($service),
            ]);

            foreach ($config['profiles'] as $name => $profile) {
                foreach ([
                             $profile['signature']['key_id'],
                             $profile['response_integrity']['signature']['key_id'],
                         ] as $keyId) {
                    $this->assertSame(
                        1,
                        preg_match(\Tozo\Security\Support\ConfigChecker::KEY_ID_PATTERN, $keyId),
                        $name . ' 推导出的 key_id 不合法：' . $keyId
                    );
                }
            }
        }
    }

    /**
     * 构造「除自己以外的三个对端」名单。
     *
     * 使用范围：四系统对称性与密钥范围用例内部调用。
     * 适用场景：模拟每个系统只声明另外三个系统的真实配置形态。
     *
     * 函数逻辑：
     * 1. 遍历服务全集，跳过自身，其余按约定域名生成根地址。
     *
     * @param string $service 本服务标识｜需排除的自身名称。示例："pos-api"
     * @return array 对端名单｜服务标识=>根地址。示例：["pmc-api"=>"https://pmc-api.example.com"]
     */
    private function peersExcluding(string $service)
    {
        $peers = [];

        foreach (self::SERVICES as $peer) {
            if ($peer === $service) {
                continue;
            }

            $peers[$peer] = 'https://' . $peer . '.example.com';
        }

        return $peers;
    }
}
