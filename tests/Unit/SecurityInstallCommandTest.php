<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 05:50
 */

/**
 * 安装命令测试
 *
 * 文件功能：
 * - 固化 tozo:security:install 按 peers 声明推导并生成密钥文件这一核心承诺
 * - 覆盖三条不可退让的行为：命名与展开器一致、绝不覆盖既有密钥、dry-run 零副作用
 * - 验证生成的密钥可直接用于 HMAC 签名，而不只是"看起来像密钥"
 *
 * 为什么必须固化：
 * - key_id 由 ConfigNormalizer 按四元组推导，接入方无法手写；命令若命名错一个字符，
 *   表现是运行期 KeyNotFoundException 而非启动期配置报错，排查成本极高
 * - 覆盖既有密钥会立即切断该关系两端的通信，且无法从备份恢复对端那一半，
 *   因此"跳过已存在"必须是被测试锁死的行为，不能依赖实现者的自觉
 *
 * 安全边界：
 * - 全部用例在系统临时目录内操作，不触碰任何真实部署的密钥目录
 * - 每个用例用独立随机子目录，避免用例间互相污染
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;
use Illuminate\Container\Container;
use Symfony\Component\Console\Input\ArrayInput;
use Illuminate\Config\Repository as ConfigRepository;
use Symfony\Component\Console\Output\BufferedOutput;
use Tozo\Security\Laravel\Command\SecurityInstallCommand;

class SecurityInstallCommandTest extends TestCase
{
    /**
     * 本用例使用的临时密钥目录绝对路径。
     *
     * 每个用例在 setUp 中生成独立随机目录并在 tearDown 中递归删除，
     * 使"是否覆盖既有密钥"这类依赖磁盘状态的断言不会被上一个用例的残留干扰。
     *
     * @var string
     */
    private $keyDir;

    /**
     * 在独立临时密钥目录内执行用例主体，结束后无条件清理。
     *
     * 使用范围：每个涉及磁盘写入的用例都必须用它包裹自己的主体。
     * 适用场景：本项目约定不使用 setUp/tearDown——那两个方法的父类签名带
     *           返回类型声明，而 ApiStyleTest 禁止项目内出现返回类型声明。
     *           用闭包包裹可在同样保证清理的前提下满足该约定。
     *
     * 函数逻辑：
     * 1. 以随机名创建 0700 目录，使用例之间不会互相看到残留密钥。
     * 2. finally 中清理：断言失败抛异常时也必须删掉临时密钥，不留在测试机上。
     *
     * @param callable $body 用例主体｜无参闭包，可通过 $this->keyDir 取当前目录。示例：function () { ... }
     * @return void 无返回值。
     */
    private function withKeyDir(callable $body)
    {
        $this->keyDir = sys_get_temp_dir() . '/tozo-install-' . bin2hex(random_bytes(6));
        mkdir($this->keyDir, 0700, true);

        try {
            $body();
        } finally {
            // 必须用 scandir 而非 glob('*')：命令会写入 .gitignore，
            // 而 glob 默认不匹配点文件，漏删会导致 rmdir 报 Directory not empty。
            foreach (array_diff(scandir($this->keyDir) ?: [], ['.', '..']) as $entry) {
                $path = $this->keyDir . '/' . $entry;

                if (is_file($path)) {
                    unlink($path);
                }
            }

            if (is_dir($this->keyDir)) {
                rmdir($this->keyDir);
            }
        }
    }

    /**
     * 三个对端必须生成 12 个密钥文件，且命名与展开器推导结果逐字符一致。
     */
    public function test_three_peers_produce_twelve_keys_matching_derived_names()
    {
        $this->withKeyDir(function () {
            $output = $this->runInstall($this->compactConfig());

            $files = array_map('basename', glob($this->keyDir . '/*.key') ?: []);

            // 3 个对端 × 2 个方向的关系 × 请求/响应两种用途 = 12 个。
            $this->assertCount(12, $files);

            // 抽查四条：本系统发出与对端发来，两个方向的请求与响应密钥都必须存在。
            foreach ([
                         'testing_tozo-app-api_to_pos-api_request.key',
                         'testing_tozo-app-api_to_pos-api_response.key',
                         'testing_pos-api_to_tozo-app-api_request.key',
                         'testing_pos-api_to_tozo-app-api_response.key',
                     ] as $expected) {
                $this->assertContains($expected, $files);
            }

            $this->assertStringContainsString('新生成 12 个', $output);
        });
    }

    /**
     * 生成的密钥必须是 32 字符且字符集安全，否则 AesGcmCipher 会在运行期拒绝。
     */
    public function test_generated_keys_are_usable_material()
    {
        $this->withKeyDir(function () {
            $this->runInstall($this->compactConfig());

            $contents = [];

            foreach (glob($this->keyDir . '/*.key') ?: [] as $file) {
                $content = (string)file_get_contents($file);

                // AesGcmCipher 校验的是 strlen 而非解码后长度，必须恰好 32。
                $this->assertSame(32, strlen($content), basename($file));

                // 不含换行与空白：FileKeyProvider 会 rtrim 行尾，含空白会让两端内容不一致。
                $this->assertSame(1, preg_match('/^[A-Za-z0-9\-_]{32}$/', $content), basename($file));

                // 能真正完成一次 HMAC 计算才算可用。
                $this->assertNotSame('', hash_hmac('sha256', 'payload', $content, true));

                $contents[] = $content;
            }

            // 不同用途必须是不同密钥，否则请求签名可被当作响应签名重放。
            $this->assertCount(12, array_unique($contents), '12 个密钥内容必须互不相同');
        });
    }

    /**
     * 已存在的密钥绝不能被覆盖：覆盖会立即切断该关系两端的通信。
     */
    public function test_existing_keys_are_never_overwritten()
    {
        $this->withKeyDir(function () {
            $config = $this->compactConfig();

            $this->runInstall($config);

            $sample   = $this->keyDir . '/testing_tozo-app-api_to_pos-api_request.key';
            $original = (string)file_get_contents($sample);

            $output = $this->runInstall($config);

            $this->assertSame($original, (string)file_get_contents($sample), '既有密钥内容被改写');
            $this->assertStringContainsString('新生成 0 个', $output);
            $this->assertStringContainsString('跳过 12 个', $output);
        });
    }

    /**
     * 新增对端时只补齐缺失的密钥，既有关系的密钥保持原样。
     */
    public function test_adding_a_peer_only_creates_the_missing_keys()
    {
        $this->withKeyDir(function () {
            $config          = $this->compactConfig();
            $config['peers'] = ['pos-api' => 'https://pos-api.example.com'];

            $this->runInstall($config);

            // 单个对端产生 4 个密钥：两个方向各有请求与响应。
            $this->assertCount(4, glob($this->keyDir . '/*.key') ?: []);

            $sample   = $this->keyDir . '/testing_tozo-app-api_to_pos-api_request.key';
            $original = (string)file_get_contents($sample);

            $config['peers']['pmc-api'] = 'https://pmc-api.example.com';

            $output = $this->runInstall($config);

            $this->assertCount(8, glob($this->keyDir . '/*.key') ?: []);
            $this->assertSame($original, (string)file_get_contents($sample), '新增对端不应影响既有密钥');
            $this->assertStringContainsString('新生成 4 个', $output);
            $this->assertStringContainsString('跳过 4 个', $output);
        });
    }

    /**
     * 必须写入 .gitignore：密钥目录在项目树内，一次 git add . 就可能提交生产密钥。
     */
    public function test_gitignore_protects_the_key_directory()
    {
        $this->withKeyDir(function () {
            $this->runInstall($this->compactConfig());

            $path = $this->keyDir . '/.gitignore';

            $this->assertFileExists($path);

            $content = (string)file_get_contents($path);

            $this->assertStringContainsString('*.key', $content);
            $this->assertStringContainsString('!.gitignore', $content);
        });
    }

    /**
     * 已有 .gitignore 时不得覆盖：宿主可能已写入自己的忽略规则。
     */
    public function test_existing_gitignore_is_left_untouched()
    {
        $this->withKeyDir(function () {
            $path = $this->keyDir . '/.gitignore';
            file_put_contents($path, "# 宿主自有规则\n*.pem\n");

            $this->runInstall($this->compactConfig());

            $this->assertSame("# 宿主自有规则\n*.pem\n", (string)file_get_contents($path));
        });
    }

    /**
     * dry-run 必须零副作用：只列清单，不创建任何文件。
     */
    public function test_dry_run_has_no_side_effects()
    {
        $this->withKeyDir(function () {
            $output = $this->runInstall($this->compactConfig(), true);

            $this->assertSame([], glob($this->keyDir . '/*.key') ?: []);
            $this->assertFileDoesNotExist($this->keyDir . '/.gitignore');

            // 清单内容仍须完整列出，否则无法用于与对端核对命名。
            $this->assertStringContainsString('dry-run', $output);
            $this->assertStringContainsString('testing_tozo-app-api_to_pos-api_request.key', $output);
        });
    }

    /**
     * 必须输出入站 Profile 名：这些名字由展开器推导，接入方无法手写。
     */
    public function test_output_lists_inbound_profile_names_for_route_binding()
    {
        $this->withKeyDir(function () {
            $output = $this->runInstall($this->compactConfig());

            foreach ([
                         'tozo_app_api_inbound_from_app_admin_api',
                         'tozo_app_api_inbound_from_pmc_api',
                         'tozo_app_api_inbound_from_pos_api',
                     ] as $profile) {
                $this->assertStringContainsString($profile, $output);
            }

            // 出站方向不应要求记 Profile 名——业务用 to('对端标识') 选路。
            $this->assertStringNotContainsString('tozo_app_api_outbound_to_pos_api', $output);
        });
    }

    /**
     * 必须提示密钥交换要求：这是整套流程唯一无法自动化、且最容易出错的一步。
     */
    public function test_output_warns_about_peer_key_exchange()
    {
        $this->withKeyDir(function () {
            $output = $this->runInstall($this->compactConfig());

            $this->assertStringContainsString('内容完全相同', $output);
            $this->assertStringContainsString('两端各自生成', $output);
        });
    }

    /**
     * service 未填时必须失败并指明要改的位置，不能生成任何文件。
     */
    public function test_missing_service_fails_with_actionable_message()
    {
        $this->withKeyDir(function () {
            $config            = $this->compactConfig();
            $config['service'] = '';

            $output = $this->runInstall($config, false, 1);

            $this->assertSame([], glob($this->keyDir . '/*.key') ?: []);
            $this->assertStringContainsString('service 尚未填写', $output);
        });
    }

    /**
     * peers 为空时必须失败：没有对端就没有任何信任关系需要密钥。
     */
    public function test_empty_peers_fails_with_actionable_message()
    {
        $this->withKeyDir(function () {
            $config          = $this->compactConfig();
            $config['peers'] = [];

            $output = $this->runInstall($config, false, 1);

            $this->assertSame([], glob($this->keyDir . '/*.key') ?: []);
            $this->assertStringContainsString('peers 为空', $output);
        });
    }

    /**
     * 命令必须已注册到 Provider，否则 artisan 里不可见，
     * 而配置文件与示例 README 都指引接入方执行它。
     */
    public function test_command_is_registered_by_provider()
    {
        $source = (string)file_get_contents(
            dirname(__DIR__, 2) . '/src/Tozo/Security/ServiceProvider.php'
        );

        $this->assertStringContainsString('SecurityInstallCommand::class', $source);
    }

    /**
     * 命令名与两个选项必须与文档指引一致。
     */
    public function test_command_signature_matches_documented_usage()
    {
        $command = new SecurityInstallCommand();
        $command->setLaravel(new Container());

        $this->assertSame('tozo:security:install', $command->getName());

        $definition = $command->getDefinition();

        foreach (['dir', 'dry-run'] as $option) {
            $this->assertTrue($definition->hasOption($option), "缺少 --{$option} 选项");
        }
    }

    /**
     * 构造本测试使用的极简配置。
     *
     * 使用范围：各用例的配置基线。
     * 适用场景：四系统互调的真实形态——本系统加另外三个对端。
     *
     * 函数逻辑：
     * 1. 固定 environment 为 testing，使推导出的 key_id 前缀可被断言。
     *
     * @return array 极简配置树。示例：["service"=>"tozo-app-api","environment"=>"testing","peers"=>[...]]
     */
    private function compactConfig()
    {
        return [
            'service'     => 'tozo-app-api',
            'environment' => 'testing',
            'peers'       => [
                'app-admin-api' => 'https://app-admin-api.example.com',
                'pmc-api'       => 'https://pmc-api.example.com',
                'pos-api'       => 'https://pos-api.example.com',
            ],
        ];
    }

    /**
     * 在临时目录内执行一次安装命令并返回其全部输出。
     *
     * 使用范围：本测试类各用例复用。
     * 适用场景：命令依赖 config 与输出通道，用最小容器 + BufferedOutput 驱动，
     *           不需要启动完整 Laravel 应用。
     *
     * 函数逻辑：
     * 1. 用 ConfigRepository 提供 tozo_security 配置树。
     * 2. 始终显式传 --dir 指向临时目录，避免触碰真实 storage 路径。
     * 3. 断言退出码符合预期后返回输出文本供内容断言。
     *
     * @param array $config 极简配置树｜写入容器的 tozo_security 值。示例：["service"=>"pos-api"]
     * @param bool $dryRun 是否只列清单｜true 时不写任何文件。示例：false
     * @param int $expectedExit 期望退出码｜0 成功，1 配置不完整。示例：0
     * @return string 命令的全部标准输出。示例："本系统：tozo-app-api（环境 testing）..."
     */
    private function runInstall(array $config, bool $dryRun = false, int $expectedExit = 0)
    {
        $container = new Container();
        $container->instance('config', new ConfigRepository(['tozo_security' => $config]));

        $command = new SecurityInstallCommand();
        $command->setLaravel($container);

        $parameters = ['--dir' => $this->keyDir];
        if ($dryRun) {
            $parameters['--dry-run'] = true;
        }

        $buffer = new BufferedOutput();
        $exit   = $command->run(new ArrayInput($parameters), $buffer);

        // fetch() 会清空缓冲区，只能取一次；先存下来再用于断言与返回。
        $output = $buffer->fetch();

        $this->assertSame($expectedExit, $exit, $output);

        return $output;
    }
}
