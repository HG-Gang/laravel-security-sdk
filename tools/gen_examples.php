<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 04:10
 */

/**
 * 四系统示例配置包生成器
 *
 * 文件功能：
 * - 生成 docs/四系统实际配置文件-v0.0.9/ 下 4 个系统 × 2 个环境的完整接入示例
 * - 每套只含 4 个文件：极简配置、Kernel 中间件别名、入站路由、示例控制器
 * - --check 模式只比对不写盘，供 CI 确认示例包未与生成规则脱节
 *
 * 为什么用生成器而不是手写：
 * - 8 套内容差异只有服务标识、环境与域名三项，手写 45 个文件必然出现不一致；
 *   配置精简前的手写版本就残留了重复数组键与不可达代码
 * - 12 条有向关系的 Profile 名必须两端严格对称，由同一份推导规则产出才能保证
 *
 * 安全边界：
 * - 只生成 key_id 标识与 Profile 名，不生成也不写入任何密钥内容
 * - 生成文件为无 BOM 的 UTF-8 且使用 LF 行尾：BOM 会破坏 Laravel 的 header() 输出，
 *   CRLF 会破坏签名规范化串的跨平台字节一致性
 */

require __DIR__ . '/../vendor/autoload.php';

use Tozo\Security\Support\ConfigNormalizer;

/**
 * 示例包目录名。带版本号是为了让接入方一眼看出自己复制的是哪一版；
 * 升级 SDK 时若示例结构变化，新目录与旧目录可短期并存以便对照。
 */
const EXAMPLE_DIR = '四系统实际配置文件-v0.0.9';

/**
 * 生成文件头部标识块使用的创建日期，格式 YYYY/MM/DD。
 * 固定值保证重复生成结果一致，否则 --check 会因日期变化而误报差异。
 */
const HEADER_DATE = '2026/08/30';

/**
 * 生成文件头部标识块使用的创建时间，24 小时制。
 */
const HEADER_TIME = '04:10';

/**
 * 四系统清单：目录名 => [服务标识, 中文名]。
 * 目录名与服务标识同名，便于接入方对号入座；
 * 服务标识才是参与签名原文绑定的权威值，两者不可混用。
 */
const SYSTEMS = [
	'tozoApp-api'   => ['tozo-app-api', 'App 端 API'],
	'app-admin-api' => ['app-admin-api', '后台管理 API'],
	'pmc-api'       => ['pmc-api', '生产管理 API'],
	'pos-api'       => ['pos-api', 'POS API'],
];

/**
 * 各环境的服务根地址。此处为占位域名（RFC 2606 保留域名，不会解析到真实主机），
 * 接入时替换为各系统实际部署地址；两个环境使用不同域名，避免测试流量误打生产。
 */
const BASE_URIS = [
	'production' => [
		'tozo-app-api'  => 'https://app-api.example.com',
		'app-admin-api' => 'https://app-admin-api.example.com',
		'pmc-api'       => 'https://api-pms.example.com',
		'pos-api'       => 'https://pos-api.example.com',
	],
	'testing'    => [
		'tozo-app-api'  => 'https://app-api.example.test',
		'app-admin-api' => 'https://app-admin-api.example.test',
		'pmc-api'       => 'https://pmc-api.example.test',
		'pos-api'       => 'https://pos-api.example.test',
	],
];

/**
 * 生成文件头部标识块。
 *
 * 使用范围：本生成器每个文件构建函数的第一段输出。
 * 适用场景：headers-check 要求每个文件都有该块，日期格式固定为 YYYY/MM/DD。
 *
 * @return string 标识块文本｜含首尾换行。示例："/**\n * Created by PhpStorm...\n *\/\n"
 */
function header_block()
{
	return "/**\n"
		. " * Created by PhpStorm.\n"
		. " * Project name Tozo-security-sdk-php.\n"
		. " * User: Huang Gang\n"
		. ' * Date: ' . HEADER_DATE . "\n"
		. ' * Time: ' . HEADER_TIME . "\n"
		. " */\n";
}

/**
 * 构建单套极简配置文件内容。
 *
 * 使用范围：每个系统 × 环境组合调用一次。
 * 适用场景：替代配置精简前的 548 行配置与独立的 tozo_services.php、.env 三份文件。
 *
 * 函数逻辑：
 * 1. 取除自身以外的三个对端与对应环境的根地址。
 * 2. 逐键写出中文说明，满足「每个配置键都要有中文注释」的项目规范。
 *
 * @param string $service 本系统服务标识｜签名绑定用权威值。示例："tozo-app-api"
 * @param string $label 本系统中文名｜仅用于文件级注释。示例："App 端 API"
 * @param string $environment 环境标识｜production 或 testing。示例："production"
 * @return string 配置文件完整内容。示例："<?php\n...return [...];\n"
 */
function build_config(string $service, string $label, string $environment)
{
	$peerLines = '';
	foreach (BASE_URIS[$environment] as $peer => $baseUri) {
		if ($peer === $service) {
			continue;
		}
		
		$peerLabel = '';
		foreach (SYSTEMS as $meta) {
			if ($meta[0] === $peer) {
				$peerLabel = $meta[1];
				break;
			}
		}
		
		$peerLines .= '        // ' . $peer . ' string｜' . $peerLabel . " 的 HTTPS 根地址；声明即与该系统建立双向信任。\n";
		$peerLines .= '        ' . str_pad("'" . $peer . "'", 17) . '=> ' . "'" . $baseUri . "',\n";
	}
	
	return "<?php\n\n"
		. header_block()
		. "\n"
		. "/**\n"
		. ' * ' . $label . '（' . $service . '）' . environment_label($environment) . "安全配置\n"
		. " *\n"
		. " * 文件功能：\n"
		. " * - 本系统接入 Tozo Security SDK 的唯一配置文件，复制到 config/tozo_security.php 即可\n"
		. ' * - 三个键展开为 6 个 Profile（3 个对端 × 出站/入站）与 12 个用途密钥标识' . "\n"
		. " *\n"
		. " * 安全边界：\n"
		. " * - 本文件不含任何密钥，可随代码提交与审计\n"
		. ' * - 密钥由 php artisan tozo:security:install 生成到 storage/app/tozo/keys/，不经过 .env' . "\n"
		. " */\n"
		. "\n"
		. "return [\n"
		. '    // service string｜本系统身份；参与签名原文与 AAD 绑定，是全部推导的起点。' . "\n"
		. "    'service'     => '" . $service . "',\n"
		. "\n"
		. '    // environment string｜运行环境；作为密钥命名空间前缀，两个环境不共用任何密钥。' . "\n"
		. "    'environment' => '" . $environment . "',\n"
		. "\n"
		. '    // peers array｜对端名单；键为对端服务标识，值为其 HTTPS 根地址。' . "\n"
		. '    // 出站调用用 app(\'tozo.http\')->to(\'对端标识\') 选路，无需记 Profile 名。' . "\n"
		. '    // 下面的域名是占位值（example.com/example.test 为保留域名，不会解析到真实主机），' . "\n"
		. '    // 接入时必须逐条替换为本环境实际部署地址；服务标识（键名）不要改动。' . "\n"
		. '    // 暂不互调的对端整条注释掉即可：不生成 Profile、不需要其密钥，其余关系不受影响。' . "\n"
		. "    'peers'       => [\n"
		. $peerLines
		. "    ],\n"
		. "];\n";
}

/**
 * 返回环境的中文标签。
 *
 * 使用范围：各文件的文件级注释拼接。
 * 适用场景：production/testing 两值固定映射，避免各处写法不一致。
 *
 * @param string $environment 环境标识。示例："production"
 * @return string 中文标签。示例："生产环境"
 */
function environment_label(string $environment)
{
	return $environment === 'production' ? '生产环境' : '测试环境';
}

/**
 * 构建 Kernel 路由中间件别名增量文件。
 *
 * 使用范围：每个系统 × 环境组合调用一次。
 * 适用场景：宿主需要把三个别名合并进自己的 $routeMiddleware，不能整文件覆盖。
 *
 * @param string $service 本系统服务标识。示例："tozo-app-api"
 * @param string $label 本系统中文名。示例："App 端 API"
 * @param string $environment 环境标识。示例："production"
 * @return string Kernel 增量文件内容。示例："<?php\n...return [...];\n"
 */
function build_kernel(string $service, string $label, string $environment)
{
	return "<?php\n\n"
		. header_block()
		. "\n"
		. "/**\n"
		. ' * ' . $label . '（' . $service . '）' . environment_label($environment) . " Kernel 中间件别名增量\n"
		. " *\n"
		. " * 文件功能：\n"
		. " * - 提供可合并进 app/Http/Kernel.php 的 \$routeMiddleware 条目\n"
		. " *\n"
		. " * 使用边界：\n"
		. " * - 这是增量片段而非完整 Kernel 类，必须合并进宿主既有数组\n"
		. " * - 直接用本文件覆盖宿主 Kernel 会删掉项目原有中间件\n"
		. " */\n"
		. "\n"
		. "return [\n"
		. '    // tozo.inbound string｜入站验证别名；验签成功后向请求注入可信 Subject 与 Profile。' . "\n"
		. "    'tozo.inbound'  => \\Tozo\\Security\\Laravel\\Middleware\\InboundAuthenticatorMiddleware::class,\n"
		. "\n"
		. '    // tozo.response string｜响应完整性别名；必须排在 tozo.inbound 之后才能拿到已验证的 Profile。' . "\n"
		. "    'tozo.response' => \\Tozo\\Security\\Laravel\\Middleware\\ResponseIntegrityMiddleware::class,\n"
		. "\n"
		. '    // tozo.outbound string｜代理出站保护别名；仅在用中间件方式转发请求时需要，' . "\n"
		. '    // 业务代码直接调用 app(\'tozo.http\')->to(...) 时不需要挂载它。' . "\n"
		. "    'tozo.outbound' => \\Tozo\\Security\\Laravel\\Middleware\\OutboundSignerMiddleware::class,\n"
		. "];\n";
}

/**
 * 构建入站路由文件。
 *
 * 使用范围：每个系统 × 环境组合调用一次。
 * 适用场景：三个对端各有一条入站路由，每条显式绑定唯一 inbound Profile。
 *
 * 函数逻辑：
 * 1. 遍历三个对端，按展开器的命名规则推导 inbound Profile 名。
 * 2. 路径用对端服务标识而非字母代号，使日志可直接定位来源系统。
 *
 * @param string $service 本系统服务标识。示例："tozo-app-api"
 * @param string $label 本系统中文名。示例："App 端 API"
 * @param string $environment 环境标识。示例："production"
 * @return string 路由文件内容。示例："<?php\n...Route::middleware(...)\n"
 */
function build_routes(string $service, string $label, string $environment)
{
	$body = '';
	foreach (BASE_URIS[$environment] as $peer => $ignored) {
		if ($peer === $service) {
			continue;
		}
		
		$profile = ConfigNormalizer::profileName($service, 'inbound_from', $peer);
		
		$body .= '// 来自 ' . $peer . " 的入站请求：先验签，再生成响应签名。\n"
			. "Route::middleware(['tozo.inbound', 'tozo.response'])\n"
			. "    ->defaults('tozo_profile', '" . $profile . "')\n"
			. "    ->post('/api/internal/tozo-security/from-" . $peer . "/health', [TozoSecurityController::class, 'handle']);\n\n";
	}
	
	return "<?php\n\n"
		. header_block()
		. "\n"
		. "/**\n"
		. ' * ' . $label . '（' . $service . '）' . environment_label($environment) . "入站安全路由\n"
		. " *\n"
		. " * 文件功能：\n"
		. " * - 为三个对端各注册一条入站健康检查路由，作为可复制的挂载范例\n"
		. " *\n"
		. " * 安全边界：\n"
		. " * - 每条路由显式绑定唯一 inbound Profile；入站解析绝不回退默认 Profile，\n"
		. " *   否则来自 A 的请求可能被按 B 的规则放行\n"
		. " * - 两个中间件顺序固定：先 tozo.inbound 验证，再 tozo.response 生成响应保护\n"
		. " */\n"
		. "\n"
		. "use Illuminate\\Support\\Facades\\Route;\n"
		. "use App\\Http\\Controllers\\Internal\\TozoSecurityController;\n"
		. "\n"
		. rtrim($body, "\n") . "\n";
}

/**
 * 构建示例控制器。
 *
 * 使用范围：每个系统 × 环境组合调用一次。
 * 适用场景：演示入站侧如何读取中间件注入的可信身份，以及出站侧如何按对端名选路。
 *
 * 函数逻辑：
 * 1. handle 只从 request attributes 读取已验签的 Profile 与 Subject，不碰原始输入。
 * 2. callPeer 演示 to() 选路：不需要拼 URL、不需要查 Profile 名。
 *
 * @param string $service 本系统服务标识。示例："tozo-app-api"
 * @param string $label 本系统中文名。示例："App 端 API"
 * @param string $environment 环境标识。示例："production"
 * @return string 控制器文件内容。示例："<?php\n...class TozoSecurityController...\n"
 */
function build_controller(string $service, string $label, string $environment)
{
	// 取第一个对端作为出站示例目标，保证每套示例都指向真实存在的关系。
	$samplePeer = '';
	foreach (BASE_URIS[$environment] as $peer => $ignored) {
		if ($peer !== $service) {
			$samplePeer = $peer;
			break;
		}
	}
	
	return "<?php\n\n"
		. header_block()
		. "\n"
		. "/**\n"
		. ' * ' . $label . '（' . $service . '）' . environment_label($environment) . "安全接口示例控制器\n"
		. " *\n"
		. " * 文件功能：\n"
		. " * - handle：入站侧范例，返回中间件已验证的调用方身份\n"
		. " * - callPeer：出站侧范例，演示按对端服务名选路发起签名请求\n"
		. " *\n"
		. " * 安全边界：\n"
		. " * - 只读取 request attributes 中由中间件写入的已验证值；\n"
		. " *   绝不从 input/query 重新取 client_id 之类的身份字段，那些值未经验签\n"
		. " * - 响应体由 tozo.response 中间件统一附加完整性保护，业务无需自行签名\n"
		. " */\n"
		. "\n"
		. "namespace App\\Http\\Controllers\\Internal;\n"
		. "\n"
		. "use Illuminate\\Http\\Request;\n"
		. "use Illuminate\\Http\\JsonResponse;\n"
		. "use App\\Http\\Controllers\\Controller;\n"
		. "\n"
		. "class TozoSecurityController extends Controller\n"
		. "{\n"
		. "    /**\n"
		. "     * 返回入站验证结果，用于两两互调的连通性确认。\n"
		. "     *\n"
		. "     * @param Request \$request 已通过 tozo.inbound 验证的请求｜身份信息在 attributes 中。\n"
		. "     * @return JsonResponse 健康检查响应｜由 tozo.response 中间件附加完整性保护。\n"
		. "     */\n"
		. "    public function handle(Request \$request)\n"
		. "    {\n"
		. "        // 这两个值由 InboundAuthenticatorMiddleware 在验签通过后写入，可信。\n"
		. "        \$profile = \$request->attributes->get('tozo_security_profile');\n"
		. "        \$subject = \$request->attributes->get('tozo_security_subject');\n"
		. "\n"
		. "        return response()->json([\n"
		. "            'status'  => 'ok',\n"
		. "            'service' => '" . $service . "',\n"
		. "            'profile' => \$profile === null ? null : \$profile->getName(),\n"
		. "            'caller'  => \$subject === null ? null : \$subject->getClientId(),\n"
		. "        ]);\n"
		. "    }\n"
		. "\n"
		. "    /**\n"
		. "     * 向对端发起一次签名请求。\n"
		. "     *\n"
		. "     * 加密、签名、附加 Token、响应验证全部由 SDK 完成；\n"
		. "     * 调用方只需要提供对端服务标识与相对路径。\n"
		. "     *\n"
		. "     * @return JsonResponse 对端返回的已验证响应内容。\n"
		. "     */\n"
		. "    public function callPeer()\n"
		. "    {\n"
		. "        // to() 按 config/tozo_security.php 的 peers 声明选路，\n"
		. "        // 未声明的对端会抛 ConfigurationException 而不是静默回退。\n"
		. "        \$response = app('tozo.http')\n"
		. "            ->to('" . $samplePeer . "')\n"
		. "            ->post('/api/internal/tozo-security/from-" . $service . "/health', ['ping' => 1]);\n"
		. "\n"
		. "        return response()->json([\n"
		. "            'status' => \$response->getStatus(),\n"
		. "            'body'   => \$response->json(),\n"
		. "        ]);\n"
		. "    }\n"
		. "}\n";
}

/**
 * 构建单套环境的 README。
 *
 * 使用范围：每个系统 × 环境组合调用一次。
 * 适用场景：列出该套展开出的 6 个 Profile 与 12 个密钥标识，作为部署核对清单。
 *
 * 函数逻辑：
 * 1. 用展开器真实展开一次配置，README 内容与代码推导结果同源。
 * 2. Profile 行用固定格式，供 FourSystemConfigurationTest 正则校验。
 *
 * @param string $service 本系统服务标识。示例："tozo-app-api"
 * @param string $label 本系统中文名。示例："App 端 API"
 * @param string $environment 环境标识。示例："production"
 * @return string README 内容。示例："# App 端 API ...\n"
 */
function build_environment_readme(string $service, string $label, string $environment)
{
	$peers = [];
	foreach (BASE_URIS[$environment] as $peer => $baseUri) {
		if ($peer !== $service) {
			$peers[$peer] = $baseUri;
		}
	}
	
	// 与运行期完全相同的展开路径，避免文档与实际推导结果脱节。
	$config = ConfigNormalizer::normalize([
		'service'     => $service,
		'environment' => $environment,
		'peers'       => $peers,
	]);
	
	$profileLines = '';
	foreach ($config['profiles'] as $name => $profile) {
		$direction = $profile['direction'] === 'outbound'
			? '出站到 ' . $profile['target_service']
			: '入站自 ' . $profile['client_id'];
		
		$profileLines .= '- `' . $name . '`：' . $direction . "\n";
	}
	
	$keyLines = '';
	$seen     = [];
	foreach ($config['profiles'] as $profile) {
		foreach ([
			         $profile['signature']['key_id'],
			         $profile['response_integrity']['signature']['key_id'],
		         ] as $keyId) {
			if (isset($seen[$keyId])) {
				continue;
			}
			
			$seen[$keyId] = true;
			$keyLines     .= '- `' . $keyId . ".key`\n";
		}
	}
	
	return '# ' . $label . '（' . $service . '）' . environment_label($environment) . "接入说明\n"
		. "\n"
		. "## 配置文件\n"
		. "\n"
		. "把 `config/tozo_security.php` 复制到项目 `config/` 下即可。该文件只有三个键：\n"
		. "\n"
		. "| 键 | 值 |\n"
		. "|---|---|\n"
		. '| `service` | `' . $service . "` |\n"
		. '| `environment` | `' . $environment . "` |\n"
		. "| `peers` | 另外三个系统的根地址 |\n"
		. "\n"
		. "不需要 `.env`，不需要 `tozo_services.php`，不需要手写 Profile。\n"
		. "\n"
		. "## 展开出的 6 个 Profile\n"
		. "\n"
		. $profileLines
		. "\n"
		. "## 需要部署的 12 个密钥文件\n"
		. "\n"
		. "位置：`storage/app/tozo/keys/`。由安装命令生成：\n"
		. "\n"
		. "```bash\n"
		. "php artisan tozo:security:install\n"
		. "```\n"
		. "\n"
		. $keyLines
		. "\n"
		. "同一条关系的两端必须持有**内容相同**的密钥文件。例如本系统与 "
		. array_keys($peers)[0] . " 之间的请求密钥，两边的 `.key` 文件内容必须一致。\n"
		. "\n"
		. "## 接入步骤\n"
		. "\n"
		. "1. 复制 `config/tozo_security.php`\n"
		. "2. 把 `app/Http/Kernel.tozo-security.php` 的三个别名合并进 `app/Http/Kernel.php` 的 `\$routeMiddleware`\n"
		. "3. 复制 `routes/tozo_security.php` 并在 `RouteServiceProvider` 中加载\n"
		. "4. 复制 `app/Http/Controllers/Internal/TozoSecurityController.php`\n"
		. "5. 执行 `php artisan tozo:security:install` 生成密钥，与对端交换\n"
		. "6. 执行 `php artisan tozo:security:check-config --runtime` 确认自洽\n"
		. "\n"
		. "## 出站调用\n"
		. "\n"
		. "```php\n"
		. "app('tozo.http')->to('" . array_keys($peers)[0] . "')->post('/api/orders', ['id' => 1]);\n"
		. "```\n";
}

/**
 * 构建系统级 README（两个环境的入口）。
 *
 * 使用范围：每个系统调用一次。
 * 适用场景：说明两套环境的差异只有 environment 与域名两项。
 *
 * @param string $service 本系统服务标识。示例："tozo-app-api"
 * @param string $label 本系统中文名。示例："App 端 API"
 * @return string README 内容。示例："# App 端 API ...\n"
 */
function build_system_readme(string $service, string $label)
{
	return '# ' . $label . '（' . $service . "）\n"
		. "\n"
		. "两个环境的接入文件：\n"
		. "\n"
		. "- `production/`：生产环境，占位域名为 example.com\n"
		. "- `testing/`：测试环境，占位域名为 example.test\n"
		. "\n"
		. "两套配置的唯一差异是 `environment` 与 `peers` 的域名。\n"
		. "`environment` 参与密钥命名空间，因此两个环境不共用任何密钥文件。\n";
}

/**
 * 构建示例包根 README。
 *
 * 使用范围：生成流程末尾调用一次。
 * 适用场景：给出四系统总览与配置精简前后的差异对照。
 *
 * @return string README 内容。示例："# 四系统实际配置文件 v0.0.9\n..."
 */
function build_root_readme()
{
	$rows = '';
	foreach (SYSTEMS as $directory => $meta) {
		$rows .= '| `' . $directory . '` | `' . $meta[0] . '` | ' . $meta[1] . " |\n";
	}
	
	return "# 四系统实际配置文件 v0.0.9\n"
		. "\n"
		. "配置精简后的接入示例。每套只有 4 个文件，其中配置文件仅 3 个键。\n"
		. "\n"
		. "## 目录对应关系\n"
		. "\n"
		. "| 目录 | 服务标识 | 说明 |\n"
		. "|---|---|---|\n"
		. $rows
		. "\n"
		. "## 域名怎么配\n"
		. "\n"
		. "各套配置里的域名是**占位值**。`example.com`（生产）与 `example.test`（测试）\n"
		. "是 RFC 2606 保留域名，不会解析到真实主机，照抄上线会在出站时连接失败——\n"
		. "这是有意为之，防止占位值被误当成可用配置。\n"
		. "\n"
		. "复制配置后只改 `peers` 段的域名：\n"
		. "\n"
		. "- **键（服务标识）不要改**：参与签名原文绑定，两端必须一致，改了就验签失败。\n"
		. "- **值（根地址）替换为本环境实际地址**：只用于出站选路，不参与签名，\n"
		. "  换域名、切内网地址、加端口都不影响密钥与 Profile 推导。\n"
		. "- **暂不互调的对端整条注释掉**：不生成 Profile、不需要其密钥，其余关系不受影响。\n"
		. "\n"
		. "测试与生产的域名分别写在各自环境的配置里，`environment` 参与密钥命名空间，\n"
		. "两个环境不共用任何密钥文件。改域名不必重跑 `tozo:security:install`，\n"
		. "但建议跑一次 `php artisan tozo:security:check-config --runtime` 确认配置自洽。\n"
		. "\n"
		. "## 与配置精简前的差异\n"
		. "\n"
		. "| 项目 | 精简前 | 现在 |\n"
		. "|---|---|---|\n"
		. "| 每套文件数 | 8 | 4 |\n"
		. "| 配置文件行数 | 548 | 约 25 |\n"
		. "| 配置键数 | 224 | 3 |\n"
		. "| `.env` | 每套 31 个变量 | 不再需要 |\n"
		. "| `config/tozo_services.php` | 需要 | 并入 SDK 内置默认 |\n"
		. "| 手写 HTTP Client | 每套 108 行样板 | 由 SDK 的 `to()` 提供 |\n"
		. "| 密钥来源 | 环境变量 | `storage/app/tozo/keys/` |\n"
		. "\n"
		. "本目录由 `composer examples` 生成，请勿手工修改——\n"
		. "手工改动会被 `composer examples-check` 判为与生成规则不一致。\n"
		. "\n"
		. "## 每套包含的文件\n"
		. "\n"
		. "```text\n"
		. "config/tozo_security.php                              三个键的极简配置\n"
		. "app/Http/Kernel.tozo-security.php                     中间件别名增量\n"
		. "routes/tozo_security.php                              三条入站路由\n"
		. "app/Http/Controllers/Internal/TozoSecurityController.php  入站与出站范例\n"
		. "README.md                                             该套的部署核对清单\n"
		. "```\n"
		. "\n"
		. "## 密钥对称要求\n"
		. "\n"
		. "12 条有向关系 × 请求/响应两种用途 = 全网 24 个密钥，每个系统持有与自己相关的 12 个。\n"
		. "同一条关系两端的同名密钥文件内容必须完全相同，否则验签失败。\n"
		. "\n"
		. "密钥标识由 SDK 按 `{environment}_{调用方}_to_{接收方}_{用途}` 推导，无需手工命名。\n";
}

/**
 * 汇总示例包全部文件的相对路径与内容。
 *
 * 使用范围：写盘与 --check 比对共用同一份产出，保证两种模式判定一致。
 * 适用场景：4 系统 × 2 环境 × 4 个文件 + 每套 README + 系统 README + 根 README。
 *
 * 函数逻辑：
 * 1. 遍历系统与环境，逐个构建四类文件与该套 README。
 * 2. 追加 4 个系统级 README 与 1 个根 README。
 *
 * @return array 文件表｜相对路径=>内容。示例：["tozoApp-api/production/config/tozo_security.php"=>"<?php..."]
 */
function build_all_files()
{
	$files = [];
	
	foreach (SYSTEMS as $directory => $meta) {
		list($service, $label) = $meta;
		
		foreach (['production', 'testing'] as $environment) {
			$base = $directory . '/' . $environment . '/';
			
			$files[$base . 'config/tozo_security.php']          = build_config($service, $label, $environment);
			$files[$base . 'app/Http/Kernel.tozo-security.php'] = build_kernel($service, $label, $environment);
			$files[$base . 'routes/tozo_security.php']          = build_routes($service, $label, $environment);
			$files[$base . 'app/Http/Controllers/Internal/TozoSecurityController.php']
			                                                    = build_controller($service, $label, $environment);
			$files[$base . 'README.md']                         = build_environment_readme($service, $label, $environment);
		}
		
		$files[$directory . '/README.md'] = build_system_readme($service, $label);
	}
	
	$files['README.md'] = build_root_readme();
	
	return $files;
}

/**
 * 生成或校验示例包。
 *
 * 使用范围：命令行入口。
 * 适用场景：composer examples 重新生成；composer examples-check 在 CI 中确认未脱节。
 *
 * 函数逻辑：
 * 1. --check 模式逐个比对磁盘内容，报告缺失与不一致后以退出码 1 结束。
 * 2. 默认模式创建目录并写入无 BOM UTF-8 内容。
 *
 * @param bool $checkOnly 校验模式开关｜true 时不写盘。示例：false
 * @return int 进程退出码｜0 表示通过。示例：0
 */
function run(bool $checkOnly)
{
	$root  = dirname(__DIR__) . '/docs/' . EXAMPLE_DIR;
	$files = build_all_files();
	
	echo "===== 四系统示例配置包生成器 =====\n\n";
	echo '目标目录：docs/' . EXAMPLE_DIR . "\n";
	echo '文件总数：' . count($files) . "\n\n";
	
	if ($checkOnly) {
		$problems = [];
		
		foreach ($files as $relative => $content) {
			$path = $root . '/' . $relative;
			
			if (!is_file($path)) {
				$problems[] = '缺失：' . $relative;
				continue;
			}
			
			if ((string)file_get_contents($path) !== $content) {
				$problems[] = '内容与生成规则不一致：' . $relative;
			}
		}
		
		if ($problems !== []) {
			echo "结论：存在未达标项\n";
			foreach ($problems as $problem) {
				echo '    - ' . $problem . "\n";
			}
			
			return 1;
		}
		
		echo "结论：示例包与生成规则一致\n";
		
		return 0;
	}
	
	foreach ($files as $relative => $content) {
		$path      = $root . '/' . $relative;
		$directory = dirname($path);
		
		if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) {
			echo '无法创建目录：' . $directory . "\n";
			
			return 1;
		}
		
		// LF 行尾与无 BOM UTF-8：BOM 会破坏 Laravel 的 header() 输出，
		// CRLF 会破坏签名规范化串的跨平台字节一致性。
		file_put_contents($path, $content);
	}
	
	echo "结论：已写入 " . count($files) . " 个文件\n";
	
	return 0;
}

exit(run(in_array('--check', $argv, true)));
