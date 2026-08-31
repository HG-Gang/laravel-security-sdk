<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 05:30
 */

/**
 * SecurityInstallCommand
 *
 * 文件功能：
 * - artisan tozo:security:install：把「配置里声明的对端」一次性落成「磁盘上可用的密钥」
 * - 按 peers 展开出的 Profile 反查全部被引用的 key_id，逐个生成密钥文件
 * - 输出需与对端交换的密钥清单，以及入站路由要绑定的 Profile 名
 *
 * 为什么需要这个命令：
 * - 配置精简后 key_id 不再由人手写，而是由 ConfigNormalizer 按四元组推导；
 *   接入方无法凭肉眼列出「我需要哪些密钥」，只能由 SDK 自己算出来
 * - 四系统互调每个系统需要 12 个密钥文件，手工创建必然出现命名错误，
 *   而命名错误的表现是运行期 KeyNotFoundException 而非启动期配置报错
 *
 * 安全边界：
 * - 绝不覆盖已存在的密钥文件：覆盖会立即切断该关系的两端通信，
 *   轮换必须由运维显式删除旧文件后再执行，不能由一次误运行造成
 * - 密钥文件权限设为 0600，目录设为 0700；同时写入 .gitignore 防止密钥进版本库
 * - 使用 random_bytes（CSPRNG）；不接受任何可预测的种子参数
 * - 不生成 RSA 密钥对：JWT RS256 私钥必须由运维用 openssl 在受控环境生成
 */

namespace Tozo\Security\Laravel\Command;

use Illuminate\Console\Command;
use Tozo\Security\Support\ConfigNormalizer;

class SecurityInstallCommand extends Command
{
	/**
	 * 生成的对称密钥字符串长度（字符数，同时也是字节数）。
	 *
	 * 取 32 是因为两类用途的下限都落在这里：AES-256-GCM 要求恰好 32 字节
	 * （AesGcmCipher 校验的是 strlen 而非解码后长度），HMAC-SHA256 的输出为
	 * 32 字节、短于此即削弱强度。统一取 32 可让同一份生成逻辑覆盖全部用途。
	 */
	private const KEY_LENGTH = 32;
	
	/**
	 * 密钥目录的默认相对路径（相对 Laravel storage 目录）。
	 *
	 * 落在 storage/app/ 下是因为 Laravel 默认不把该目录暴露给 web 服务器，
	 * 放在 public/ 或项目根目录会让密钥可被 HTTP 直接下载。
	 */
	private const DEFAULT_KEY_SUBPATH = 'app/tozo/keys';
	
	/**
	 * 命令签名与选项定义。
	 *
	 * --dry-run 存在的意义：首次接入时先确认「将要生成哪些 key_id」，
	 * 与对端核对命名一致后再真正落盘，避免两端各自生成出不同命名的密钥。
	 *
	 * @var string
	 */
	protected $signature = 'tozo:security:install
                            {--dir= : 覆盖密钥目录绝对路径；默认 storage/app/tozo/keys}
                            {--dry-run : 只列出计划生成的密钥，不创建目录也不写任何文件}';
	
	/**
	 * 命令描述。出现在 artisan list 中，需一句话说清副作用范围。
	 * 「不覆盖已存在的密钥」必须写进描述：这是运维判断能否重复执行的依据，
	 * 也是本命令与「重新生成」语义的关键区别——轮换必须先手工删除旧文件。
	 *
	 * @var string
	 */
	protected $description = 'Tozo Security 安装：按 peers 推导并生成本系统全部密钥文件（不覆盖已存在的密钥）';
	
	/**
	 * 执行安装：推导密钥清单并落盘，随后打印交换清单与路由绑定信息。
	 *
	 * 使用范围：接入方首次部署，或在 peers 中新增对端之后由运维执行。
	 * 适用场景：把配置声明的信任关系转成磁盘上实际可用的密钥物料。
	 *
	 * 函数逻辑：
	 * 1. 读配置并要求已填 service 与 peers；未填时直接失败并给出要改的位置。
	 * 2. 经 ConfigNormalizer 展开出 Profile，再反查全部被引用的 key_id。
	 * 3. dry-run 只打印清单；否则创建目录、逐个生成缺失密钥、写 .gitignore。
	 * 4. 打印对端交换清单与入站 Profile 名——这两项接入方无法自行推导。
	 *
	 * @return int 进程退出码｜0 成功，1 配置不完整或目录不可写。示例：0
	 */
	public function handle()
	{
		$config = $this->laravel['config']->get('tozo_security', []);
		$config = is_array($config) ? $config : [];
		
		$service = isset($config['service']) && is_string($config['service']) ? $config['service'] : '';
		
		if ($service === '') {
			$this->error('config/tozo_security.php 的 service 尚未填写，无法推导任何密钥。');
			$this->line('  请先填入本系统标识，例如：\'service\' => \'tozo-app-api\'');
			
			return 1;
		}
		
		$peers = isset($config['peers']) && is_array($config['peers']) ? $config['peers'] : [];
		
		if ($peers === []) {
			$this->error('config/tozo_security.php 的 peers 为空，没有任何对端需要建立信任关系。');
			$this->line('  请先声明对端，例如：\'app-admin-api\' => \'https://app-admin-api.example.com\'');
			
			return 1;
		}
		
		// 展开失败（environment 缺失、对端与自身同名等）会抛 ConfigurationException，
		// 这里不捕获：配置错误必须让运维看到完整堆栈并修配置，而非拿到一句模糊提示。
		$normalized = ConfigNormalizer::normalize($config);
		$keyIds     = $this->collectKeyIds($normalized['profiles']);
		
		$this->line('');
		$this->info('本系统：' . $service . '（环境 ' . $normalized['environment'] . '）');
		$this->line('  对端数量：' . count($peers) . '｜展开 Profile：' . count($normalized['profiles'])
			. ' 个｜需要密钥：' . count($keyIds) . ' 个');
		$this->line('');
		
		if ($this->option('dry-run')) {
			return $this->reportDryRun($keyIds, $normalized['profiles']);
		}
		
		$directory = $this->resolveKeyDirectory();
		if ($directory === null) {
			return 1;
		}
		
		return $this->writeKeys($directory, $keyIds, $normalized['profiles']);
	}
	
	/**
	 * 收集展开结果中被引用的全部 key_id。
	 *
	 * 使用范围：handle 在展开配置之后调用。
	 * 适用场景：同一密钥会被出站与入站两个 Profile 同时引用（这正是两端共享的语义），
	 *           因此必须去重；漏去重会导致同一文件被重复处理并虚报生成数量。
	 *
	 * 函数逻辑：
	 * 1. 逐 Profile 取签名、响应签名两个必有用途，以及加密、Token 两个可选用途。
	 * 2. 用数组键天然去重，最后排序使输出顺序稳定、便于与对端逐行核对。
	 *
	 * @param array $profiles Profile 表｜ConfigNormalizer 展开结果。示例：["a_outbound_to_b"=>["signature"=>["key_id"=>"..."]]]
	 * @return string[] 去重并排序后的 key_id 列表。示例：["production_a_to_b_request","production_a_to_b_response"]
	 */
	private function collectKeyIds(array $profiles)
	{
		$ids = [];
		
		foreach ($profiles as $profile) {
			// 两个必有用途：请求完整性与响应完整性，二者必须使用不同密钥。
			$ids[$profile['signature']['key_id']]                       = true;
			$ids[$profile['response_integrity']['signature']['key_id']] = true;
			
			// 加密密钥只在该关系显式开启 encryption 时才存在。
			if (isset($profile['encryption']['key_id'])) {
				$ids[$profile['encryption']['key_id']] = true;
			}
			
			// Token 密钥只在该关系升级为 token_plus_request_signature 时才存在。
			if (isset($profile['token']['signing_key_id'])) {
				$ids[$profile['token']['signing_key_id']] = true;
			}
		}
		
		$list = array_keys($ids);
		sort($list);
		
		return $list;
	}
	
	/**
	 * 打印计划而不产生任何副作用。
	 *
	 * 使用范围：handle 在 --dry-run 模式下调用。
	 * 适用场景：两端在正式生成前先核对 key_id 命名是否一致。
	 *
	 * 函数逻辑：
	 * 1. 列出全部待生成 key_id 对应的文件名。
	 * 2. 打印对端交换要求与入站 Profile 名，与真实执行时的输出保持一致。
	 *
	 * @param array $keyIds 待生成 key_id 列表。示例：["production_a_to_b_request"]
	 * @param array $profiles Profile 表｜用于打印入站绑定信息。示例：["a_inbound_from_b"=>[...]]
	 * @return int 进程退出码｜恒为 0。示例：0
	 */
	private function reportDryRun(array $keyIds, array $profiles)
	{
		$this->comment('dry-run：以下文件将被创建，本次不写入任何内容。');
		$this->line('');
		
		foreach ($keyIds as $keyId) {
			$this->line('  ' . $keyId . '.key');
		}
		
		$this->line('');
		$this->printExchangeNotice();
		$this->printInboundProfiles($profiles);
		
		return 0;
	}
	
	/**
	 * 打印与对端交换密钥的硬性要求。
	 *
	 * 使用范围：dry-run 与真实执行的输出末尾均调用。
	 * 适用场景：这是整套流程唯一无法自动化的一步，也是最容易出错的一步——
	 *           两端各自生成会得到内容不同的同名文件，表现为验签失败而非配置报错。
	 *
	 * 函数逻辑：
	 * 1. 说明同名文件两端内容必须一致这一核心约束。
	 * 2. 给出传输通道要求与轮换方式，避免密钥经聊天工具留下副本。
	 *
	 * @return void 无返回值。
	 */
	private function printExchangeNotice()
	{
		$this->warn('与对端交换密钥（这一步无法自动完成）：');
		$this->line('  1. 同一条关系两端必须持有内容完全相同的同名 .key 文件；');
		$this->line('     本命令只在本机生成，对端不会自动拿到，需经安全通道同步。');
		$this->line('  2. 谁生成都可以，但只能有一方生成后同步给另一方；');
		$this->line('     两端各自生成会得到内容不同的同名文件，结果是验签失败。');
		$this->line('  3. 不要用邮件、聊天工具或工单系统传输密钥内容。');
		$this->line('  4. 轮换时先删除两端旧文件再重新执行本命令；本命令不覆盖已存在的密钥。');
		$this->line('');
	}
	
	/**
	 * 打印入站路由需要绑定的 Profile 名。
	 *
	 * 使用范围：dry-run 与真实执行的输出末尾均调用。
	 * 适用场景：Profile 名由展开器推导，接入方无法手写；漏绑或绑错会导致启动即失败。
	 *           出站方向不需要 Profile 名——业务用 to('对端标识') 按服务名选路。
	 *
	 * 函数逻辑：
	 * 1. 只列出 inbound 方向的 Profile 名，并给出可直接粘贴的路由片段格式。
	 *
	 * @param array $profiles Profile 表｜展开结果。示例：["a_inbound_from_b"=>["direction"=>"inbound"]]
	 * @return void 无返回值。
	 */
	private function printInboundProfiles(array $profiles)
	{
		$inbound = [];
		
		foreach ($profiles as $name => $profile) {
			if ($profile['direction'] === 'inbound') {
				$inbound[$name] = $profile['client_id'];
			}
		}
		
		if ($inbound === []) {
			return;
		}
		
		$this->info('入站路由需绑定的 Profile 名（在 routes 中用 ->defaults(\'tozo_profile\', ...) 指定）：');
		
		foreach ($inbound as $name => $caller) {
			$this->line('  来自 ' . $caller . ' → ' . $name);
		}
		
		$this->line('');
		$this->comment('下一步：php artisan tozo:security:check-config --runtime');
		$this->line('');
	}
	
	/**
	 * 解析并准备密钥目录。
	 *
	 * 使用范围：handle 在非 dry-run 模式下调用。
	 * 适用场景：--dir 用于把密钥放到 Laravel 之外的受控挂载点（如容器 secret 卷）。
	 *
	 * 函数逻辑：
	 * 1. --dir 优先；未给出时回退 storage_path 的默认子路径。
	 * 2. 目录不存在则以 0700 创建——只有属主可读写，同机其他用户无法列出密钥文件名。
	 *
	 * @return string|null 目录绝对路径；创建失败时返回 null（调用方据此返回 1）。示例："/var/www/storage/app/tozo/keys"
	 */
	private function resolveKeyDirectory()
	{
		$override = $this->option('dir');
		
		if (is_string($override) && $override !== '') {
			$directory = $override;
		} else {
			$directory = $this->laravel->storagePath() . '/' . self::DEFAULT_KEY_SUBPATH;
		}
		
		if (is_dir($directory)) {
			return $directory;
		}
		
		// 并发执行时两个进程可能同时创建；mkdir 失败后再确认一次是否已存在。
		if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
			$this->error('无法创建密钥目录：' . $directory);
			$this->line('  请确认父目录存在且当前用户有写权限，或用 --dir 指定其他位置。');
			
			return null;
		}
		
		return $directory;
	}
	
	/**
	 * 生成缺失的密钥文件并汇报结果。
	 *
	 * 使用范围：handle 在解析出目录之后调用。
	 * 适用场景：既支持首次全量生成，也支持新增对端后的增量补齐。
	 *
	 * 函数逻辑：
	 * 1. 已存在的文件一律跳过并计数——覆盖会立即切断该关系两端的通信。
	 * 2. 逐个以 0600 写入 CSPRNG 密钥；任一写入失败立即中止，不留下半套密钥。
	 * 3. 写 .gitignore，随后打印统计、交换要求与入站 Profile 名。
	 *
	 * @param string $directory 密钥目录绝对路径。示例："/var/www/storage/app/tozo/keys"
	 * @param array $keyIds 待生成 key_id 列表。示例：["production_a_to_b_request"]
	 * @param array $profiles Profile 表｜用于打印入站绑定信息。示例：["a_inbound_from_b"=>[...]]
	 * @return int 进程退出码｜0 成功，1 写入失败。示例：0
	 */
	private function writeKeys(string $directory, array $keyIds, array $profiles)
	{
		$this->info('密钥目录：' . $directory);
		$this->line('');
		
		$created = 0;
		$skipped = 0;
		
		foreach ($keyIds as $keyId) {
			$path = $directory . '/' . $keyId . '.key';
			
			if (is_file($path)) {
				// 轮换必须由运维显式删除旧文件后再执行；一次误运行不应造成通信中断。
				$skipped++;
				$this->line('  跳过（已存在）：' . $keyId . '.key');
				continue;
			}
			
			if (file_put_contents($path, $this->generateKey()) === false) {
				$this->error('写入失败：' . $path);
				$this->line('  已生成 ' . $created . ' 个密钥；请修复权限后重新执行，已生成的文件不会被覆盖。');
				
				return 1;
			}
			
			// 权限收紧到仅属主可读写：同机其他账号不应能读取密钥内容。
			@chmod($path, 0600);
			
			$created++;
			$this->line('  已生成：' . $keyId . '.key');
		}
		
		$this->line('');
		$this->writeGitignore($directory);
		
		$this->info('完成：新生成 ' . $created . ' 个，跳过 ' . $skipped . ' 个已存在的密钥。');
		$this->line('');
		
		$this->printExchangeNotice();
		$this->printInboundProfiles($profiles);
		
		return 0;
	}
	
	/**
	 * 生成单个对称密钥字符串。
	 *
	 * 使用范围：writeKeys 为每个缺失的 key_id 调用一次。
	 * 适用场景：KeyProvider 返回的是文件内容原文，AesGcmCipher 校验 strlen(key) === 32。
	 *           因此不能写入 base64_encode(random_bytes(32))——那是 44 字符，会被解密器拒绝。
	 *           这里保证「字符串长度恰为 32」，同时满足 HMAC 与 AES 两类用途。
	 *
	 * 函数逻辑：
	 * 1. 取足量随机字节做 Base64URL 编码，每字符承载 6 bit。
	 * 2. 截断到恰好 32 字符；截断不引入偏置，熵为 192 bit。
	 * 3. 字符集限定 [A-Za-z0-9-_]，无换行与空白，避免 FileKeyProvider 的 rtrim 改变内容。
	 *
	 * @return string 密钥字符串｜长度恰为 32。示例："xK3p_Qm7...（32 字符）"
	 */
	private function generateKey()
	{
		$raw     = random_bytes((int)ceil(self::KEY_LENGTH * 6 / 8) + 1);
		$encoded = rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
		
		return substr($encoded, 0, self::KEY_LENGTH);
	}
	
	/**
	 * 在密钥目录写入 .gitignore。
	 *
	 * 使用范围：writeKeys 在密钥生成完成后调用。
	 * 适用场景：密钥目录位于项目树内（storage/app/），一次 git add . 就可能把生产密钥提交进库；
	 *           signed_request 模式下签名即身份，密钥入库等于全网身份伪造能力泄露。
	 *
	 * 函数逻辑：
	 * 1. 已存在则不改动——宿主可能已有自己的忽略规则，覆盖会丢失其内容。
	 * 2. 忽略全部 .key 并显式保留 .gitignore 自身，使目录结构仍可被追踪。
	 *
	 * @param string $directory 密钥目录绝对路径。示例："/var/www/storage/app/tozo/keys"
	 * @return void 无返回值；写入失败只提示，不阻断安装流程。
	 */
	private function writeGitignore(string $directory)
	{
		$path = $directory . '/.gitignore';
		
		if (is_file($path)) {
			$this->line('  .gitignore 已存在，未改动。');
			
			return;
		}
		
		$content = "# 密钥文件绝不进版本库：签名即身份，泄露等于全网身份伪造能力泄露。\n"
			. "*.key\n"
			. "\n"
			. "# 保留本文件自身，使目录结构仍可被 git 追踪。\n"
			. "!.gitignore\n";
		
		if (file_put_contents($path, $content) === false) {
			$this->warn('  .gitignore 写入失败，请手工确认密钥不会被提交进版本库。');
			
			return;
		}
		
		$this->line('  已写入 .gitignore（忽略全部 *.key）。');
	}
}
