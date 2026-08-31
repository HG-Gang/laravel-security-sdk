<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * SecurityCheckConfigCommand
 *
 * 文件功能：
 * - artisan tozo:security:check-config：部署前主动发现配置错误
 * - 默认仅结构链路检查；--runtime 追加密钥存在性与缓存连通性（不输出密钥值）
 *
 * 安全边界：
 * - 任何输出不得包含密钥内容、完整 Token 或 Profile 内部候选数量细节
 */

namespace Tozo\Security\Laravel\Command;

use Illuminate\Console\Command;
use Tozo\Security\Support\ConfigChecker;
use Tozo\Security\Contracts\KeyProviderInterface;
use Illuminate\Contracts\Cache\Repository as CacheRepository;

class SecurityCheckConfigCommand extends Command
{
	/**
	 * 命令签名与选项定义。
	 *
	 * --runtime 与默认结构检查分开的原因：结构检查不接触任何外部依赖，
	 * 可在 CI 中安全运行；而 runtime 探测会读取真实密钥并连接缓存后端，
	 * 只适合在目标部署环境执行。两者合并会让 CI 因缺少生产依赖而必然失败。
	 *
	 * @var string
	 */
	protected $signature = 'tozo:security:check-config
                            {--runtime : 同时探测密钥存在性与缓存连通性（不输出密钥值）}';
	
	/**
	 * 命令描述。出现在 artisan list 中，需一句话说清检查覆盖的链路。
	 * 描述里列出五个环节是有意的——它同时充当「体检查了什么」的速查表，
	 * 使运维不必翻文档就知道通过意味着哪些矛盾已被排除。
	 *
	 * @var string
	 */
	protected $description = 'Tozo Security 配置体检：功能开关 → Profile 引用 → driver → key ID 格式 → 接口依赖';
	
	/**
	 * 执行配置体检并格式化输出。
	 *
	 * 使用范围：运维在部署前/CI 流水线手动执行。
	 * 适用场景：config:cache 之后、流量接入之前确认安全配置闭环无矛盾。
	 *
	 * 函数逻辑：
	 * 1. 从容器取 tozo_security 配置树与可选 KeyProvider/CacheRepository。
	 * 2. 委托 ConfigChecker 执行结构（+可选 runtime）体检。
	 * 3. 逐条输出错误/警告；成功输出 Profile 数量摘要。
	 * 4. 返回码：ok=0，失败=1（便于 CI 判定）。
	 *
	 * @return int 进程退出码｜0 成功，1 存在错误。示例：0
	 */
	public function handle()
	{
		$config = $this->laravel['config']->get('tozo_security', []);
		$keys   = $this->laravel->bound(KeyProviderInterface::class)
			? $this->laravel->make(KeyProviderInterface::class)
			: null;
		$cache  = $this->laravel->bound(CacheRepository::class)
			? $this->laravel->make(CacheRepository::class)
			: null;
		
		$result = (new ConfigChecker())->check(
			$config,
			$keys,
			$cache,
			(bool)$this->option('runtime')
		);
		
		foreach ($result['errors'] as $error) {
			$this->error('[error] ' . $error);
		}
		
		foreach ($result['warnings'] as $warning) {
			$this->warn('[warn] ' . $warning);
		}
		
		if ($result['ok']) {
			$this->info("tozo_security configuration OK ({$result['profiles']} enabled profiles)");
			return 0;
		}
		
		$this->error('tozo_security configuration has errors');
		return 1;
	}
}
