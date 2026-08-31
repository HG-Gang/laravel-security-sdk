<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 发布前语法检查工具
 *
 * 文件功能：
 * - 对 src / tests / config / tools 全量执行 php -l，用当前 PHP 二进制验证语法
 * - 供 composer run lint 与 CI 调用，返回码 0=通过、1=存在语法错误
 *
 * 使用方式：
 *   php tools/lint.php                     使用当前 PHP 检查
 *   path\to\php7.4\php.exe tools/lint.php  用 7.4 验证最低版本兼容性
 *
 * 安全边界：
 * - 只做语法检查，不加载业务代码、不读取密钥、不连接外部依赖
 */

$root        = dirname(__DIR__);
$directories = ['src', 'tests', 'config', 'tools'];

$total  = 0;
$failed = 0;

foreach ($directories as $directory) {
	$path = $root . DIRECTORY_SEPARATOR . $directory;
	if (!is_dir($path)) {
		continue;
	}
	
	$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));
	
	foreach ($iterator as $file) {
		if (!$file->isFile() || $file->getExtension() !== 'php') {
			continue;
		}
		
		$total++;
		
		// 用当前运行的 PHP 二进制执行语法检查，保证与目标版本一致。
		$command = escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file->getPathname());
		exec($command, $output, $exitCode);
		
		if ($exitCode !== 0) {
			$failed++;
			echo 'FAIL: ' . str_replace($root, '', $file->getPathname()) . PHP_EOL;
			foreach ($output as $line) {
				echo '      ' . $line . PHP_EOL;
			}
		}
		
		// exec() 会向 $output 追加而非覆盖，必须逐个文件重置。
		$output = [];
	}
}

printf('PHP %s: 检查 %d 个文件，失败 %d 个%s', PHP_VERSION, $total, $failed, PHP_EOL);

exit($failed === 0 ? 0 : 1);
