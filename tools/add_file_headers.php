<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 文件头部标识块批量插入工具
 *
 * 文件功能：
 * - 为 src/tests/config/tools 下每个 PHP 文件插入统一的 PhpStorm 风格头部块
 * - 已存在头部的文件跳过，保证可重复执行（幂等）
 * - 同步处理 protocol/conformance 下的 Python 与 Go 文件（使用各自注释语法）
 *
 * 使用方式：
 *   php tools/add_file_headers.php            插入缺失的头部块
 *   php tools/add_file_headers.php --check    只报告缺失项，不修改文件（供 CI 使用）
 *
 * 插入位置：
 * - PHP：紧随 <?php 之后、文件级功能说明 PHPDoc 之前（PhpStorm 默认位置）
 * - Python：文件最开头（模块 docstring 之前）
 * - Go：package 声明之前
 *
 * 安全边界：
 * - 只在文件开头插入固定文本，不改动任何既有代码或注释
 * - 保持 LF 行尾与无 BOM 的 UTF-8 编码，避免破坏签名原文的字节一致性
 */

$root      = dirname(__DIR__);
$checkOnly = in_array('--check', $argv, true);

// 头部块固定字段。项目名取仓库目录名；作者与时间为本次统一标注值。
$projectName = 'Tozo-security-sdk-php';
$user        = 'Huang Gang';
$date        = '2026/08/28';
$time        = '01:10';

/**
 * 生成 PHP 风格头部块。
 *
 * @param string $projectName 项目名称。
 * @param string $user 作者。
 * @param string $date 日期（yyyy/mm/dd）。
 * @param string $time 时间（HH:mm）。
 * @return string 以换行结尾的注释块。
 */
function phpHeader(string $projectName, string $user, string $date, string $time)
{
	return "/**\n"
		. " * Created by PhpStorm.\n"
		. " * Project name {$projectName}.\n"
		. " * User: {$user}\n"
		. " * Date: {$date}\n"
		. " * Time: {$time}\n"
		. " */\n";
}

/**
 * 生成井号注释风格头部块（Python）。
 *
 * @param string $projectName 项目名称。
 * @param string $user 作者。
 * @param string $date 日期。
 * @param string $time 时间。
 * @return string 以换行结尾的注释块。
 */
function hashHeader(string $projectName, string $user, string $date, string $time)
{
	return "# Created by PhpStorm.\n"
		. "# Project name {$projectName}.\n"
		. "# User: {$user}\n"
		. "# Date: {$date}\n"
		. "# Time: {$time}\n";
}

/**
 * 生成双斜杠注释风格头部块（Go）。
 *
 * @param string $projectName 项目名称。
 * @param string $user 作者。
 * @param string $date 日期。
 * @param string $time 时间。
 * @return string 以换行结尾的注释块。
 */
function slashHeader(string $projectName, string $user, string $date, string $time)
{
	return "// Created by PhpStorm.\n"
		. "// Project name {$projectName}.\n"
		. "// User: {$user}\n"
		. "// Date: {$date}\n"
		. "// Time: {$time}\n";
}

/**
 * 收集待处理文件。
 *
 * @param string $root 项目根目录。
 * @return array<string,string> 绝对路径 => 语言标识（php/python/go）。
 */
function collectFiles(string $root)
{
	$files = [];
	
	foreach (['src', 'tests', 'config', 'tools'] as $directory) {
		$path = $root . '/' . $directory;
		if (!is_dir($path)) {
			continue;
		}
		
		foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path)) as $file) {
			if ($file->isFile() && $file->getExtension() === 'php') {
				$files[$file->getPathname()] = 'php';
			}
		}
	}
	
	$conformance = $root . '/protocol/conformance';
	if (is_dir($conformance)) {
		foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($conformance)) as $file) {
			if (!$file->isFile()) {
				continue;
			}
			
			if ($file->getExtension() === 'py') {
				$files[$file->getPathname()] = 'python';
			} elseif ($file->getExtension() === 'go') {
				$files[$file->getPathname()] = 'go';
			}
		}
	}
	
	ksort($files);
	
	return $files;
}

/**
 * 为单个文件内容插入头部块。
 *
 * 使用范围：主流程逐文件调用。
 * 适用场景：三种语言的插入锚点不同，必须分别定位，不能统一插到第 0 行。
 *
 * 函数逻辑：
 * 1. PHP：定位首个 <?php 行，插到其后。
 * 2. Python：插到文件最开头。
 * 3. Go：定位 package 声明行，插到其前（Go 要求注释在 package 之上才算文件注释）。
 *
 * @param string $source 原始文件内容。
 * @param string $language 语言标识（php/python/go）。
 * @param string $header 待插入的头部块。
 * @return string|null 插入后的内容；无法定位锚点时返回 null。
 */
function insertHeader(string $source, string $language, string $header)
{
	if ($language === 'php') {
		$openTag  = "<?php\n";
		$position = strpos($source, $openTag);
		
		if ($position !== 0) {
			// 仅处理以 <?php 开头的文件，避免破坏含前导内容的特殊文件。
			return null;
		}
		
		return $openTag . "\n" . $header . substr($source, strlen($openTag));
	}
	
	if ($language === 'python') {
		return $header . "\n" . $source;
	}
	
	// Go：标识块放在文件最开头。
	//
	// 不能插到 package 之前的位置——那里紧贴着包文档注释，
	// 插入后标识块会被 godoc 吸收为包文档的一部分。放在文件最顶端并空一行，
	// 既保持标识块可见，又不破坏"包文档注释必须紧邻 package"的 Go 约定。
	if (preg_match('/^package\s+\w+/m', $source) !== 1) {
		return null;
	}
	
	return $header . "\n" . $source;
}

$files = collectFiles($root);

$inserted = 0;
$skipped  = 0;
$failed   = [];
$missing  = [];

foreach ($files as $path => $language) {
	$source = (string)file_get_contents($path);
	$short  = str_replace($root, '', $path);
	
	// 幂等：已含标识行的文件不再处理。
	if (strpos($source, 'Created by PhpStorm') !== false) {
		$skipped++;
		continue;
	}
	
	if ($checkOnly) {
		$missing[] = $short;
		continue;
	}
	
	$header = $language === 'php'
		? phpHeader($projectName, $user, $date, $time)
		: ($language === 'python'
			? hashHeader($projectName, $user, $date, $time)
			: slashHeader($projectName, $user, $date, $time));
	
	$updated = insertHeader($source, $language, $header);
	
	if ($updated === null) {
		$failed[] = $short;
		continue;
	}
	
	// 保持无 BOM 的 UTF-8 与原有 LF 行尾。
	file_put_contents($path, $updated);
	$inserted++;
}

if ($checkOnly) {
	printf('待处理文件总数：%d｜已有头部：%d｜缺失：%d%s', count($files), $skipped, count($missing), PHP_EOL);
	
	foreach (array_slice($missing, 0, 30) as $one) {
		echo '  - ' . $one . PHP_EOL;
	}
	
	if (count($missing) > 30) {
		printf('  ... 其余 %d 项%s', count($missing) - 30, PHP_EOL);
	}
	
	exit($missing === [] ? 0 : 1);
}

printf('文件总数：%d｜新插入：%d｜已存在跳过：%d｜无法定位锚点：%d%s',
	count($files), $inserted, $skipped, count($failed), PHP_EOL);

foreach ($failed as $one) {
	echo '  未处理（锚点缺失）: ' . $one . PHP_EOL;
}

exit($failed === [] ? 0 : 1);
