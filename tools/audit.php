<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 代码规范自查工具
 *
 * 文件功能：
 * - 按 docs/中文注释标准-v0.0.3.md 校验 src 方法级注释完整性
 * - 校验 src / tests / config / tools：UTF-8 BOM、Tab 缩进、孤立 PHPDoc 块、未使用 use 导入
 * - 供 composer run audit 与发布前检查调用，返回码 0=全部通过
 *
 * 校验口径：
 * - src 下每个具名方法必须有 PHPDoc，且 @param 覆盖全部签名参数、非构造器需 @return
 * - tests 下不强制方法注释（注释标准 §10：测试名优先表达行为）
 *
 * 安全边界：
 * - 只做静态文本分析，不加载被检查的代码、不读取密钥
 */

$root        = dirname(__DIR__);
$directories = ['src', 'tests', 'config', 'tools'];

$methodTotal   = 0;
$missingDoc    = [];
$missingParam  = [];
$missingReturn = [];
$bomFiles      = [];
$tabFiles      = [];
$orphanBlocks  = [];
$unusedImports = [];

foreach ($directories as $directory) {
    $path = $root . DIRECTORY_SEPARATOR . $directory;
    if (!is_dir($path)) {
    	continue;
    }
    
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path)) as $file) {
    	if (!$file->isFile() || $file->getExtension() !== 'php') {
    		continue;
    	}
    	
    	$filePath = $file->getPathname();
    	$short    = str_replace($root, '', $filePath);
    	$source   = (string)file_get_contents($filePath);
    	
    	// BOM 会在 Laravel 中产生提前输出，破坏 header() 调用。
    	if (strncmp($source, "\xEF\xBB\xBF", 3) === 0) {
    		$bomFiles[] = $short;
    	}
    	
    	$lines = explode("\n", $source);
    	
    	foreach ($lines as $line) {
    		if (strncmp($line, "\t", 1) === 0) {
    			$tabFiles[] = $short;
    			break;
    		}
    	}
    	
    	// 孤立 PHPDoc：一个块紧接另一个块，说明前者没有挂到任何声明上。
    	//
    	// 例外：文件头部的 PhpStorm 标识块本就位于文件级功能说明之前，
    	// 两块相邻是规定格式而非缺陷，必须排除，否则每个文件都会误报。
    	$lineCount = count($lines);
    	for ($i = 0; $i < $lineCount - 2; $i++) {
    		if (trim($lines[$i]) !== '*/' || trim($lines[$i + 1]) !== '' || trim($lines[$i + 2]) !== '/**') {
    			continue;
    		}
    		
    		// 回溯前一个块的起始位置，判断它是否为 PhpStorm 头部标识块。
    		$isFileHeader = false;
    		for ($k = $i; $k >= 0; $k--) {
    			if (strpos($lines[$k], 'Created by PhpStorm') !== false) {
    				$isFileHeader = true;
    				break;
    			}
    			
    			if (trim($lines[$k]) === '/**' && $k !== $i) {
    				break;
    			}
    		}
    		
    		if ($isFileHeader) {
    			continue;
    		}
    		
    		$orphanBlocks[] = $short . ':' . ($i + 1);
    	}
    	
    	// 未使用 use 导入：先剥离 use 段本身，再在剩余代码中查别名。
    	$body = (string)preg_replace('/^use\s+[^;]+;$/m', '', $source);
    	if (preg_match_all('/^use\s+([A-Za-z0-9_\\\\]+)(?:\s+as\s+(\w+))?;$/m', $source, $matches, PREG_SET_ORDER)) {
    		foreach ($matches as $one) {
    			if (isset($one[2]) && $one[2] !== '') {
    				$alias = $one[2];
    			} else {
    				// 根命名空间类（如 Throwable）无反斜杠，strrpos 返回 false，不能直接 +1。
    				$position = strrpos($one[1], '\\');
    				$alias    = $position === false ? $one[1] : substr($one[1], $position + 1);
    			}
    			
    			$pattern = '/(?<![A-Za-z0-9_\\\\])' . preg_quote($alias, '/') . '(?![A-Za-z0-9_])/';
    			if (preg_match($pattern, $body) !== 1) {
    				$unusedImports[] = $short . ': ' . $alias;
    			}
    		}
    	}
    	
    	// 方法注释只对 src 强校验；迭代器可能混用分隔符，先归一化再判断。
    	if (strpos(str_replace('\\', '/', $filePath), '/src/') === false) {
    		continue;
    	}
    	
    	$tokens = token_get_all($source);
    	$count  = count($tokens);
    	
    	for ($i = 0; $i < $count; $i++) {
    		if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_FUNCTION) {
    			continue;
    		}
    		
    		$name = null;
    		for ($j = $i + 1; $j < $count; $j++) {
    			if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
    				$name = $tokens[$j][1];
    				break;
    			}
    			if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
    				continue;
    			}
    			if ($tokens[$j] === '(') {
    				break;
    			}
    		}
    		
    		// 匿名函数没有名字，不纳入方法注释统计。
    		if ($name === null) {
    			continue;
    		}
    		
    		$methodTotal++;
    		
    		$doc = null;
    		for ($k = $i - 1; $k >= 0; $k--) {
    			if (!is_array($tokens[$k])) {
    				break;
    			}
    			if ($tokens[$k][0] === T_DOC_COMMENT) {
    				$doc = $tokens[$k][1];
    				break;
    			}
    			$skippable = [T_WHITESPACE, T_PUBLIC, T_PROTECTED, T_PRIVATE, T_STATIC, T_FINAL, T_ABSTRACT];
    			if (in_array($tokens[$k][0], $skippable, true)) {
    				continue;
    			}
    			break;
    		}
    		
    		if ($doc === null) {
    			$missingDoc[] = $short . '::' . $name . '()';
    			continue;
    		}
    		
    		$params = [];
    		$depth  = 0;
    		for ($p = $i; $p < $count; $p++) {
    			$value = is_array($tokens[$p]) ? $tokens[$p][1] : $tokens[$p];
    			if ($value === '(') {
    				$depth++;
    			} elseif ($value === ')') {
    				$depth--;
    				if ($depth === 0) {
    					break;
    				}
    			} elseif ($depth >= 1 && is_array($tokens[$p]) && $tokens[$p][0] === T_VARIABLE) {
    				$params[] = $tokens[$p][1];
    			}
    		}
    		
    		foreach ($params as $param) {
    			if (strpos($doc, '@param') === false || strpos($doc, $param) === false) {
    				$missingParam[] = $short . '::' . $name . '() -> ' . $param;
    			}
    		}
    		
    		if ($name !== '__construct' && strpos($doc, '@return') === false) {
    			$missingReturn[] = $short . '::' . $name . '()';
    		}
    	}
    }
}

/**
 * 输出一组检查结果。
 *
 * @param string $title 检查项名称。
 * @param array $items 命中项列表。
 * @param int $limit 最多展示条数。
 * @return void
 */
function reportGroup(string $title, array $items, int $limit = 15)
{
    $items = array_values(array_unique($items));
    printf("%-28s %d%s", $title, count($items), PHP_EOL);
    
    foreach (array_slice($items, 0, $limit) as $item) {
    	echo '    - ' . $item . PHP_EOL;
    }
    
    if (count($items) > $limit) {
    	printf('    ... 其余 %d 项%s', count($items) - $limit, PHP_EOL);
    }
}

echo '===== Tozo Security SDK 代码规范自查 =====' . PHP_EOL . PHP_EOL;
printf("src 具名方法总数             %d%s", $methodTotal, PHP_EOL);
reportGroup('缺少方法级 PHPDoc', $missingDoc);
reportGroup('@param 未覆盖签名参数', $missingParam);
reportGroup('缺少 @return', $missingReturn);
reportGroup('UTF-8 BOM 文件', $bomFiles);
reportGroup('Tab 缩进文件', $tabFiles);
reportGroup('孤立 PHPDoc 块', $orphanBlocks);
reportGroup('未使用 use 导入', $unusedImports);

$clean = $missingDoc === []
    && $missingParam === []
    && $missingReturn === []
    && $bomFiles === []
    && $tabFiles === []
    && $orphanBlocks === []
    && $unusedImports === [];

echo PHP_EOL . '结论：' . ($clean ? '全部检查项通过' : '存在未通过项') . PHP_EOL;

exit($clean ? 0 : 1);
