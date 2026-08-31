<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 类成员注释覆盖率审计工具
 *
 * 文件功能：
 * - 审计 src/tests 下每个「类属性」与「类常量」是否具备紧邻的中文注释
 * - 审计 config 下每个配置键是否具备说明注释
 * - 输出缺失清单，供 composer run audit-members 与发布前检查使用
 *
 * 判定口径：
 * - 属性/常量：声明前必须紧邻 PHPDoc 块或行注释（中间只允许空白）
 * - 注释必须含中日韩统一表意文字，纯英文注释视为不达标（本项目要求中文注释）
 * - 配置键：所在行上方必须有注释行，或该行行尾带注释
 *
 * 安全边界：
 * - 只做静态文本分析，不加载被检查的代码
 */

$root = dirname(__DIR__);

$memberTotal          = 0;
$missingComment       = [];
$nonChineseComment    = [];
$configKeyTotal       = 0;
$missingConfigComment = [];

// T_READONLY 自 PHP 8.1 起才存在；本项目基线为 7.4，必须动态取值而非直接引用常量。
$readonlyToken = defined('T_READONLY') ? constant('T_READONLY') : -1;

/**
 * 判断字符串是否包含中文字符。
 *
 * @param string $text 待检测文本。
 * @return bool 含中日韩统一表意文字返回 true。
 */
function hasChinese(string $text)
{
    return preg_match('/[\x{4e00}-\x{9fff}]/u', $text) === 1;
}

// ---------- 1. 类属性与类常量 ----------
foreach (['src', 'tests'] as $directory) {
    $path = $root . DIRECTORY_SEPARATOR . $directory;
    if (!is_dir($path)) {
    	continue;
    }
    
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path)) as $file) {
    	if (!$file->isFile() || $file->getExtension() !== 'php') {
    		continue;
    	}
    	
    	$short  = str_replace($root, '', $file->getPathname());
    	$tokens = token_get_all((string)file_get_contents($file->getPathname()));
    	$count  = count($tokens);
    	
    	// 记录当前是否处于类体内，避免把函数内的 static 变量当作属性。
    	$braceDepth = 0;
    	$classDepth = -1;
    	
    	for ($i = 0; $i < $count; $i++) {
    		$token = $tokens[$i];
    		
    		if (!is_array($token)) {
    			if ($token === '{') {
    				$braceDepth++;
    			} elseif ($token === '}') {
    				if ($braceDepth === $classDepth) {
    					$classDepth = -1;
    				}
    				$braceDepth--;
    			}
    			continue;
    		}
    		
    		if (in_array($token[0], [T_CLASS, T_INTERFACE, T_TRAIT], true)) {
    			// 类体的大括号深度 = 当前深度 + 1。
    			$classDepth = $braceDepth + 1;
    			continue;
    		}
    		
    		$isVisibility = in_array($token[0], [T_PUBLIC, T_PROTECTED, T_PRIVATE], true);
    		$isConst      = $token[0] === T_CONST;
    		
    		if (!$isVisibility && !$isConst) {
    			continue;
    		}
    		
    		// 只审计类体直属成员。
    		if ($classDepth === -1 || $braceDepth !== $classDepth) {
    			continue;
    		}
    		
    		// 向后确认这是属性/常量声明而不是方法，并取得成员名。
    		//
    		// 两种形态的终止条件不同，必须分开处理：
    		//   const NAME = ...   → 取第一个 T_STRING
    		//   private $prop      → 取第一个 T_VARIABLE（类型声明中的 T_STRING 必须跳过）
    		$name     = null;
    		$isMethod = false;
    		for ($j = $i + 1; $j < $count; $j++) {
    			if (!is_array($tokens[$j])) {
    				// 遇到 ( 说明是方法；遇到 = 或 ; 说明已越过成员名。
    				if ($tokens[$j] === '(' || $tokens[$j] === '=' || $tokens[$j] === ';') {
    					break;
    				}
    				continue;
    			}
    			
    			if ($tokens[$j][0] === T_FUNCTION) {
    				$isMethod = true;
    				break;
    			}
    			
    			if ($isConst) {
    				// 常量名就是第一个标识符。
    				if ($tokens[$j][0] === T_STRING) {
    					$name = $tokens[$j][1];
    					break;
    				}
    				
    				if ($tokens[$j][0] === T_WHITESPACE) {
    					continue;
    				}
    				
    				break;
    			}
    			
    			if ($tokens[$j][0] === T_VARIABLE) {
    				$name = $tokens[$j][1];
    				break;
    			}
    			
    			// 属性可带类型声明（含可空、联合与命名空间），这些 token 需跳过。
    			$skippable = [T_WHITESPACE, T_STATIC, T_FINAL, T_ABSTRACT, $readonlyToken, T_STRING, T_ARRAY, T_NS_SEPARATOR];
    			if (in_array($tokens[$j][0], $skippable, true)) {
    				continue;
    			}
    			
    			break;
    		}
    		
    		if ($isMethod || $name === null) {
    			continue;
    		}
    		
    		$memberTotal++;
    		
    		// 向上寻找紧邻注释（允许跨过空白与其他可见性修饰符）。
    		$comment = null;
    		for ($k = $i - 1; $k >= 0; $k--) {
    			if (!is_array($tokens[$k])) {
    				break;
    			}
    			
    			if (in_array($tokens[$k][0], [T_DOC_COMMENT, T_COMMENT], true)) {
    				$comment = $tokens[$k][1];
    				break;
    			}
    			
    			$passthrough = [T_WHITESPACE, T_PUBLIC, T_PROTECTED, T_PRIVATE, T_STATIC, T_FINAL, T_ABSTRACT, $readonlyToken, T_CONST];
    			if (in_array($tokens[$k][0], $passthrough, true)) {
    				continue;
    			}
    			
    			break;
    		}
    		
    		$label = $short . ' :: ' . $name . ' (L' . $token[2] . ')';
    		
    		if ($comment === null) {
    			$missingComment[] = $label;
    			continue;
    		}
    		
    		if (!hasChinese($comment)) {
    			$nonChineseComment[] = $label;
    		}
    	}
    }
}

// ---------- 2. 配置文件键 ----------
$configFiles = glob($root . '/config/*.php') ?: [];

foreach ($configFiles as $configFile) {
    $short = str_replace($root, '', $configFile);
    $lines = explode("\n", (string)file_get_contents($configFile));
    
    foreach ($lines as $index => $line) {
    	// 匹配形如 'key' => 的配置键行。
    	if (preg_match("/^\s*'([^']+)'\s*=>/", $line, $matches) !== 1) {
    		continue;
    	}
    	
    	$configKeyTotal++;
    	
    	// 行尾注释算达标。
    	if (strpos($line, '//') !== false && hasChinese($line)) {
    		continue;
    	}
    	
    	// 向上找最近的非空行，必须是注释且含中文。
    	$documented = false;
    	for ($k = $index - 1; $k >= 0; $k--) {
    		$above = trim($lines[$k]);
    		
    		if ($above === '') {
    			continue;
    		}
    		
    		$isCommentLine = strncmp($above, '//', 2) === 0
    			|| strncmp($above, '*', 1) === 0
    			|| strncmp($above, '/*', 2) === 0;
    		
    		if ($isCommentLine && hasChinese($above)) {
    			$documented = true;
    		}
    		
    		// 遇到 [ 或 => 起始的结构行说明该键属于新块，向上追溯到此为止。
    		break;
    	}
    	
    	if (!$documented) {
    		$missingConfigComment[] = $short . ' :: ' . $matches[1] . ' (L' . ($index + 1) . ')';
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
function reportGroup(string $title, array $items, int $limit = 40)
{
    printf('%-34s %d%s', $title, count($items), PHP_EOL);
    
    foreach (array_slice($items, 0, $limit) as $item) {
    	echo '    - ' . $item . PHP_EOL;
    }
    
    if (count($items) > $limit) {
    	printf('    ... 其余 %d 项%s', count($items) - $limit, PHP_EOL);
    }
}

echo '===== 类成员与配置键注释覆盖率审计 =====' . PHP_EOL . PHP_EOL;
printf('类属性/常量总数                    %d%s', $memberTotal, PHP_EOL);
printf('配置键总数                         %d%s', $configKeyTotal, PHP_EOL);
echo PHP_EOL;

reportGroup('缺少注释的类属性/常量', $missingComment);
reportGroup('注释非中文的类属性/常量', $nonChineseComment);
reportGroup('缺少注释的配置键', $missingConfigComment);

$clean = $missingComment === [] && $nonChineseComment === [] && $missingConfigComment === [];

echo PHP_EOL . '结论：' . ($clean ? '全部成员与配置键均有中文注释' : '存在未达标项') . PHP_EOL;

exit($clean ? 0 : 1);
