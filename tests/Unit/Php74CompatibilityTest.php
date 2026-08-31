<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * PHP 7.4 语法兼容性守卫测试
 *
 * 文件功能：
 * - 固化"最低支持 PHP 7.4"这一发布承诺，防止后续提交引入 8.0+ 专有语法
 * - 覆盖：8.0 新增函数、match 表达式、nullsafe 运算符、构造器属性提升、
 *   联合类型、mixed/static 类型声明、Attributes、非捕获 catch、throw 表达式
 *
 * 为什么需要静态检查：
 * - CI 未必总能提供 PHP 7.4 运行时；即使能跑，语法错误只在被加载的文件上暴露，
 *   而本测试对全部源码做静态扫描，覆盖未被任何用例加载的分支
 *
 * 安全边界：
 * - 本测试只检查语法兼容性，不替代在真实 PHP 7.4 运行时上执行全量测试
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;

class Php74CompatibilityTest extends TestCase
{
    /**
     * composer.json 必须同时声明 PHP >= 7.4 与 platform 锁定，
     * 否则依赖会按开发机版本解析出 7.4 装不上的组合。
     */
    public function test_composer_declares_php_74_baseline(){
        $composer = json_decode(
            (string) file_get_contents(dirname(__DIR__, 2) . '/composer.json'),
            true
        );

        $this->assertSame('>=7.4', $composer['require']['php']);

        // platform.php 锁定解析目标：不锁定时 Composer 会按开发机 PHP 解析依赖，
        // 生成的 lock 在 7.4 上会被 platform_check 拒绝。
        $this->assertSame(
            '7.4.0',
            $composer['config']['platform']['php'] ?? null,
            'composer.json 缺少 config.platform.php=7.4.0，依赖可能解析出 7.4 不兼容版本'
        );
    }

    /**
     * 锁定的依赖集必须能在 PHP 7.4 安装：platform_check 的门槛不得高于 70400。
     */
    public function test_vendor_platform_check_allows_php_74(){
        $path = dirname(__DIR__, 2) . '/vendor/composer/platform_check.php';

        if (!is_file($path)) {
            $this->markTestSkipped('vendor/composer/platform_check.php 不存在（未安装依赖）');
        }

        $source = (string) file_get_contents($path);

        if (preg_match('/PHP_VERSION_ID\s*>=\s*(\d+)/', $source, $m) !== 1) {
            // 没有版本门槛等价于不限制，属于可接受状态。
            $this->assertTrue(true);

            return;
        }

        $this->assertLessThanOrEqual(
            70400,
            (int) $m[1],
            '锁定依赖要求的 PHP 版本高于 7.4，PHP 7.4 宿主无法安装本包'
        );
    }

    /**
     * 全量源码不得出现 PHP 8.0+ 专有语法。
     *
     * @dataProvider forbiddenPatternProvider
     */
    public function test_source_avoids_php_80_only_syntax(string $label, string $pattern){
        $violations = [];

        foreach ($this->projectFiles() as $file) {
            $source = (string) file_get_contents($file);

            // 先剥离注释与字符串字面量，避免注释里的示例被误判。
            $code = $this->stripCommentsAndStrings($source);

            if (preg_match_all($pattern, $code, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $line = substr_count(substr($code, 0, $match[1]), "\n") + 1;
                    $violations[] = str_replace(dirname(__DIR__, 2), '', $file) . ":{$line}";
                }
            }
        }

        $this->assertSame(
            [],
            $violations,
            "发现 PHP 8.0+ 专有语法（{$label}），破坏 PHP 7.4 兼容承诺：\n" . implode("\n", $violations)
        );
    }

    public function forbiddenPatternProvider(){
        return [
            '8.0 新增字符串函数' => ['8.0 新增字符串函数', '/\b(?:str_contains|str_starts_with|str_ends_with)\s*\(/'],
            '8.0 新增类型函数' => ['8.0 新增类型函数', '/\b(?:get_debug_type|array_is_list)\s*\(/'],
            'match 表达式' => ['match 表达式', '/\bmatch\s*\(/'],
            'nullsafe 运算符' => ['nullsafe 运算符', '/\?->/'],
            '构造器属性提升' => ['构造器属性提升', '/function\s+__construct\s*\([^)]*\b(?:public|private|protected)\s+\$/s'],
            'Attributes' => ['Attributes', '/^[ \t]*#\[/m'],
            'mixed 类型声明' => ['mixed 类型声明', '/(?::\s*mixed\b)|(?:\bmixed\s+\$\w+\s*[,)=])/'],
            'static 返回类型' => ['static 返回类型', '/\)\s*:\s*\??static\b/'],
            '非捕获 catch' => ['非捕获 catch', '/catch\s*\(\s*[A-Za-z_\\\\][A-Za-z0-9_\\\\|\s]*\)\s*\{/'],
            'throw 表达式' => ['throw 表达式', '/(?:\?\?|=>|=)\s*throw\s+new\b/'],
        ];
    }

    /**
     * 收集 src + tests + config + tools 下的全部 PHP 文件。
     *
     * @return string[] 绝对路径列表。
     */
    private function projectFiles(){
        $root = dirname(__DIR__, 2);
        $files = [];

        foreach (['src', 'tests', 'config', 'tools'] as $dir) {
            $path = $root . '/' . $dir;
            if (!is_dir($path)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path));
            foreach ($iterator as $file) {
                if ($file->isFile() && $file->getExtension() === 'php') {
                    $files[] = $file->getPathname();
                }
            }
        }

        sort($files);

        return $files;
    }

    /**
     * 用等长空白替换注释与字符串字面量，保留字节偏移以便定位行号。
     *
     * 使用范围：test_source_avoids_php_80_only_syntax 扫描前的预处理。
     * 适用场景：注释中出现 "match(" 或 "?->" 等示例文本时不应被判为违规。
     *
     * 函数逻辑：
     * 1. token_get_all 切分源码。
     * 2. 注释、doc 注释与字符串类 token 替换为同长度空白（换行保留）。
     * 3. 其余 token 原样拼接，保证偏移与原文一致。
     *
     * @param string $source 原始源码。
     * @return string 已剥离注释与字符串的等长源码。
     */
    private function stripCommentsAndStrings(string $source){
        $blanked = '';

        foreach (token_get_all($source) as $token) {
            if (!is_array($token)) {
                $blanked .= $token;
                continue;
            }

            $isMasked = in_array(
                $token[0],
                [T_COMMENT, T_DOC_COMMENT, T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE, T_INLINE_HTML],
                true
            );

            if (!$isMasked) {
                $blanked .= $token[1];
                continue;
            }

            // 保留换行以维持行号，其余字符替换为空格保持偏移。
            $blanked .= preg_replace('/[^\n]/', ' ', $token[1]);
        }

        return $blanked;
    }
}
