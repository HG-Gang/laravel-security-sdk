<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 文件头部标识块覆盖率测试
 *
 * 文件功能：
 * - 固化「每个文件必须有 PhpStorm 头部标识块」这一注释标准 v0.0.3 第 4 节要求
 * - 校验字段完整性与位置正确性，而不只是检查关键字是否出现
 *
 * 判定口径：
 * - 五个字段齐全：Created by PhpStorm / Project name / User / Date / Time
 * - Date 为 yyyy/mm/dd、Time 为 HH:mm
 * - PHP 文件中标识块必须位于 <?php 之后、namespace/declare 之前
 * - 标识块不替代文件级功能说明：两者都必须存在
 *
 * 安全边界：
 * - 只做静态文本检查，不加载被检查的代码
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;

class FileHeaderTest extends TestCase
{
    /**
     * 项目名固定值。与仓库目录名一致，随包分发后不应因下游目录改名而变化。
     */
    private const PROJECT_NAME = 'Tozo-security-sdk-php';

    /**
     * 每个 PHP 文件都必须有完整的头部标识块。
     */
    public function test_every_php_file_has_a_complete_header_block(){
        $missing = [];
        $incomplete = [];
        $total = 0;

        foreach ($this->phpFiles() as $file) {
            $total++;
            $short = str_replace(dirname(__DIR__, 2), '', $file);
            $head = $this->headSection($file);

            if (strpos($head, 'Created by PhpStorm') === false) {
                $missing[] = $short;
                continue;
            }

            foreach ($this->requiredPatterns() as $label => $pattern) {
                if (preg_match($pattern, $head) !== 1) {
                    $incomplete[] = $short . ' -> 缺少或格式错误：' . $label;
                }
            }
        }

        $this->assertGreaterThan(100, $total, '扫描到的 PHP 文件过少，收集逻辑可能失效');
        $this->assertSame([], $missing, "以下文件缺少头部标识块：\n" . implode("\n", $missing));
        $this->assertSame([], $incomplete, "以下文件头部字段不完整：\n" . implode("\n", $incomplete));
    }

    /**
     * 标识块必须在 namespace 与 declare 之前，否则不是文件头部。
     */
    public function test_header_precedes_namespace_declaration(){
        $violations = [];

        foreach ($this->phpFiles() as $file) {
            $source = (string) file_get_contents($file);
            $short = str_replace(dirname(__DIR__, 2), '', $file);

            $headerPosition = strpos($source, 'Created by PhpStorm');
            if ($headerPosition === false) {
                // 缺失情形由另一个用例报告，此处不重复。
                continue;
            }

            foreach (['namespace ', 'declare('] as $keyword) {
                $keywordPosition = strpos($source, $keyword);

                if ($keywordPosition !== false && $keywordPosition < $headerPosition) {
                    $violations[] = $short . ' -> 标识块出现在 ' . trim($keyword) . ' 之后';
                }
            }
        }

        $this->assertSame([], $violations, implode("\n", $violations));
    }

    /**
     * 标识块不得替代文件级功能说明：src 下每个文件都要同时具备两块注释。
     */
    public function test_header_does_not_replace_file_level_docblock(){
        $missing = [];

        foreach ($this->phpFiles(['src']) as $file) {
            $source = (string) file_get_contents($file);
            $short = str_replace(dirname(__DIR__, 2), '', $file);

            // 文件级功能说明的标志：出现「文件功能」小节。
            if (strpos($source, '文件功能') === false) {
                $missing[] = $short;
            }
        }

        $this->assertSame(
            [],
            $missing,
            "以下文件只有标识块、缺少文件级功能说明：\n" . implode("\n", $missing)
        );
    }

    /**
     * 非 PHP 的协议一致性实现同样要求标识块（使用各语言注释语法）。
     */
    public function test_conformance_implementations_have_headers(){
        $directory = dirname(__DIR__, 2) . '/protocol/conformance';

        if (!is_dir($directory)) {
            $this->markTestSkipped('protocol/conformance 目录不存在');
        }

        $missing = [];
        $checked = 0;

        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory)) as $file) {
            if (!$file->isFile() || !in_array($file->getExtension(), ['py', 'go'], true)) {
                continue;
            }

            $checked++;
            $source = (string) file_get_contents($file->getPathname());

            if (strpos($source, 'Created by PhpStorm') === false) {
                $missing[] = str_replace(dirname(__DIR__, 2), '', $file->getPathname());
            }
        }

        $this->assertGreaterThan(0, $checked, '未找到任何 Python/Go 一致性实现文件');
        $this->assertSame([], $missing, "以下文件缺少头部标识块：\n" . implode("\n", $missing));
    }

    /**
     * 头部块必须声明的字段及其格式。
     *
     * 使用范围：test_every_php_file_has_a_complete_header_block 内部调用。
     * 适用场景：只检查关键字存在无法发现"日期写成 2026-08-28"这类格式偏差。
     *
     * @return array<string,string> 字段名 => 匹配正则。
     */
    private function requiredPatterns(){
        return [
            'Project name' => '/Project name ' . preg_quote(self::PROJECT_NAME, '/') . '\./',
            'User' => '/User:\s*\S+/',
            'Date（yyyy\/mm\/dd）' => '#Date:\s*\d{4}/\d{2}/\d{2}#',
            'Time（HH:mm）' => '/Time:\s*\d{2}:\d{2}/',
        ];
    }

    /**
     * 取文件前若干行作为头部检查范围。
     *
     * 使用范围：字段完整性校验。
     * 适用场景：标识块固定在文件开头，只需检查前部区域即可，避免误匹配正文内容。
     *
     * @param string $file 文件绝对路径。
     * @return string 前 15 行拼接的文本。
     */
    private function headSection(string $file){
        $lines = explode("\n", (string) file_get_contents($file));

        return implode("\n", array_slice($lines, 0, 15));
    }

    /**
     * 收集待检查的 PHP 文件。
     *
     * @param array $directories 相对项目根的目录名列表；缺省覆盖全部受管目录。
     * @return string[] 绝对路径列表（已排序，保证结果稳定）。
     */
    private function phpFiles(array $directories = ['src', 'tests', 'config', 'tools']){
        $root = dirname(__DIR__, 2);
        $files = [];

        foreach ($directories as $directory) {
            $path = $root . '/' . $directory;
            if (!is_dir($path)) {
                continue;
            }

            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path)) as $file) {
                if ($file->isFile() && $file->getExtension() === 'php') {
                    $files[] = $file->getPathname();
                }
            }
        }

        sort($files);

        return $files;
    }
}
