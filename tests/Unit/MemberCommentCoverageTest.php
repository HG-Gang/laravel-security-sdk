<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 类成员与配置键注释覆盖率测试
 *
 * 文件功能：
 * - 固化"每个类属性、每个类常量、每个配置键都必须有中文注释"这一项目要求
 * - 与 tools/audit_members.php 共用同一判定口径，但以测试形式纳入 CI 门禁
 *
 * 判定口径：
 * - 属性/常量：声明前必须紧邻注释块，且注释含中文（纯英文 @var 不达标）
 * - 配置键：所在行上方紧邻注释行，或该行行尾带中文注释
 *
 * 为什么用测试而不只靠工具脚本：
 * - 工具脚本需要手工执行；测试会随 composer run test 一起跑，
 *   新增属性时忘记写注释会立即失败而不是等到发布前检查
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;

class MemberCommentCoverageTest extends TestCase
{
    /**
     * src 与 tests 下每个类属性与类常量都必须有中文注释。
     */
    public function test_every_class_member_has_a_chinese_comment(){
        $missing = [];
        $nonChinese = [];
        $total = 0;

        foreach ($this->projectFiles(['src', 'tests']) as $file) {
            foreach ($this->classMembers($file) as $member) {
                $total++;

                if ($member['comment'] === null) {
                    $missing[] = $member['label'];
                    continue;
                }

                if (!$this->hasChinese($member['comment'])) {
                    $nonChinese[] = $member['label'];
                }
            }
        }

        // 有成员被扫描到，否则说明解析逻辑失效而非真的全部达标。
        $this->assertGreaterThan(100, $total, '扫描到的类成员过少，解析逻辑可能失效');

        $this->assertSame([], $missing, "以下类属性/常量缺少注释：\n" . implode("\n", $missing));
        $this->assertSame(
            [],
            $nonChinese,
            "以下类属性/常量的注释不含中文（本项目要求中文注释）：\n" . implode("\n", $nonChinese)
        );
    }

    /**
     * config 下每个配置键都必须有中文说明。
     */
    public function test_every_config_key_has_a_chinese_comment(){
        $missing = [];
        $total = 0;

        foreach (glob(dirname(__DIR__, 2) . '/config/*.php') ?: [] as $file) {
            $lines = explode("\n", (string) file_get_contents($file));
            $short = str_replace(dirname(__DIR__, 2), '', $file);

            foreach ($lines as $index => $line) {
                if (preg_match("/^\s*'([^']+)'\s*=>/", $line, $matches) !== 1) {
                    continue;
                }

                $total++;

                if ($this->configKeyDocumented($lines, $index, $line)) {
                    continue;
                }

                $missing[] = $short . ' :: ' . $matches[1] . ' (L' . ($index + 1) . ')';
            }
        }

        // 阈值本意是防止 glob 未匹配或正则失效，不是要求配置必须有多少个键。
        // 配置精简后包内只剩 service/environment/peers 三个键，真正的断言是下面那条
        // 「每个键都必须有中文说明」。
        $this->assertGreaterThan(2, $total, '扫描到的配置键过少，解析逻辑可能失效');
        $this->assertSame([], $missing, "以下配置键缺少中文说明：\n" . implode("\n", $missing));
    }

    /**
     * 判断某个配置键是否已有中文说明。
     *
     * 使用范围：test_every_config_key_has_a_chinese_comment 内部调用。
     * 适用场景：说明既可写在键的上一行，也可写在行尾。
     *
     * 函数逻辑：
     * 1. 行尾含 // 且含中文即达标。
     * 2. 否则向上找最近的非空行，必须是注释行且含中文。
     *
     * @param array $lines 配置文件全部行。
     * @param int $index 当前键所在行下标（从 0 起）。
     * @param string $line 当前行原文。
     * @return bool 已有中文说明返回 true。
     */
    private function configKeyDocumented(array $lines, int $index, string $line){
        if (strpos($line, '//') !== false && $this->hasChinese($line)) {
            return true;
        }

        for ($k = $index - 1; $k >= 0; $k--) {
            $above = trim($lines[$k]);

            if ($above === '') {
                continue;
            }

            $isComment = strncmp($above, '//', 2) === 0
                || strncmp($above, '*', 1) === 0
                || strncmp($above, '/*', 2) === 0;

            return $isComment && $this->hasChinese($above);
        }

        return false;
    }

    /**
     * 提取文件中所有类属性与类常量及其紧邻注释。
     *
     * 使用范围：test_every_class_member_has_a_chinese_comment 内部调用。
     * 适用场景：需要区分「类体直属成员」与「方法内 static 变量」，后者不在要求范围内。
     *
     * 函数逻辑：
     * 1. 跟踪大括号深度，只在类体深度上采集成员。
     * 2. const 取第一个标识符为名；可见性修饰符取第一个变量为名。
     * 3. 向上跨过空白与修饰符寻找紧邻的注释块。
     *
     * @param string $file 待解析文件绝对路径。
     * @return array<int,array{label:string,comment:string|null}> 成员列表。
     */
    private function classMembers(string $file){
        // T_READONLY 自 PHP 8.1 起才存在；基线为 7.4 必须动态取值。
        $readonlyToken = defined('T_READONLY') ? constant('T_READONLY') : -1;

        $tokens = token_get_all((string) file_get_contents($file));
        $count = count($tokens);
        $short = str_replace(dirname(__DIR__, 2), '', $file);

        $members = [];
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
                $classDepth = $braceDepth + 1;
                continue;
            }

            $isVisibility = in_array($token[0], [T_PUBLIC, T_PROTECTED, T_PRIVATE], true);
            $isConst = $token[0] === T_CONST;

            if ((!$isVisibility && !$isConst) || $classDepth === -1 || $braceDepth !== $classDepth) {
                continue;
            }

            $name = $this->memberName($tokens, $i, $count, $isConst);
            if ($name === null) {
                continue;
            }

            $members[] = [
                'label' => $short . ' :: ' . $name . ' (L' . $token[2] . ')',
                'comment' => $this->adjacentComment($tokens, $i, $readonlyToken),
            ];
        }

        return $members;
    }

    /**
     * 取得成员名，若该声明实际是方法则返回 null。
     *
     * @param array $tokens token 序列。
     * @param int $index 修饰符或 const 所在下标。
     * @param int $count token 总数。
     * @param bool $isConst 是否为常量声明。
     * @return string|null 成员名；方法或解析失败返回 null。
     */
    private function memberName(array $tokens, int $index, int $count, bool $isConst){
        for ($j = $index + 1; $j < $count; $j++) {
            if (!is_array($tokens[$j])) {
                if ($tokens[$j] === '(' || $tokens[$j] === '=' || $tokens[$j] === ';') {
                    return null;
                }
                continue;
            }

            if ($tokens[$j][0] === T_FUNCTION) {
                return null;
            }

            if ($isConst) {
                if ($tokens[$j][0] === T_STRING) {
                    return $tokens[$j][1];
                }

                if ($tokens[$j][0] === T_WHITESPACE) {
                    continue;
                }

                return null;
            }

            if ($tokens[$j][0] === T_VARIABLE) {
                return $tokens[$j][1];
            }

            $skippable = [T_WHITESPACE, T_STATIC, T_FINAL, T_ABSTRACT, T_STRING, T_ARRAY, T_NS_SEPARATOR];
            if (in_array($tokens[$j][0], $skippable, true)) {
                continue;
            }

            return null;
        }

        return null;
    }

    /**
     * 向上查找紧邻的注释块。
     *
     * @param array $tokens token 序列。
     * @param int $index 成员声明起始下标。
     * @param int $readonlyToken T_READONLY 的实际值（7.4 下为 -1）。
     * @return string|null 注释原文；无紧邻注释返回 null。
     */
    private function adjacentComment(array $tokens, int $index, int $readonlyToken){
        for ($k = $index - 1; $k >= 0; $k--) {
            if (!is_array($tokens[$k])) {
                return null;
            }

            if (in_array($tokens[$k][0], [T_DOC_COMMENT, T_COMMENT], true)) {
                return $tokens[$k][1];
            }

            $passthrough = [
                T_WHITESPACE, T_PUBLIC, T_PROTECTED, T_PRIVATE,
                T_STATIC, T_FINAL, T_ABSTRACT, $readonlyToken, T_CONST,
            ];

            if (in_array($tokens[$k][0], $passthrough, true)) {
                continue;
            }

            return null;
        }

        return null;
    }

    /**
     * 判断文本是否含中日韩统一表意文字。
     *
     * @param string $text 待检测文本。
     * @return bool 含中文返回 true。
     */
    private function hasChinese(string $text){
        return preg_match('/[\x{4e00}-\x{9fff}]/u', $text) === 1;
    }

    /**
     * 收集指定目录下的全部 PHP 文件。
     *
     * @param array $directories 相对项目根的目录名列表。
     * @return string[] 绝对路径列表（已排序，保证结果稳定）。
     */
    private function projectFiles(array $directories){
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
