<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;

/**
 * 校验项目自有 PHP 文件的公开声明风格。
 *
 * 返回类型和 nullable 参数类型会增加当前项目不需要的声明复杂度；
 * 该测试把约定固化，避免后续新增方法重新引入这两类写法。
 */
class ApiStyleTest extends TestCase
{
    public function test_project_functions_have_no_return_or_nullable_parameter_types(){
        $root = dirname(__DIR__, 2);
        $files = [];
        foreach (['src', 'tests', 'config', 'tools'] as $directory) {
            $files = array_merge($files, $this->phpFiles($root . '/' . $directory));
        }

        $violations = [];
        foreach ($files as $file) {
            $tokens = token_get_all((string) file_get_contents($file));
            $count = count($tokens);

            for ($index = 0; $index < $count; $index++) {
                if (!is_array($tokens[$index]) || $tokens[$index][0] !== T_FUNCTION) {
                    continue;
                }

                $open = $this->nextFunctionParameterToken($tokens, $index + 1);
                if ($open === null) {
                    continue;
                }

                [$close, $parameterText] = $this->functionParameterRange($tokens, $open);
                if ($close === null) {
                    $violations[] = $file . ': malformed function parameter list';
                    continue;
                }

                if (strpos($parameterText, '?') !== false) {
                    $violations[] = $file . ': nullable parameter type';
                }

                $after = $this->nextSignificantToken($tokens, $close + 1);
                if ($after !== null && $tokens[$after] === ':') {
                    $violations[] = $file . ': return type declaration';
                }
            }
        }

        $this->assertSame([], $violations, implode("\n", $violations));
    }

    private function phpFiles(string $directory){
        $files = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory));

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        sort($files);

        return $files;
    }

    private function nextSignificantToken(array $tokens, int $index)
    {
        $count = count($tokens);
        while ($index < $count) {
            $token = $tokens[$index];
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                $index++;
                continue;
            }

            return $index;
        }

        return null;
    }

    private function nextFunctionParameterToken(array $tokens, int $index)
    {
        $count = count($tokens);
        while ($index < $count) {
            $token = $tokens[$index];
            $value = is_array($token) ? $token[1] : $token;
            if ($value === '(') {
                return $index;
            }

            if (is_array($token) && $token[0] === T_WHITESPACE) {
                $index++;
                continue;
            }

            if ($value === ';' || $value === '{') {
                return null;
            }

            $index++;
        }

        return null;
    }

    private function functionParameterRange(array $tokens, int $open){
        $depth = 0;
        $text = '';
        $count = count($tokens);

        for ($index = $open; $index < $count; $index++) {
            $token = $tokens[$index];
            $value = is_array($token) ? $token[1] : $token;

            if ($value === '(') {
                $depth++;
            } elseif ($value === ')') {
                $depth--;
                if ($depth === 0) {
                    return [$index, $text];
                }
            }

            if ($depth > 0 && $index !== $open) {
                $text .= $value;
            }
        }

        return [null, $text];
    }
}
