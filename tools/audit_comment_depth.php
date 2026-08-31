<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/30
 * Time: 07:10
 */

/**
 * 中文注释深度审查工具
 *
 * 文件功能：
 * - 按《中文注释标准-v0.0.3》第 5.1 节校验注释的**实质内容**，而非仅校验是否含中文
 * - 成员级：剥掉 @var/@param/@return 等机器标注后，剩余中文说明字数须达阈值
 * - 方法级：PHPDoc 须含「使用范围 / 适用场景 / 函数逻辑」三段说明
 *
 * 为什么需要独立于 audit_members.php：
 * - audit_members.php 的判定是「注释块含中日韩表意文字」，`@var string 状态码。`即可通过，
 *   但标准 5.1 明确写出这类只写类型的注释**不合格**
 * - 「极其详细」这一要求若无机器口径，128 个文件的量级下人工复核必然漏项；
 *   本工具把该要求变为可复核的退出码
 *
 * 判定局限（须知悉，不可当作注释质量的充分证明）：
 * - 只能度量说明的**长度**，无法判断说明是否真的回答了「为什么是这个值、违反会怎样」；
 *   字数达标不等于内容达标，人工审阅仍不可省略
 * - 因此本工具是下限门禁而非上限保证
 */

require __DIR__ . '/../vendor/autoload.php';

/**
 * 成员级注释的最少中文字数。
 *
 * 取 20 的依据：标准 5.1 的合格范例「调用方唯一标识。参与签名原文与 AEAD AAD 的绑定，
 * 同时作为入站 Profile 候选查找的不可信索引依据。」约 50 字，包含「是什么 + 为什么」两层；
 * 不合格范例仅 `@var string`，剥离标注后为 0 字。20 字是能容纳一句完整说明的下限，
 * 低于此几乎必然只是在复述成员名与类型。
 */
const MIN_MEMBER_CHARS = 20;

/**
 * 方法级 PHPDoc 必须出现的三个段落标记。
 *
 * 对应标准第 7 节要求方法注释必须回答的问题：这个方法在哪被调用（使用范围）、
 * 解决什么问题（适用场景）、内部分几步完成（函数逻辑）。
 */
const REQUIRED_METHOD_SECTIONS = ['使用范围', '适用场景', '函数逻辑'];

/**
 * 豁免方法级三段说明的目录。
 *
 * 测试方法的行为由方法名表达（标准第 9 节：测试名优先表达行为），
 * 强制三段会产生大量无信息量的样板注释，反而降低可读性。
 * 但测试文件的**成员级**注释不豁免——标准 5.6 明确要求测试替身的属性也要说明存在理由。
 */
const METHOD_EXEMPT_DIRECTORIES = ['tests'];

/**
 * 统计文本中的中日韩统一表意文字数量。
 *
 * 使用范围：成员级注释深度判定。
 * 适用场景：只数汉字，避免把类名、@var 标注、英文术语与标点算进说明字数——
 *           那样 `@var CacheRepository` 这类纯标注也会被判为达标。
 *
 * 函数逻辑：
 * 1. 用 Unicode 区间 4e00-9fff 匹配全部汉字并计数。
 *
 * @param string $text 待统计文本｜注释原文或剥离后的说明。示例："调用方唯一标识。"
 * @return int 汉字个数。示例：7
 */
function cjk_length(string $text)
{
    return (int)preg_match_all('/[\x{4e00}-\x{9fff}]/u', $text);
}

/**
 * 剥掉注释块中的机器标注与格式符号，只留人工撰写的说明。
 *
 * 使用范围：成员级注释深度判定前的预处理。
 * 适用场景：`@var int 保留秒数。` 这类注释里，`@var int` 是给 IDE 与静态分析看的，
 *           不构成对维护者的说明；必须剥掉后再量长度，否则标注本身会撑高字数。
 *
 * 函数逻辑：
 * 1. 逐行去掉 /**、*、*​/ 三类边框字符。
 * 2. 标注行只剥掉标签与紧随的类型（如 `@var int`），保留其后的说明文字——
 *    项目内大量成员把说明写在 @var 行上，整行丢弃会把这些说明误判为不存在。
 * 3. 其余行原样保留，最后拼接为说明文本。
 *
 * @param string $comment 注释块原文｜含边框与标注。示例："/**\n * @var int 保留秒数。\n *\/"
 * @return string 仅含人工说明的文本。示例："保留秒数。"
 */
function strip_annotations(string $comment)
{
    $kept = [];

    foreach (preg_split('/\r\n|\r|\n/', $comment) ?: [] as $line) {
        $line = trim($line);
        $line = preg_replace('#^/\*+#', '', (string)$line);
        $line = preg_replace('#\*+/$#', '', (string)$line);
        $line = preg_replace('#^\*+#', '', (string)$line);
        $line = trim((string)$line);

        if ($line === '') {
            continue;
        }

        // 标注行：剥掉 @tag 与紧随的类型表达式，保留其后的说明。
        // 类型表达式允许联合类型、数组泛型与命名空间，例如 array<string,Profile>|null。
        if (strncmp($line, '@', 1) === 0) {
            $line = (string)preg_replace('/^@[A-Za-z-]+\s*/', '', $line);
            $line = (string)preg_replace('/^[A-Za-z0-9_\\\\|\[\]<>,\s\{\}:]+/', '', $line);
            $line = trim($line);

            if ($line === '') {
                continue;
            }
        }

        $kept[] = $line;
    }

    return implode(' ', $kept);
}

/**
 * 收集指定目录下的全部 PHP 文件。
 *
 * 使用范围：run() 组装扫描清单。
 * 适用场景：与 lint/audit-style 保持同一扫描范围，避免各工具口径不一致。
 *
 * 函数逻辑：
 * 1. 递归遍历目录，只取扩展名为 php 的文件。
 * 2. 排序使输出顺序稳定，便于两次运行结果对比。
 *
 * @param string $directory 目录绝对路径｜扫描根。示例："D:\\project\\src"
 * @return string[] 文件绝对路径列表（已排序）。示例：["D:\\project\\src\\A.php"]
 */
function collect_php_files(string $directory)
{
    if (!is_dir($directory)) {
        return [];
    }

    $files = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory)) as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $files[] = $file->getPathname();
        }
    }

    sort($files);

    return $files;
}

/**
 * 向上查找声明前紧邻的注释块。
 *
 * 使用范围：scan_file 为每个成员与方法取注释。
 * 适用场景：注释与声明之间通常隔着空白与可见性修饰符，须跨过这些 token 再判断；
 *           跨过范围之外若不是注释，说明该声明没有紧邻注释。
 *
 * 函数逻辑：
 * 1. 从声明起始位置向前遍历。
 * 2. 遇到注释即返回其原文；遇到可跳过的 token 继续向前；遇到其他 token 判定为无注释。
 *
 * @param array $tokens token 序列｜token_get_all 结果。示例：token_get_all($source)
 * @param int $index 声明起始下标｜可见性修饰符或 function 所在位置。示例：42
 * @return string|null 注释原文；无紧邻注释返回 null。示例："/** 说明。 *\/"
 */
function adjacent_comment(array $tokens, int $index)
{
    // T_READONLY 自 PHP 8.1 起才存在；基线为 7.4 必须动态取值。
    $readonly = defined('T_READONLY') ? constant('T_READONLY') : -1;

    $passthrough = [
        T_WHITESPACE, T_PUBLIC, T_PROTECTED, T_PRIVATE,
        T_STATIC, T_FINAL, T_ABSTRACT, T_CONST, T_FUNCTION, $readonly,
    ];

    for ($k = $index - 1; $k >= 0; $k--) {
        if (!is_array($tokens[$k])) {
            return null;
        }

        if (in_array($tokens[$k][0], [T_DOC_COMMENT, T_COMMENT], true)) {
            return $tokens[$k][1];
        }

        if (in_array($tokens[$k][0], $passthrough, true)) {
            continue;
        }

        return null;
    }

    return null;
}

/**
 * 判定一处声明是方法还是类成员，并取其名称。
 *
 * 使用范围：scan_file 逐 token 分派。
 * 适用场景：可见性修饰符之后既可能是方法也可能是属性，两者的判定口径不同——
 *           方法查三段说明，成员查说明字数，必须先区分开。
 *
 * 函数逻辑：
 * 1. 从修饰符之后向前扫描：先遇 T_FUNCTION 即为方法，取其后的标识符为名。
 * 2. 先遇 T_VARIABLE 即为属性；const 声明取其后第一个标识符为名。
 * 3. 遇到 = 或 ; 说明已越过声明头，判定失败返回 null。
 *
 * @param array $tokens token 序列。示例：token_get_all($source)
 * @param int $index 声明起始下标。示例：42
 * @param bool $isConst 是否为 const 声明。示例：false
 * @return array|null [kind, name]｜kind 为 method 或 member；无法判定返回 null。示例：["member","$status"]
 */
function declaration_kind(array $tokens, int $index, bool $isConst)
{
    $count = count($tokens);

    for ($j = $index + 1; $j < $count; $j++) {
        $token = $tokens[$j];

        if (!is_array($token)) {
            // 括号说明这是方法签名的开始；等号或分号说明已越过声明头。
            if ($token === '(') {
                return null;
            }

            if ($token === '=' || $token === ';') {
                return null;
            }

            continue;
        }

        if ($token[0] === T_FUNCTION) {
            // 取 function 之后的第一个标识符作为方法名。
            for ($m = $j + 1; $m < $count; $m++) {
                if (is_array($tokens[$m]) && $tokens[$m][0] === T_STRING) {
                    return ['method', $tokens[$m][1]];
                }

                if (!is_array($tokens[$m]) && $tokens[$m] === '(') {
                    // 匿名函数没有名字，不纳入审查。
                    return null;
                }
            }

            return null;
        }

        if ($isConst) {
            if ($token[0] === T_STRING) {
                return ['member', $token[1]];
            }

            if ($token[0] === T_WHITESPACE) {
                continue;
            }

            return null;
        }

        if ($token[0] === T_VARIABLE) {
            return ['member', $token[1]];
        }

        // 类型声明、数组类型、命名空间分隔符等可跨过。
        if (in_array($token[0], [T_WHITESPACE, T_STATIC, T_FINAL, T_ABSTRACT, T_STRING, T_ARRAY, T_NS_SEPARATOR], true)) {
            continue;
        }

        return null;
    }

    return null;
}

/**
 * 扫描单个文件，返回其中所有未达标项。
 *
 * 使用范围：run() 逐文件调用。
 * 适用场景：只采集类体直属成员与方法；方法内的局部变量与匿名函数不在标准要求范围内。
 *
 * 函数逻辑：
 * 1. 跟踪大括号深度，只在类体深度上采集声明。
 * 2. 方法：校验三段说明是否齐全（豁免目录跳过）。
 * 3. 成员：剥离标注后校验中文说明字数。
 *
 * @param string $file 文件绝对路径。示例："D:\\project\\src\\A.php"
 * @param string $root 项目根绝对路径｜用于生成相对路径。示例："D:\\project"
 * @param bool $methodExempt 是否豁免方法三段说明。示例：true
 * @return array 未达标项列表｜每项含 label、kind、detail。示例：[["label"=>"/src/A.php :: $x (L10)","kind"=>"member","detail"=>"说明仅 3 字"]]
 */
function scan_file(string $file, string $root, bool $methodExempt)
{
    $source = (string)file_get_contents($file);
    $tokens = token_get_all($source);
    $count  = count($tokens);
    $short  = str_replace($root, '', $file);

    $problems   = [];
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
        $isConst      = $token[0] === T_CONST;

        if ((!$isVisibility && !$isConst) || $classDepth === -1 || $braceDepth !== $classDepth) {
            continue;
        }

        $declaration = declaration_kind($tokens, $i, $isConst);
        if ($declaration === null) {
            continue;
        }

        list($kind, $name) = $declaration;

        $label   = $short . ' :: ' . $name . ' (L' . $token[2] . ')';
        $comment = adjacent_comment($tokens, $i);

        if ($kind === 'method') {
            if ($methodExempt) {
                continue;
            }

            if ($comment === null) {
                $problems[] = ['label' => $label, 'kind' => 'method', 'detail' => '无 PHPDoc'];
                continue;
            }

            $missing = [];
            foreach (REQUIRED_METHOD_SECTIONS as $section) {
                if (strpos($comment, $section) === false) {
                    $missing[] = $section;
                }
            }

            if ($missing !== []) {
                $problems[] = [
                    'label'  => $label,
                    'kind'   => 'method',
                    'detail' => '缺段：' . implode('、', $missing),
                ];
            }

            continue;
        }

        if ($comment === null) {
            $problems[] = ['label' => $label, 'kind' => 'member', 'detail' => '无注释'];
            continue;
        }

        $chars = cjk_length(strip_annotations($comment));

        if ($chars < MIN_MEMBER_CHARS) {
            $problems[] = [
                'label'  => $label,
                'kind'   => 'member',
                'detail' => '剥离标注后仅 ' . $chars . ' 字（下限 ' . MIN_MEMBER_CHARS . '）',
            ];
        }
    }

    return $problems;
}

/**
 * 执行全量审查并输出报告。
 *
 * 使用范围：命令行入口。
 * 适用场景：composer audit-depth 与 CI 门禁；退出码非 0 时阻断发布。
 *
 * 函数逻辑：
 * 1. 按 src/tests/config/tools 四个目录收集文件，与其他审查工具保持同一范围。
 * 2. 逐文件扫描，按 member/method 两类分别计数。
 * 3. 输出统计表与未达标明细；--list 只输出明细便于逐项修复。
 *
 * @param bool $listOnly 明细模式开关｜true 时省略统计表。示例：false
 * @return int 进程退出码｜0 全部达标。示例：0
 */
function run(bool $listOnly)
{
    $root = dirname(__DIR__);

    $shallowMembers = [];
    $thinMethods    = [];
    $totalMembers   = 0;
    $totalMethods   = 0;
    $totalFiles     = 0;

    foreach (['src', 'tests', 'config', 'tools'] as $directory) {
        $methodExempt = in_array($directory, METHOD_EXEMPT_DIRECTORIES, true);

        foreach (collect_php_files($root . '/' . $directory) as $file) {
            $totalFiles++;

            foreach (scan_file($file, $root, $methodExempt) as $problem) {
                if ($problem['kind'] === 'member') {
                    $shallowMembers[] = $problem;
                } else {
                    $thinMethods[] = $problem;
                }
            }
        }
    }

    // 统计总量用于确认解析逻辑未失效：扫不到成员说明 token 解析出了问题，
    // 那种情况下「0 个未达标」是假通过。
    foreach (['src', 'tests', 'config', 'tools'] as $directory) {
        foreach (collect_php_files($root . '/' . $directory) as $file) {
            $tokens = token_get_all((string)file_get_contents($file));

            foreach ($tokens as $index => $token) {
                if (!is_array($token)) {
                    continue;
                }

                if ($token[0] === T_FUNCTION) {
                    $totalMethods++;
                }

                if (in_array($token[0], [T_PUBLIC, T_PROTECTED, T_PRIVATE, T_CONST], true)) {
                    $totalMembers++;
                }
            }
        }
    }

    if (!$listOnly) {
        echo '===== 中文注释深度审查（标准 v0.0.3 第 5.1 节）=====' . PHP_EOL . PHP_EOL;
        echo '扫描文件数                         ' . $totalFiles . PHP_EOL;
        echo '成员/方法声明 token 数             ' . $totalMembers . ' / ' . $totalMethods . PHP_EOL;
        echo PHP_EOL;
        echo '成员说明过浅（<' . MIN_MEMBER_CHARS . ' 字）        ' . count($shallowMembers) . PHP_EOL;
        echo '方法缺三段说明                     ' . count($thinMethods) . PHP_EOL;
        echo PHP_EOL;
    }

    foreach ([['成员说明过浅', $shallowMembers], ['方法缺三段说明', $thinMethods]] as list($title, $items)) {
        if ($items === []) {
            continue;
        }

        echo '--- ' . $title . '（' . count($items) . ' 项）---' . PHP_EOL;

        foreach ($items as $item) {
            echo '    - ' . $item['label'] . '  ' . $item['detail'] . PHP_EOL;
        }

        echo PHP_EOL;
    }

    if ($totalMembers < 100) {
        echo '结论：扫描到的声明过少，token 解析可能失效' . PHP_EOL;

        return 1;
    }

    if ($shallowMembers === [] && $thinMethods === []) {
        echo '结论：全部达标' . PHP_EOL;

        return 0;
    }

    echo '结论：存在未达标项' . PHP_EOL;

    return 1;
}

exit(run(in_array('--list', $argv, true)));
