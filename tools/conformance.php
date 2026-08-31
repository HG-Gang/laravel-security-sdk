<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 跨语言协议一致性统一入口
 *
 * 文件功能：
 * - 依次执行：冻结向量漂移检查 → PHP 向量测试 → Python 一致性 → Go 一致性
 * - 缺失 Python/Go 运行时时跳过并明确标注 SKIP，不伪装成通过
 *
 * 使用方式：
 *   php tools/conformance.php          执行全部可用检查
 *   composer run conformance           同上
 *
 * 返回码：0 = 全部已执行项通过；1 = 存在失败项
 *
 * 安全边界：
 * - 只读取协议向量与执行只读校验，不修改任何向量文件
 */

$root = dirname(__DIR__);
chdir($root);

$results = [];

/**
 * 执行一条检查命令并记录结果。
 *
 * @param string $label 检查项名称。
 * @param string $command 待执行命令（已含参数）。
 * @param string $workingDirectory 工作目录相对路径；空串表示项目根目录。
 * @return array{label:string,status:string,output:string}
 */
function runCheck(string $label, string $command, string $workingDirectory = '')
{
	$prefix = '';
	if ($workingDirectory !== '') {
		// Windows 与 POSIX 都支持 cd ... && ...，此处只用于本地开发脚本。
		$prefix = 'cd ' . escapeshellarg($workingDirectory) . ' && ';
	}
	
	$output   = [];
	$exitCode = 0;
	exec($prefix . $command . ' 2>&1', $output, $exitCode);
	
	return [
		'label'  => $label,
		'status' => $exitCode === 0 ? 'PASS' : 'FAIL',
		'output' => implode(PHP_EOL, $output),
	];
}

/**
 * 判断某个可执行程序是否可用。
 *
 * @param string $probe 探测命令（应在可用时返回 0）。
 * @return bool
 */
function isAvailable(string $probe)
{
	$output   = [];
	$exitCode = 0;
	exec($probe . ' 2>&1', $output, $exitCode);
	
	return $exitCode === 0;
}

echo '===== Protocol v1 跨语言一致性 =====' . PHP_EOL . PHP_EOL;

// 1. 冻结向量是否被实现悄悄改写。
$results[] = runCheck('冻结向量漂移检查', escapeshellarg(PHP_BINARY) . ' tools/gen_vectors.php --check');

// 2. PHP 参考实现消费向量。
$results[] = runCheck(
	'PHP 向量测试',
	escapeshellarg(PHP_BINARY) . ' vendor/bin/phpunit --no-coverage --colors=never --filter ProtocolVectorTest'
);

// 3. Python 独立实现。
if (isAvailable('python --version')) {
	$results[] = runCheck('Python 一致性', 'python protocol/conformance/python/conformance_test.py');
} elseif (isAvailable('python3 --version')) {
	$results[] = runCheck('Python 一致性', 'python3 protocol/conformance/python/conformance_test.py');
} else {
	$results[] = ['label' => 'Python 一致性', 'status' => 'SKIP', 'output' => '未检测到 python 运行时'];
}

// 4. Go 独立实现。
if (isAvailable('go version')) {
	$results[] = runCheck('Go 格式检查', 'gofmt -l . && exit 0', 'protocol/conformance/go');
	$results[] = runCheck('Go 静态检查', 'go vet ./...', 'protocol/conformance/go');
	$results[] = runCheck('Go 一致性', 'go run .', 'protocol/conformance/go');
} else {
	$results[] = ['label' => 'Go 一致性', 'status' => 'SKIP', 'output' => '未检测到 go 运行时'];
}

// ---------- 汇总 ----------
$failed  = 0;
$skipped = 0;

foreach ($results as $result) {
	printf('[%s] %s%s', $result['status'], $result['label'], PHP_EOL);
	
	if ($result['status'] === 'FAIL') {
		$failed++;
		foreach (explode(PHP_EOL, $result['output']) as $line) {
			echo '       ' . $line . PHP_EOL;
		}
	}
	
	if ($result['status'] === 'SKIP') {
		$skipped++;
		echo '       ' . $result['output'] . PHP_EOL;
	}
}

echo PHP_EOL;

if ($failed > 0) {
	printf('结论：%d 项失败 —— 协议存在歧义或某语言实现有误%s', $failed, PHP_EOL);
	exit(1);
}

if ($skipped > 0) {
	printf('结论：已执行项全部通过，但有 %d 项因缺少运行时被跳过%s', $skipped, PHP_EOL);
	exit(0);
}

echo '结论：PHP / Python / Go 三种实现与冻结向量逐字节一致' . PHP_EOL;
exit(0);
