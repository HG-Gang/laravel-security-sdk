<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Protocol v1 测试向量生成器
 *
 * 文件功能：
 * - 生成 protocol/test-vectors-v1.json，供各语言实现只读消费
 * - 结构化 query 输入强制序列化为 JSON 对象，避免 PHP 空数组被其他语言读成列表
 *
 * 使用方式：
 *   php tools/gen_vectors.php            重新生成向量文件
 *   php tools/gen_vectors.php --check     只校验现有文件与当前实现是否一致（不写盘）
 *
 * 安全边界：
 * - 向量中的 HMAC 密钥是公开示例值（32 个 k），禁止用于任何真实环境
 * - 向量一经协议评审冻结，修改任何 expected 值等于破坏性协议变更
 */

require __DIR__ . '/../vendor/autoload.php';

use Tozo\Security\Protocol\Encoding;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Protocol\CanonicalRequest;

$checkOnly = in_array('--check', $argv, true);

// 固定测试材料：全部为公开示例值。
$hmacKey       = str_repeat('k', 32);
$timestamp     = 1700000000;
$nonce         = '5f1c9e2a77b34d01ae95c8d012b64f7a';
$clientId      = 'product-center';
$targetService = 'order-api';
$keyId         = 'order-signing';

$vectors = [
	'_meta' => [
		'protocol_version' => CanonicalRequest::PROTOCOL_VERSION,
		'description'      => 'Tozo Security Protocol v1 固定测试向量；跨语言实现必须逐字节复现。',
		'hmac_key_ascii'   => $hmacKey,
		'notes'            => [
			'hmac_key_ascii 是公开示例密钥，仅用于测试向量，禁止用于任何真实环境。',
			'signature 为 base64url(hmac_sha256(canonical, hmac_key_ascii))，无 padding。',
			'canonical 字段以 \\n 连接 11 项，顺序固定不可调整。',
			'canonical_query_array[].input 恒为 JSON 对象；空 query 表示为 {}，'
			. '不使用 [] —— 空列表与空映射在多数语言中是不同类型。',
		],
	],
];

// ---------- 1. path 规范化 ----------
$paths = [
	'', '/', '/api/orders', '/api/orders/', '//a//b//', '/api/../admin', '/a/./b',
	'/../../etc', '/api/x/..', 'https://host/api/x?y=1', '/api/x?y=1', '/api/x#f',
	'/A/B', '/%E4%B8%AD%E6%96%87',
];
foreach ($paths as $path) {
	$vectors['normalize_path'][] = [
		'input'    => $path,
		'expected' => CanonicalRequest::normalizePath($path),
	];
}

// ---------- 2. query 规范化（原始字符串入口）----------
$queries = [
	'', 'a=1', 'b=2&a=1', 'a=1&a=2', 'tags=y&tags=x&page=2',
	'filter%5Bstatus%5D=open', 'filter%5Bstatus%5D=open&filter%5Btype%5D=a',
	'filter%5Bstatus%5D=a&filter%5Btype%5D=open',
	'q=hello+world', 'q=hello%20world', 'plus=%2B', 'empty=', 'flag',
	'a=1&b=%E4%B8%AD%E6%96%87', 'UPPER=X&upper=x',
];
foreach ($queries as $query) {
	$vectors['canonical_query_string'][] = [
		'input'    => $query,
		'expected' => CanonicalRequest::canonicalQueryString($query),
	];
}

// ---------- 3. query 规范化（结构化入口）----------
$arrayQueries = [
	[],
	['a' => '1'],
	['b' => '2', 'a' => '1'],
	['tag' => ['one', 'two']],
	['filter' => ['status' => 'open']],
	['filter' => ['status' => 'open', 'type' => 'a'], 'page' => '2'],
	['q' => 'hello world'],
	['q' => 'a+b'],
	['flag' => ''],
];
foreach ($arrayQueries as $query) {
	$vectors['canonical_query_array'][] = [
		// 强制对象形态：PHP 空数组默认序列化为 []，其他语言会读成列表而非映射。
		'input'    => (object)$query,
		'wire'     => CanonicalRequest::buildQueryString($query),
		'expected' => CanonicalRequest::canonicalQuery($query),
	];
}

// ---------- 4. Content-Type 规范化 ----------
$contentTypes = [
	'', 'application/json', 'Application/JSON; charset=utf-8',
	'TEXT/Plain ;x=1', 'application/x-www-form-urlencoded',
];
foreach ($contentTypes as $contentType) {
	$vectors['normalize_content_type'][] = [
		'input'    => $contentType,
		'expected' => CanonicalRequest::normalizeContentType($contentType),
	];
}

// ---------- 5. Base64URL ----------
foreach (['', 'a', 'ab', 'abc', 'abcd', "\x00\x01\xff", '中文'] as $raw) {
	$vectors['base64url_encode'][] = [
		'input_hex' => bin2hex($raw),
		'expected'  => Encoding::base64UrlEncode($raw),
	];
}
foreach (['qE8f', 'AAAA', 'qE8f=', 'qE+8f', '!!!', ''] as $encoded) {
	$decoded                       = Encoding::base64UrlDecode($encoded);
	$vectors['base64url_decode'][] = [
		'input'        => $encoded,
		'expected_hex' => $decoded === null ? null : bin2hex($decoded),
	];
}

// ---------- 6. 完整签名向量 ----------
$requests = [
	[
		'name'         => 'post json with body',
		'method'       => 'post', 'path' => '/api/orders/', 'query' => '',
		'content_type' => 'application/json; charset=utf-8', 'body' => '{"sku":"A-1"}',
	],
	[
		'name'         => 'get with repeated query keys',
		'method'       => 'GET', 'path' => '/api/orders', 'query' => 'tags=y&tags=x',
		'content_type' => '', 'body' => '',
	],
	[
		'name'         => 'get with bracketed query',
		'method'       => 'GET', 'path' => '/api/orders', 'query' => 'filter%5Bstatus%5D=open',
		'content_type' => '', 'body' => '',
	],
	[
		'name'         => 'delete empty body dot segments',
		'method'       => 'DELETE', 'path' => '/api/../api/orders/42', 'query' => '',
		'content_type' => '', 'body' => '',
	],
	[
		'name'         => 'put utf8 body',
		'method'       => 'PUT', 'path' => '/api/orders/42', 'query' => 'lang=zh',
		'content_type' => 'application/json', 'body' => '{"name":"中文名称"}',
	],
];

foreach ($requests as $request) {
	$canonical = CanonicalRequest::build(
		$request['method'],
		$request['path'],
		$request['query'],
		$request['content_type'],
		$request['body'],
		$timestamp,
		$nonce,
		$clientId,
		$targetService,
		$keyId
	);
	
	$vectors['signature'][] = [
		'name'        => $request['name'],
		'input'       => [
			'method'         => $request['method'],
			'path'           => $request['path'],
			'query'          => $request['query'],
			'content_type'   => $request['content_type'],
			'body'           => $request['body'],
			'timestamp'      => $timestamp,
			'nonce'          => $nonce,
			'client_id'      => $clientId,
			'target_service' => $targetService,
			'key_id'         => $keyId,
		],
		'canonical'   => $canonical,
		'body_sha256' => hash('sha256', $request['body']),
		'signature'   => Encoding::base64UrlEncode(hash_hmac('sha256', $canonical, $hmacKey, true)),
	];
}

// ---------- 7. AEAD AAD 向量 ----------
$aadCases = [
	['direction' => 'request', 'method' => 'POST', 'path' => '/api/orders', 'key_id' => 'order-request-encryption'],
	['direction' => 'response', 'method' => '', 'path' => '', 'key_id' => 'order-response-encryption'],
	['direction' => 'request', 'method' => 'get', 'path' => '/api/orders/', 'key_id' => 'k1'],
];
foreach ($aadCases as $case) {
	$vectors['aead_aad'][] = [
		'input'    => $case + ['client_id' => $clientId, 'target_service' => $targetService],
		'expected' => implode("\n", [
			AesGcmCipher::ENVELOPE_VERSION,
			$case['direction'],
			$clientId,
			$targetService,
			strtoupper($case['method']),
			CanonicalRequest::normalizePath($case['path']),
			$case['key_id'],
		]),
	];
}

// ---------- 8. 响应签名向量 ----------
$responseKeyId = 'order-response-signing';
foreach (['{"ok":true}', '', '{"order_id":42,"amount":"100.00"}'] as $body) {
	$canonical = implode("\n", [
		AesGcmCipher::ENVELOPE_VERSION,
		'response',
		$clientId,
		$targetService,
		hash('sha256', $body),
		$responseKeyId,
	]);
	
	$vectors['response_signature'][] = [
		'input'     => [
			'body'           => $body,
			'client_id'      => $clientId,
			'target_service' => $targetService,
			'key_id'         => $responseKeyId,
		],
		'canonical' => $canonical,
		'signature' => Encoding::base64UrlEncode(hash_hmac('sha256', $canonical, $hmacKey, true)),
	];
}

// ---------- 9. ReplayStore TTL 公式 ----------
foreach ([[300, 60, 5], [60, 5, 1], [900, 120, 10]] as $window) {
	$vectors['replay_ttl'][] = [
		'max_age_seconds'              => $window[0],
		'clock_skew_seconds'           => $window[1],
		'replay_safety_margin_seconds' => $window[2],
		'expected_ttl_seconds'         => $window[0] + 2 * $window[1] + $window[2],
	];
}

$path = __DIR__ . '/../protocol/test-vectors-v1.json';
$json = json_encode($vectors, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";

if ($checkOnly) {
	// --check 用于 CI：确认冻结文件仍与当前实现一致，不静默改写。
	if (!is_file($path)) {
		echo '向量文件不存在：' . $path . PHP_EOL;
		exit(1);
	}
	
	$existing = (string)file_get_contents($path);
	if ($existing === $json) {
		echo '向量文件与当前实现一致' . PHP_EOL;
		exit(0);
	}
	
	echo '向量文件与当前实现不一致：实现已改变协议行为。' . PHP_EOL;
	echo '若为有意的破坏性变更，必须升协议版本而不是覆盖 v1 向量。' . PHP_EOL;
	exit(1);
}

$directory = dirname($path);
if (!is_dir($directory)) {
	mkdir($directory, 0777, true);
}

file_put_contents($path, $json);

echo '已生成 protocol/test-vectors-v1.json' . PHP_EOL;
foreach ($vectors as $group => $items) {
	if ($group === '_meta') {
		continue;
	}
	printf('  %-26s %d 条%s', $group, count($items), PHP_EOL);
}
