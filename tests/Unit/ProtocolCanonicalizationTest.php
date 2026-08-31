<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Protocol v1 规范化闭环测试
 *
 * 文件功能：
 * - 固定 query 规范化的「调用端字节 == 服务端字节」契约
 * - 固定 path 点段解析与前导双斜杠行为
 * - 证明不同 query 不会折叠出同一规范化串（签名唯一性）
 *
 * 安全边界：
 * - 这些用例失败意味着合法请求会被误判为 invalid_signature，
 *   或不同请求共享同一签名原文，属于协议级缺陷而非风格问题
 */

namespace Tozo\Security\Tests\Unit;

use Illuminate\Http\Request;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Tests\TestCase;

class ProtocolCanonicalizationTest extends TestCase
{
    /**
     * 调用端把 URL 规范化后发出，服务端从 QUERY_STRING 重新规范化，两者必须逐字节相等。
     *
     * @dataProvider queryProvider
     */
    public function test_client_and_server_derive_the_same_canonical_query(string $rawQuery){
        $url = 'https://order-api.test/api/orders?' . $rawQuery;

        // 调用端：把 query 规范化写回最终 URL（TozoHttpClient::urlWithQuery 的等价结果）。
        $clientCanonical = CanonicalRequest::canonicalQueryString($rawQuery);
        $sentUrl = $clientCanonical === ''
            ? 'https://order-api.test/api/orders'
            : 'https://order-api.test/api/orders?' . $clientCanonical;

        // 服务端：只看实际收到的 QUERY_STRING。
        $request = Request::create($sentUrl, 'GET');
        $serverCanonical = CanonicalRequest::canonicalQueryString(
            (string) $request->server->get('QUERY_STRING', '')
        );

        $this->assertSame(
            $clientCanonical,
            $serverCanonical,
            "query [{$rawQuery}] 在调用端与服务端产出了不同的签名原文"
        );
        $this->assertNotSame('', $url);
    }

    public function queryProvider(){
        return [
            'repeated key' => ['a=1&a=2'],
            'repeated key with others' => ['tags=x&tags=y&page=2'],
            'bracketed key' => ['filter%5Bstatus%5D=open'],
            'two bracketed keys' => ['filter%5Bstatus%5D=open&filter%5Btype%5D=a'],
            'plus as space' => ['q=hello+world'],
            'percent encoded space' => ['q=hello%20world'],
            'literal plus' => ['plus=%2B'],
            'empty value' => ['empty='],
            'no equals sign' => ['flag'],
            'utf8 value' => ['a=1&b=%E4%B8%AD%E6%96%87'],
            'empty query' => [''],
        ];
    }

    /**
     * 重复键不得被折叠：折叠会让服务端算出与调用端不同的原文。
     */
    public function test_repeated_query_keys_are_preserved(){
        $this->assertSame('a=1&a=2', CanonicalRequest::canonicalQueryString('a=2&a=1'));
        $this->assertSame('a=1&a=2', CanonicalRequest::canonicalQueryString('a=1&a=2'));
    }

    /**
     * 方括号子键必须保留：丢掉子键名会让不同 query 产出同一签名原文。
     */
    public function test_distinct_bracketed_queries_do_not_collide(){
        $first = CanonicalRequest::canonicalQueryString('filter%5Bstatus%5D=a&filter%5Btype%5D=open');
        $second = CanonicalRequest::canonicalQueryString('filter%5Bstatus%5D=open&filter%5Btype%5D=a');

        $this->assertNotSame($first, $second, '不同 query 折叠出了同一规范化串，签名不再唯一绑定 query');
    }

    /**
     * 规范化必须幂等：最终 URL 会被再次规范化，两次结果不同会导致验签失败。
     *
     * @dataProvider queryProvider
     */
    public function test_canonical_query_is_idempotent(string $rawQuery){
        $once = CanonicalRequest::canonicalQueryString($rawQuery);

        $this->assertSame($once, CanonicalRequest::canonicalQueryString($once));
    }

    /**
     * 数组入口与字符串入口必须产出同一结果，否则签名与实际发送字节会分叉。
     */
    public function test_array_and_string_entries_agree(){
        $query = ['filter' => ['status' => 'open'], 'page' => '2', 'tag' => ['one', 'two']];

        $this->assertSame(
            CanonicalRequest::canonicalQuery($query),
            CanonicalRequest::canonicalQueryString(CanonicalRequest::buildQueryString($query))
        );
    }

    /**
     * 顺序列表渲染为重复键而非 PHP 的方括号索引，保证跨语言实现可复现。
     */
    public function test_lists_render_as_repeated_keys(){
        $this->assertSame('tag=one&tag=two', CanonicalRequest::buildQueryString(['tag' => ['one', 'two']]));
    }

    /**
     * 关联数组保留子键名，避免字节碰撞。
     */
    public function test_associative_arrays_keep_sub_keys(){
        $this->assertSame(
            'filter%5Bstatus%5D=open',
            CanonicalRequest::buildQueryString(['filter' => ['status' => 'open']])
        );
    }

    /**
     * path 必须解析点段：代理若先归一化 ".." 再转发，未解析的一方会验签失败。
     *
     * @dataProvider pathProvider
     */
    public function test_path_normalization(string $input, string $expected){
        $this->assertSame($expected, CanonicalRequest::normalizePath($input));
    }

    public function pathProvider(){
        return [
            'empty' => ['', '/'],
            'root' => ['/', '/'],
            'duplicate slashes' => ['//a//b//', '/a/b'],
            'trailing slash' => ['/api/orders/', '/api/orders'],
            'parent segment' => ['/api/../admin', '/admin'],
            'current segment' => ['/a/./b', '/a/b'],
            'escape attempt stays at root' => ['/../../etc', '/etc'],
            'trailing parent' => ['/api/x/..', '/api'],
            'absolute url' => ['https://host/api/x?y=1', '/api/x'],
            'query stripped' => ['/api/x?y=1', '/api/x'],
            'fragment stripped' => ['/api/x#frag', '/api/x'],
        ];
    }

    /**
     * 前导双斜杠是路径的第一段，不能被 parse_url 当成主机名吞掉。
     */
    public function test_leading_double_slash_is_not_treated_as_host(){
        $this->assertSame('/a/b', CanonicalRequest::normalizePath('//a//b//'));
    }

    /**
     * 规范化串字段数与顺序固定为 11 项，跨语言实现以此为准。
     */
    public function test_canonical_string_has_eleven_ordered_fields(){
        $canonical = CanonicalRequest::build(
            'post',
            '/api/orders/',
            'b=2&a=1',
            'Application/JSON; charset=utf-8',
            '{"sku":"A-1"}',
            1700000000,
            str_repeat('a', 32),
            'product-center',
            'order-api',
            'order-signing'
        );

        $lines = explode("\n", $canonical);

        $this->assertCount(11, $lines);
        $this->assertSame('1', $lines[0]);
        $this->assertSame('POST', $lines[1]);
        $this->assertSame('/api/orders', $lines[2]);
        $this->assertSame('a=1&b=2', $lines[3]);
        $this->assertSame('application/json', $lines[4]);
        $this->assertSame(hash('sha256', '{"sku":"A-1"}'), $lines[5]);
        $this->assertSame('1700000000', $lines[6]);
        $this->assertSame('product-center', $lines[8]);
        $this->assertSame('order-api', $lines[9]);
        $this->assertSame('order-signing', $lines[10]);
    }

    /**
     * 字符串与数组两种 query 入口在 build() 中必须得到同一规范化串。
     */
    public function test_build_accepts_both_query_forms(){
        $args = ['GET', '/x', null, '', '', 1700000000, 'n', 'c', 't', 'k'];

        $fromArray = CanonicalRequest::build(
            $args[0], $args[1], ['a' => '1', 'b' => '2'], $args[4], $args[4],
            $args[5], $args[6], $args[7], $args[8], $args[9]
        );
        $fromString = CanonicalRequest::build(
            $args[0], $args[1], 'b=2&a=1', $args[4], $args[4],
            $args[5], $args[6], $args[7], $args[8], $args[9]
        );

        $this->assertSame($fromArray, $fromString);
    }
}
