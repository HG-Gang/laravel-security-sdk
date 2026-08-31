<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * CanonicalRequest
 *
 * 文件功能：
 * - 构造 Protocol v1 请求签名规范化串
 * - 固定字段顺序、分隔符与大小写规则，调用端与服务端必须产出完全一致的字节
 *
 * 规范化规则（Protocol v1 草案，正式冻结前以本实现为唯一参考）：
 * - 字段按固定顺序用 "\n" 连接：
 *   protocol_version / METHOD / path / query / content_type / body_sha256_hex /
 *   timestamp / nonce / client_id / target_service / key_id
 * - METHOD 统一大写；path 以 "/" 开头、解析 "." 与 ".." 点段、折叠连续 "/"、去尾部 "/"（根路径除外）
 * - query 以「线上原始 query 字符串」为唯一事实来源：按 & 拆对、按首个 = 拆键值、
 *   解码后用 rawurlencode 重新编码、整对按字节序排序后用 & 连接
 * - content_type 小写并去除参数部分（"; charset=..."）
 * - body 哈希为最终 wire-level Body 的 SHA-256 十六进制小写
 *
 * 安全边界：
 * - 签名原文不包含任何密钥材料
 * - 时间戳单位固定为秒；Nonce 由 SDK 内部 CSPRNG 生成
 * - query 规范化不依赖 PHP 数组语义：重复键与方括号键都按原始字节保留，
 *   不允许出现「不同 query 产出同一规范化串」的碰撞
 */

namespace Tozo\Security\Protocol;

class CanonicalRequest
{
    /**
     * 规范化串的首字段：协议版本。
     * 写入签名原文使协议升级天然导致旧签名失效，避免跨版本混用。
     */
    public const PROTOCOL_VERSION = '1';
    
    /**
     * 提取 query 键的顶层名称（去掉方括号路径）。
     *
     * 使用范围：HttpClient 合并 options.query 与 URL 原有 query 时判断覆盖关系。
     * 适用场景：options 以顶层键给出（如 filter），需要据此移除 URL 中 filter[status] 等同族参数。
     *
     * 函数逻辑：
     * 1. 截取首个 "[" 之前的部分；无方括号时返回原键。
     *
     * @param string $key 已解码的键名｜可能含方括号路径。示例："filter[status]"
     * @return string 顶层键名。示例："filter"
     */
    public static function topLevelQueryKey(string $key)
    {
        $bracket = strpos($key, '[');
        
        return $bracket === false ? $key : substr($key, 0, $bracket);
    }
    
    /**
     * 构造请求签名规范化串。
     *
     * 使用范围：HmacSha256Signer 的 sign/verify 双端共用；是 HMAC 的唯一输入。
     * 适用场景：签发端以请求上下文生成原文，验证端以 Header 元数据重建同一字节做常量时间比对。
     *
     * 函数逻辑：
     * 1. 将 11 个字段按固定顺序收集为数组。
     * 2. query 支持两种入口：字符串按原始字节规范化，数组按 http_build_query 展开后规范化。
     * 3. 以 "\n" 连接返回；body 字段即时计算 SHA-256 十六进制小写。
     *
     * @param string $method HTTP 方法｜统一转大写。示例："post"
     * @param string $path 请求路径｜内部规范化。示例："/api/orders/"
     * @param array|string $query 查询参数｜数组或原始 query 字符串，内部统一规范化。示例："tags=x&tags=y"
     * @param string|null $contentType 内容类型｜内部规范化，null 视为空。示例："application/json"
     * @param string $body 最终 wire Body｜参与 SHA-256 的原始字节。示例：'{"a":1}'
     * @param int $timestamp 时间戳(秒)｜Unix 秒级。示例：1700000000
     * @param string $nonce 一次性随机串｜32 位十六进制。示例："5f1c9e2a..."
     * @param string $clientId 客户端标识｜调用方 ID。示例："product-center"
     * @param string $targetService 目标服务｜接收方标识。示例："order-api"
     * @param string $keyId 密钥标识｜签名用途 key_id。示例："order-signing"
     * @return string 以 "\n" 连接的规范化串（UTF-8 字节）。示例：以换行符连接的 11 字段规范化串
     */
    public static function build(
        string $method,
        string $path,
               $query,
        string $contentType,
        string $body,
        int    $timestamp,
        string $nonce,
        string $clientId,
        string $targetService,
        string $keyId
    )
    {
        // query 双入口归一：字符串走原始字节路径，数组走 http_build_query 展开路径。
        $canonicalQuery = is_array($query)
            ? self::canonicalQuery($query)
            : self::canonicalQueryString((string)$query);
        
        $lines = [
            self::PROTOCOL_VERSION,
            strtoupper($method),
            self::normalizePath($path),
            $canonicalQuery,
            self::normalizeContentType($contentType),
            hash('sha256', $body),
            (string)$timestamp,
            $nonce,
            $clientId,
            $targetService,
            $keyId,
        ];
        
        return implode("\n", $lines);
    }
    
    /**
     * 规范化 PHP 数组形态的 query。
     *
     * 使用范围：调用方以 options.query 数组传参时（HttpClient 合并 URL 原有 query 后使用）。
     * 适用场景：业务只持有关联数组、尚未拼出 URL 时，需要与线上字节形态得到同一规范化结果。
     *
     * 函数逻辑：
     * 1. 空数组返回空串。
     * 2. 以 http_build_query(RFC3986) 生成与实际发送一致的线上字节（嵌套数组展开为方括号键）。
     * 3. 交给 canonicalQueryString 完成解码/重编码/排序，确保数组入口与字符串入口结果一致。
     *
     * @param array $query 查询参数｜键值数组，值可为标量或嵌套数组。示例：["b"=>"2","a"=>"1"]
     * @return string 规范化查询串；空参数返回 ""。示例："a=1&b=2"
     */
    public static function canonicalQuery(array $query)
    {
        if ($query === []) {
            return '';
        }
        
        // http_build_query 与 buildQueryString 使用同一展开规则，保证签名原文等于实际发送字节。
        return self::canonicalQueryString(self::buildQueryString($query));
    }
    
    /**
     * 规范化线上原始 query 字符串（Protocol v1 的 query 唯一事实来源）。
     *
     * 使用范围：入站中间件与出站 HttpClient 构造签名原文时共用；build() 接收字符串时内部调用。
     * 适用场景：请求携带重复键（?tags=x&tags=y）或方括号键（?filter[status]=open）时，
     *           双端必须由同一份原始字节推导出同一规范化串——不能先转成 PHP 数组，
     *           因为 PHP/Symfony 会把重复键折叠为最后一个值、把方括号键解析成嵌套数组，
     *           导致调用端与服务端签名原文不一致，或不同 query 折叠出相同结果。
     *
     * 函数逻辑：
     * 1. 去除前导 "?"；空串直接返回空串。
     * 2. 按 "&" 拆分为若干对，丢弃空段。
     * 3. 每对按「首个 =」拆分键值；无 "=" 时值视为空串。
     * 4. urldecode 解码（兼容 "+" 表示空格；字面加号须以 %2B 传输），
     *    再以 rawurlencode 重新编码，消除同一语义的多种编码写法。
     * 5. 整对字符串按字节序排序后用 "&" 连接，保证与参数顺序无关。
     *
     * @param string $rawQuery 原始 query 字符串｜URL 中 "?" 之后的字节，可含前导 "?"。示例："tags=y&tags=x&page=2"
     * @return string 规范化 query 串；无参数返回 ""。示例："page=2&tags=x&tags=y"
     */
    public static function canonicalQueryString(string $rawQuery)
    {
        $rawQuery = ltrim($rawQuery, '?');
        if ($rawQuery === '') {
            return '';
        }
        
        $pairs = [];
        foreach (explode('&', $rawQuery) as $segment) {
            if ($segment === '') {
                continue;
            }
            
            $split = explode('=', $segment, 2);
            // 键与值都先解码再重新编码：%20 与 + 归一为同一字节，%2B 仍还原为字面加号。
            $key   = rawurlencode(urldecode($split[0]));
            $value = rawurlencode(urldecode(isset($split[1]) ? $split[1] : ''));
            
            $pairs[] = $key . '=' . $value;
        }
        
        sort($pairs, SORT_STRING);
        
        return implode('&', $pairs);
    }
    
    /**
     * 把 PHP 数组渲染为实际发送的 query 字节串。
     *
     * 使用范围：HttpClient 拼装最终请求 URL、canonicalQuery 生成规范化输入时调用。
     * 适用场景：数组与线上字节必须一一对应——签名覆盖的 query 与实际传输的 query
     *           不能是两套渲染结果，否则服务端按收到的字节验签必然失败。
     *
     * 函数逻辑：
     * 1. 顺序列表（0..n 连续整数键）渲染为「重复键」形态：tag=one&tag=two。
     *    不使用 PHP 的 tag[0]=one，因为方括号索引是 PHP 特有语义，
     *    Go/Java/Python 实现会把它当作字面键名，破坏跨语言互通。
     * 2. 关联数组渲染为方括号嵌套键：filter[status]=open。
     *    这一层必须保留子键名，否则不同 query 会折叠出相同字节。
     * 3. 标量按 rawurlencode 编码；null 视为空串。
     *
     * @param array $query 查询参数｜键值数组，值可为标量、列表或关联数组。示例：["filter"=>["open","paid"]]
     * @return string 可直接拼接到 "?" 之后的字节串。示例："filter=open&filter=paid"
     */
    public static function buildQueryString(array $query)
    {
        $pairs = [];
        foreach ($query as $key => $value) {
            self::appendQueryPairs($pairs, (string)$key, $value);
        }
        
        return implode('&', $pairs);
    }
    
    /**
     * 递归渲染单个 query 键值为线上字节对。
     *
     * 使用范围：buildQueryString 内部递归调用。
     * 适用场景：值可能是标量、列表或嵌套关联数组三种形态，需要分别落到不同 wire 表示。
     *
     * 函数逻辑：
     * 1. 非数组：直接产出 rawurlencode(key)=rawurlencode(value)。
     * 2. 顺序列表：对每个元素复用同一个 key（重复键形态）。
     * 3. 关联数组：以 key[sub] 形式递归，保留完整子键路径。
     *
     * @param array $pairs 累积结果｜按引用追加已渲染的字节对。示例：["a=1"]
     * @param string $key 当前键名｜可能已含方括号路径。示例："filter[status]"
     * @param mixed $value 当前值｜标量、列表或关联数组。示例：["open","paid"]
     * @return void 无返回值；结果写入 $pairs。
     */
    private static function appendQueryPairs(array &$pairs, string $key, $value)
    {
        if (!is_array($value)) {
            $pairs[] = rawurlencode($key) . '=' . rawurlencode($value === null ? '' : (string)$value);
            
            return;
        }
        
        // 顺序列表用重复键表达，保持语言中立；关联数组保留子键名避免字节碰撞。
        $isList = array_keys($value) === range(0, count($value) - 1);
        
        foreach ($value as $subKey => $subValue) {
            self::appendQueryPairs(
                $pairs,
                $isList ? $key : $key . '[' . $subKey . ']',
                $subValue
            );
        }
    }
    
    /**
     * 规范化 HTTP path。
     *
     * 使用范围：签名规范化串与加密 AAD 构造时调用，双端必须一致。
     * 适用场景：调用方传 "/api/orders/"、服务端收到 "/api/orders" 或完整 URL 时归一为同一字节。
     *
     * 函数逻辑：
     * 1. 仅当输入带 scheme（http://…）时才走 parse_url 取 path；否则整串按路径处理。
     *    直接对 "//a//b" 调用 parse_url 会把 "//a" 当作 authority 而丢掉首段。
     * 2. 剥离 query 与 fragment，两者不参与 path 规范化。
     * 3. 折叠连续斜杠；解析 "." 与 ".." 点段（RFC 3986 §5.2.4），避免代理归一化后签名失配。
     * 4. 补前导 "/"；去尾斜杠（根路径除外）。
     *
     * @param string $path 请求路径｜可含完整 URL。示例："/api/orders/" 或 "https://host/api/orders"
     * @return string 规范化后的路径。示例："/api/orders"
     */
    public static function normalizePath(string $path)
    {
        // 只有明确带 scheme 的绝对 URL 才解析 authority；纯路径不能交给 parse_url，
        // 否则前导 "//" 会被识别为主机名并丢失第一段路径。
        if (preg_match('#^[A-Za-z][A-Za-z0-9+.\-]*://#', $path) === 1) {
            $parsed = parse_url($path);
            $path   = is_array($parsed) && isset($parsed['path']) ? $parsed['path'] : '/';
        }
        
        // query 与 fragment 不属于 path 规范化范围。
        $cut  = strcspn($path, '?#');
        $path = substr($path, 0, $cut);
        
        if ($path === '') {
            return '/';
        }
        
        // 折叠连续斜杠，统一为单一分隔符后再做点段解析。
        $path = (string)preg_replace('#/{2,}#', '/', $path);
        
        // 记录原始尾斜杠语义：点段解析会丢失该信息，但根路径之外统一去尾斜杠，无需回填。
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                // 空段来自前导/尾部斜杠；"." 表示当前层级，两者都不进入结果。
                continue;
            }
            
            if ($segment === '..') {
                // ".." 回退一层；已在根目录时忽略，避免逃出根路径。
                array_pop($segments);
                continue;
            }
            
            $segments[] = $segment;
        }
        
        return $segments === [] ? '/' : '/' . implode('/', $segments);
    }
    
    /**
     * 规范化 Content-Type。
     *
     * 使用范围：build() 组装规范化串第 5 字段时调用。
     * 适用场景：客户端带 "; charset=utf-8" 参数或大小写差异时不影响签名一致性。
     *
     * 函数逻辑：
     * 1. 截取分号前的主类型；trim 后转小写；空值返回空串。
     *
     * @param string|null $contentType 内容类型｜原始 Content-Type 头值。示例："Application/JSON; charset=utf-8"
     * @return string 规范化主类型。示例："application/json"
     */
    public static function normalizeContentType($contentType)
    {
        if ($contentType === null || $contentType === '') {
            return '';
        }
        
        $contentType = (string)$contentType;
        $semi        = strpos($contentType, ';');
        $main        = $semi === false ? $contentType : substr($contentType, 0, $semi);
        
        return strtolower(trim($main));
    }
}
