<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Payload
 *
 * 文件功能：
 * - 表示一次安全通信中的完整负载（请求上下文 + 签名元数据 + 加密信封）
 * - 签名、加密、认证模块通过统一的键读写共享数据
 *
 * 约定键：
 * - method/path/query/content_type/body：请求上下文（body 为最终 wire-level 字节）
 * - timestamp/nonce/body_hash/signature/key_id/protocol_version：签名元数据
 * - envelope：AES-GCM 加密信封数组
 * - jwt / authorization_bearer / authorization：Token 载体
 */

namespace Tozo\Security;

class Payload
{
    /**
     * 负载数据，键为 Protocol v1 约定的字段名（method/path/query/body/client_id 等）。
     * 本类是**不可变值对象**：每次变换返回新实例而非就地修改，
     * 保证签名时读到的字节与最终发送的字节严格一致——就地修改会让
     * 「签名后又改了 Body」这类错误难以察觉。
     *
     * @var array
     */
    private $data;
    
    /**
     * 初始化负载数据。
     *
     * 使用范围：中间件构建入站载荷、HttpClient 构建出站载荷、测试夹具构造时调用。
     * 适用场景：为签名/加密/认证提供统一的数据载体，避免多模块间裸数组传参。
     *
     * 函数逻辑：
     * 1. 保存传入的关联数组作为初始数据。
     *
     * @param array $data 初始数据｜约定键值对。示例：['method'=>'POST','path'=>'/api/orders','body'=>'{}']
     * @return void 无返回值。
     */
    public function __construct(array $data = [])
    {
        $this->data = $data;
    }
    
    /**
     * 返回全部负载数据。
     *
     * 使用范围：Signer/Cipher/Middleware 读取上下文与元数据。
     * 适用场景：需要一次性遍历或整体重建载荷的场景。
     *
     * 函数逻辑：
     * 1. 返回 data 属性。
     *
     * @return array 关联数组。示例：['method'=>'POST','signature'=>'qE8f']
     */
    public function getData()
    {
        return $this->data;
    }
    
    /**
     * 整体替换负载数据。
     *
     * 使用范围：加密/解密阶段原子更新 Body 与元数据。
     * 适用场景：信封替换 Body 后同步 content_type 等关联字段。
     *
     * 函数逻辑：
     * 1. 以新数组整体覆盖 data。
     *
     * @param array $data 新数据｜完整键值对。示例：['body'=>'{"version":"1",...}']
     * @return void 无返回值。
     */
    public function setData(array $data)
    {
        $this->data = $data;
    }
    
    /**
     * 写入单个键。
     *
     * 使用范围：Signer 写入 timestamp/nonce/signature 等元数据。
     * 适用场景：局部更新而不触碰其他字段的细粒度修改。
     *
     * 函数逻辑：
     * 1. data[key]=value。
     *
     * @param string $key 数据键｜约定键名。示例："body_hash"
     * @param mixed $value 写入值｜任意标量或数组。示例："a1b2c3..."
     * @return void 无返回值。
     */
    public function set(string $key, $value)
    {
        $this->data[$key] = $value;
    }
    
    /**
     * 读取单个键并支持缺省值。
     *
     * 使用范围：Middleware/Verifier 提取载体与元数据。
     * 适用场景：替代调用方反复 isset 判断的样板代码。
     *
     * 函数逻辑：
     * 1. isset 则返回对应值，否则返回 default。
     *
     * @param string $key 数据键｜约定键名。示例："authorization_bearer"
     * @param mixed $default 缺省返回值｜未命中时。示例：null
     * @return mixed 键值或缺省值。示例："eyJhbGciOiJIUzI1NiJ9..."
     */
    public function get(string $key, $default = null)
    {
        return isset($this->data[$key]) ? $this->data[$key] : $default;
    }
    
    /**
     * 计算并记录 Body 的 SHA-256 哈希。
     *
     * 使用范围：出站构建阶段显式固化哈希。
     * 适用场景：签名原文必须绑定最终 wire Body 的一致性保障。
     *
     * 函数逻辑：
     * 1. data['body_hash']=hash('sha256',$body)。
     *
     * @param string $body 最终 wire Body｜原始字节。示例：'{"sku":"A-1"}'
     * @return void 无返回值。
     */
    public function normalizeBodyHash(string $body)
    {
        $this->data['body_hash'] = hash('sha256', $body);
    }
    
    /**
     * 返回已计算的 Body 哈希。
     *
     * 使用范围：验证端比对哈希前判空。
     * 适用场景：防御未签名载荷直接进入比对流程。
     *
     * 函数逻辑：
     * 1. 存在且为字符串则返回，否则 null。
     *
     * @return string|null 十六进制哈希；未计算时 null。示例："e3b0c442..."
     */
    public function getBodyHash()
    {
        return isset($this->data['body_hash']) && is_string($this->data['body_hash'])
            ? $this->data['body_hash']
            : null;
    }
}
