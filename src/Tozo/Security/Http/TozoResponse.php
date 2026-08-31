<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * TozoResponse
 *
 * 文件功能：
 * - HttpClient 的轻量响应 DTO，解耦具体 HTTP 实现（Guzzle/Symfony/测试桩）
 * - Header 名称统一保留原始大小写，读取时大小写不敏感
 */

namespace Tozo\Security\Http;

class TozoResponse
{
	/**
	 * HTTP 状态码，原样透传传输层结果，SDK 不做任何改写。
	 * 业务含义由调用方判定：2xx 放行、5xx 触发重试策略等。
	 * 需要注意的是：响应完整性验证失败时不会构造本对象而是直接抛异常，
	 * 因此拿到本对象即意味着（在 required=true 前提下）Body 已通过验证。
	 *
	 * @var int
	 */
	private $status;
	
	/**
	 * 响应 Header 映射，保留服务端返回的原始大小写。
	 * 保留原样而不统一小写，是为了让 signed 模式能按原名读取响应签名头；
	 * 读取统一走 header() 做大小写不敏感匹配，避免网关规范化差异影响取值。
	 * 值可能是字符串或数组——同名头重复出现时为数组形态。
	 *
	 * @var array<string,string|array>
	 */
	private $headers;
	
	/**
	 * @var string 已通过响应完整性验证的 Body（未要求验证时为原始 Body）。
	 */
	private $body;
	
	/**
	 * 构造响应 DTO。
	 *
	 * 使用范围：HttpClient 收到传输结果、测试构造桩响应时调用。
	 * 适用场景：以框架无关形态承载状态/头/体三要素。
	 *
	 * 函数逻辑：
	 * 1. 保存三个字段。
	 *
	 * @param int $status HTTP 状态码｜响应状态。示例：200
	 * @param array $headers Header 数组｜名称=>值。示例：["Content-Type"=>"application/json"]
	 * @param string $body 响应 Body｜字节串。示例：'{"ok":true}'
	 * @return void 无返回值。
	 */
	public function __construct(int $status, array $headers, string $body)
	{
		$this->status  = $status;
		$this->headers = $headers;
		$this->body    = $body;
	}
	
	/**
	 * 返回 HTTP 状态码。
	 *
	 * 使用范围：调用方判定请求成败。
	 * 适用场景：2xx 放行、5xx 触发重试策略等业务分支。
	 *
	 * 函数逻辑：
	 * 1. 返回 status 属性。
	 *
	 * @return int 状态码。示例：200
	 */
	public function getStatus()
	{
		return $this->status;
	}
	
	/**
	 * 返回完整 Header 数组。
	 *
	 * 使用范围：signed 模式读取 X-Tozo-Response-Signature。
	 * 适用场景：完整性验证与链路追踪需要全部响应头。
	 *
	 * 函数逻辑：
	 * 1. 返回 headers 属性。
	 *
	 * @return array 名称=>值映射。示例：["X-Tozo-Response-Signature"=>"qE8f"]
	 */
	public function getHeaders()
	{
		return $this->headers;
	}
	
	/**
	 * 返回响应 Body 字节。
	 *
	 * 使用范围：业务层消费已验证内容。
	 * 适用场景：encrypted 模式下此值已是解密明文。
	 *
	 * 函数逻辑：
	 * 1. 返回 body 属性。
	 *
	 * @return string Body 字节。示例：'{"ok":true}'
	 */
	public function getBody()
	{
		return $this->body;
	}
	
	/**
	 * 大小写不敏感读取单个 Header。
	 *
	 * 使用范围：调用方读取自定义跟踪头。
	 * 适用场景：网关大小写规范化差异不影响取值。
	 *
	 * 函数逻辑：
	 * 1. 遍历匹配 strcasecmp；数组值取首元素；未命中返回 default。
	 *
	 * @param string $name 目标 Header 名｜标准名。示例："X-Request-Id"
	 * @param mixed $default 缺省返回值｜未命中时。示例：null
	 * @return mixed Header 值或缺省值。
	 */
	public function header(string $name, $default = null)
	{
		foreach ($this->headers as $key => $value) {
			if (strcasecmp((string)$key, $name) === 0) {
				return is_array($value) ? reset($value) : $value;
			}
		}
		
		return $default;
	}
	
	/**
	 * 将 Body 解析为数组。
	 *
	 * 使用范围：业务层消费 JSON 响应。
	 * 适用场景：替代手动 json_decode 并集中处理非法 JSON。
	 *
	 * 函数逻辑：
	 * 1. json_decode 关联模式；非数组抛 InvalidArgumentException。
	 *
	 * @return array 解码后的关联数组。示例：["ok"=>true]
	 * @throws \InvalidArgumentException Body 非法 JSON。
	 */
	public function json()
	{
		$decoded = json_decode($this->body, true);
		if (!is_array($decoded)) {
			throw new \InvalidArgumentException('Response body is not valid JSON');
		}
		
		return $decoded;
	}
}
