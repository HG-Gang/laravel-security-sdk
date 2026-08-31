<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * HttpClientInterface
 *
 * 文件功能：
 * - 定义统一安全 HTTP Client 契约：自动签名、自动加密、自动附加 Token、响应完整性验证
 * - 返回框架解耦的 TozoResponse，便于测试与多传输实现
 */

namespace Tozo\Security\Contracts;

use Tozo\Security\Http\TozoResponse;
use Tozo\Security\Profile;

interface HttpClientInterface
{
    /**
     * GET 安全请求契约。
     *
     * 使用范围：只读接口调用方。
     * 适用场景：幂等查询仍需签名与防重放保护。
     *
     * 函数逻辑：
     * 1. 实现方执行统一出站流程（序列化→加密→签名→Header→发送→完整性→审计）。
     *
     * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders/42"
     * @param array $options 请求选项｜headers/query/request_id/body/http_options。示例：["query"=>["full"=>1]]
     * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
     * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
     */
    public function get(string $url, array $options = [], Profile $profile = null);
    
    /**
     * POST 安全请求契约。
     *
     * 使用范围：创建资源等写操作调用方。
     * 适用场景：Body 参与加密与签名的统一入口。
     *
     * 函数逻辑：
     * 1. 同 get 契约，$data 经确定性 JSON 序列化作为 Body。
     *
     * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders"
     * @param array $data 业务数据｜序列化体。示例：["sku"=>"A-1"]
     * @param array $options 请求选项｜同 get；http_options 可传 timeout/connect_timeout/verify。示例：[]
     * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
     * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
     */
    public function post(string $url, array $data = [], array $options = [], Profile $profile = null);
    
    /**
     * PUT 安全请求契约。
     *
     * 使用范围：全量更新操作调用方。
     * 适用场景：整体替换资源的统一安全入口。
     *
     * 函数逻辑：
     * 1. 同 post 契约，方法为 PUT。
     *
     * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders/42"
     * @param array $data 业务数据｜全量字段。示例：["sku"=>"A-2"]
     * @param array $options 请求选项｜同 get；http_options 可传 timeout/connect_timeout/verify。示例：[]
     * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
     * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
     */
    public function put(string $url, array $data = [], array $options = [], Profile $profile = null);
    
    /**
     * DELETE 安全请求契约。
     *
     * 使用范围：删除操作调用方。
     * 适用场景：无 Body 但签名仍绑定方法/路径/时间戳/Nonce。
     *
     * 函数逻辑：
     * 1. 同 get 契约，方法为 DELETE。
     *
     * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders/42"
     * @param array $options 请求选项｜同 get；http_options 可传 timeout/connect_timeout/verify。示例：[]
     * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
     * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
     */
    public function delete(string $url, array $options = [], Profile $profile = null);
    
    /**
     * PATCH 安全请求契约。
     *
     * 使用范围：部分更新操作调用方。
     * 适用场景：差异 Body 参与完整性证明，防局部篡改。
     *
     * 函数逻辑：
     * 1. 同 post 契约，方法为 PATCH。
     *
     * @param string $url 目标地址｜绝对 URL。示例："https://order-api.internal/api/orders/42"
     * @param array $data 业务数据｜差异字段。示例：["status"=>"cancelled"]
     * @param array $options 请求选项｜同 get；http_options 可传 timeout/connect_timeout/verify。示例：[]
     * @param Profile|null $profile 请求级 Profile｜null 用默认绑定。示例：null
     * @return TozoResponse 已验证响应。示例：TozoResponse(200, [], "{}")
     */
    public function patch(string $url, array $data = [], array $options = [], Profile $profile = null);
    
    /**
     * 按对端服务名选路契约。
     *
     * 使用范围：跨系统调用的推荐入口。
     * 适用场景：调用方只提供目标服务标识与相对路径，Profile 与根地址由配置推导。
     *
     * 函数逻辑：
     * 1. 实现方按选路表查找该目标服务的出站关系，缺失即抛配置异常。
     * 2. 返回绑定该关系的新实例，原实例状态不变。
     *
     * @param string $service 目标服务标识｜须为配置 peers 中声明的键。示例："pos-api"
     * @return static 已绑定该关系的新实例。示例：$client->to('pos-api')
     */
    public function to(string $service);
    
    /**
     * 返回默认出站 Profile 契约。
     *
     * 使用范围：调用方可观测当前信任关系。
     * 适用场景：多 Profile 应用确认缺省目标。
     *
     * 函数逻辑：
     * 1. 实现方返回当前绑定；未绑定为 null。
     *
     * @return Profile|null 默认出站 Profile。示例：默认出站 Profile 或 null
     */
    public function getProfile();
    
    /**
     * 绑定默认出站 Profile 契约。
     *
     * 使用范围：装配默认项或切换目标系统。
     * 适用场景：配置错误在绑定瞬间暴露。
     *
     * 函数逻辑：
     * 1. 实现方对非 null 输入先执行结构校验再保存。
     *
     * @param Profile|null $profile 出站 Profile｜null 解除绑定。示例：Profile::fromConfig(...)
     * @return void 无返回值。
     */
    public function setProfile(Profile $profile = null);
}
