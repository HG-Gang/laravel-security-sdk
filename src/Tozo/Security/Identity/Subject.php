<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * Subject
 *
 * 文件功能：
 * - 认证成功后统一返回的身份主体对象
 * - 字段全部来自密码学验证通过的 Token claims，不允许外部篡改
 *
 * 安全边界：
 * - subject_type 必须来自 Profile 白名单校验后的结果
 * - audience 内部统一为数组形态，避免 string/array 双态分支
 */

namespace Tozo\Security\Identity;

class Subject
{
    /**
     * 主体标识，形如 `subject_type:subject_id`（例 `service:product-center`）。
     * 这是被认证主体的唯一权威标识，来自已验签 Token 的 sub claim 或 signed_request
     * 模式下由 Profile 构造，业务层的授权判定与审计留痕都以它为准。
     * 类型前缀不可省略——同名 id 在不同主体类型间不产生任何等价关系。
     *
     * @var string
     */
    private $sub;

    /**
     * 客户端应用标识。取值优先级 client_id > azp > sub，因为不同签发方对
     * 「哪个应用发起了调用」使用的 claim 名不统一，这里归一为单一入口。
     * 与 sub 的区别：sub 是主体（谁），clientId 是发起调用的应用（用什么在调用），
     * 服务代表用户操作时两者不同。按 client 维度限流或审计时用它。
     *
     * @var string
     */
    private $clientId;

    /**
     * 签发者标识，来自 Token 的 iss claim。
     * 入站验证阶段已确认它命中 Profile 声明的允许签发者，因此到达业务层时是可信值。
     * 保留它的用途是多签发方体系下的审计溯源——记录这张令牌出自哪个授权系统。
     *
     * @var string
     */
    private $issuer;

    /**
     * 受众列表，来自 aud claim，已归一化为数组形态。
     * 归一化的原因：JWT 规范允许 aud 是字符串或数组两种形态，
     * 若不统一，下游每处做交集校验都要重复判断类型，漏判即等于跳过受众绑定。
     * 入站验证已确认与 Profile 声明的受众有交集；保留它供下游服务二次校验。
     *
     * @var string[]
     */
    private $audience;

    /**
     * 主体类型，取值 service（内部系统）/ partner（外部合作方）/ user（登录用户）。
     * 三类权限互不可替代：同名 Scope 在不同主体类型间不产生等价关系，
     * 因此授权判定必须同时看类型与 Scope，只看 Scope 会让合作方拿到内部系统的权限。
     * 缺省为 service，因为 SDK 的主用场景是内部系统互调。
     *
     * @var string
     */
    private $subjectType;
    
    /**
     * 已授予的 Scope 列表。兼容两种输入形态：数组，以及 OAuth 惯用的空格分隔字符串。
     * 这是**已授予**的权限而非**所需**的权限——判定放行由 ScopeAuthorizer 拿它与
     * 路由所需 Scope 求交集完成。列表为空表示该主体未获任何显式 Scope，
     * 此时任何需要 Scope 的路由都必须拒绝，不能视为「无限制」。
     *
     * @var string[]
     */
    private $scopes;

    /**
     * Token 唯一标识，来自 jti claim；signed_request 模式下无 Token 因而为 null。
     * 两处用途：吊销存储按它判断该令牌是否已被撤销；审计日志按它串联同一张令牌的
     * 全部调用。不能用它做防重放——防重放依据的是请求 Nonce，一张令牌在有效期内
     * 本就允许发起多次合法请求。
     *
     * @var string|null
     */
    private $jti;

    /**
     * 令牌过期时间的 Unix 秒级时间戳，来自 exp claim；无 Token 时为 null。
     * 到达业务层时过期判定已由验证器完成（含 clock_skew 容忍），因此这里**不是**
     * 需要业务再次检查的字段；保留它是为了让业务能决定是否提前刷新，
     * 以及审计时记录令牌的剩余有效期。
     *
     * @var int|null
     */
    private $expiresAt;

    /**
     * 租户上下文标识，来自 tenant_id claim；未启用多租户时为 null。
     * 它是主体身份之上的**数据隔离维度**，不替代主体——同一个 service 主体可能
     * 携带不同租户上下文访问不同数据集。入站验证已确认它命中 Profile 的租户白名单
     * （若声明了白名单）。业务查询必须显式带上它，漏带即等于跨租户读取。
     *
     * @var string|null
     */
    private $tenantId;

    /**
     * 代理主体信息，来自 act claim；无代理关系时为 null。
     * 出现在「服务代表用户操作」的场景：sub 是被代表的用户，act 记录实际发起调用的服务。
     * 审计必须同时记录两者，否则无法回答「这次操作是用户自己做的还是某个服务代做的」。
     * 授权判定仍以 sub 与 scopes 为准，act 不额外放大权限。
     *
     * @var array|null
     */
    private $act;
    
    /**
     * 由已验证 claims 构建主体对象。
     *
     * 使用范围：JwtTokenVerifier.verify 成功路径、signed_request 模式中间件构造签名主体时调用。
     * 适用场景：把裸 claims 数组固化为不可变对象，防止身份信息在层间被篡改。
     *
     * 函数逻辑：
     * 1. 归一化各字段：audience 统一数组；scope 兼容数组与空格分隔字符串。
     * 2. 提取 jti/exp/tenant_id/act 可空字段。
     *
     * @param array $data 身份数据｜来自已验证 claims。示例：['sub'=>'service:pc','client_id'=>'product-center','scope'=>['order.read']]
     * @return void 无返回值。
     */
    public function __construct(array $data)
    {
        $this->sub      = (string)($data['sub'] ?? '');
        $this->clientId = (string)($data['client_id'] ?? $data['azp'] ?? $data['sub'] ?? '');
        
        $audience = $data['aud'] ?? [];
        if (is_array($audience)) {
            $this->audience = array_map('strval', $audience);
        } else {
            $this->audience = $audience === null ? [] : [(string)$audience];
        }
        
        $this->issuer      = (string)($data['iss'] ?? '');
        $this->subjectType = (string)($data['subject_type'] ?? 'service');
        
        $scopes = $data['scope'] ?? [];
        if (is_array($scopes)) {
            $this->scopes = array_map('strval', $scopes);
        } elseif (is_string($scopes) && $scopes !== '') {
            // 兼容空格分隔的 scope 字符串形式。
            $this->scopes = explode(' ', $scopes);
        } else {
            $this->scopes = [];
        }
        
        $this->jti       = isset($data['jti']) && is_string($data['jti']) ? $data['jti'] : null;
        $this->expiresAt = isset($data['exp']) && is_numeric($data['exp']) ? (int)$data['exp'] : null;
        $this->tenantId  = isset($data['tenant_id']) && is_string($data['tenant_id']) && $data['tenant_id'] !== ''
            ? $data['tenant_id']
            : null;
        $this->act       = isset($data['act']) && is_array($data['act']) ? $data['act'] : null;
    }
    
    /**
     * 返回主体标识 sub。
     *
     * 使用范围：Scope 授权、审计日志、业务层身份展示。
     * 适用场景：以规范 type:id 形态唯一确定被认证主体。
     *
     * 函数逻辑：
     * 1. 返回 sub 属性。
     *
     * @return string 主体标识。示例："service:product-center"
     */
    public function getSub()
    {
        return $this->sub;
    }
    
    /**
     * 返回客户端应用标识。
     *
     * 使用范围：入站绑定校验后的业务读取。
     * 适用场景：按 client 维度限流或审计。
     *
     * 函数逻辑：
     * 1. 返回 clientId 属性。
     *
     * @return string 客户端标识。示例："product-center"
     */
    public function getClientId()
    {
        return $this->clientId;
    }
    
    /**
     * 返回签发者 iss。
     *
     * 使用范围：审计日志记录签发来源。
     * 适用场景：多签发方体系区分令牌出处。
     *
     * 函数逻辑：
     * 1. 返回 issuer 属性。
     *
     * @return string 签发者。示例："tozo-auth"
     */
    public function getIssuer()
    {
        return $this->issuer;
    }
    
    /**
     * 返回受众列表。
     *
     * 使用范围：下游服务二次校验 aud。
     * 适用场景：统一 string/array 双态为数组形态。
     *
     * 函数逻辑：
     * 1. 返回 audience 属性。
     *
     * @return string[] 受众列表。示例：["order-api"]
     */
    public function getAudience()
    {
        return $this->audience;
    }
    
    /**
     * 返回主体类型。
     *
     * 使用范围：授权层类型防线判定。
     * 适用场景：用户/服务/合作方权限互不可替代。
     *
     * 函数逻辑：
     * 1. 返回 subjectType 属性。
     *
     * @return string 主体类型。示例："service"
     */
    public function getSubjectType()
    {
        return $this->subjectType;
    }
    
    /**
     * 返回 Scope 列表。
     *
     * 使用范围：授权判定 required⊆granted。
     * 适用场景：接口权限校验的数据来源。
     *
     * 函数逻辑：
     * 1. 返回 scopes 属性。
     *
     * @return string[] Scope 列表。示例：["order.read"]
     */
    public function getScopes()
    {
        return $this->scopes;
    }
    
    /**
     * 返回 jti。
     *
     * 使用范围：吊销登记与审计关联。
     * 适用场景：需要精确到单个 Token 的失效操作。
     *
     * 函数逻辑：
     * 1. 返回 jti 属性。
     *
     * @return string|null jti；缺失时 null。示例："9f8b7c6d5e4f3210"
     */
    public function getJti()
    {
        return $this->jti;
    }
    
    /**
     * 返回过期时间戳 exp。
     *
     * 使用范围：监控评估剩余有效期。
     * 适用场景：提前刷新策略的数据来源。
     *
     * 函数逻辑：
     * 1. 返回 expiresAt 属性。
     *
     * @return int|null Unix 秒；缺失时 null。示例：1700000900
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }
    
    /**
     * 返回租户上下文。
     *
     * 使用范围：多租户业务的隔离判断。
     * 适用场景：tenant_id 不替代主体，仅作上下文。
     *
     * 函数逻辑：
     * 1. 返回 tenantId 属性。
     *
     * @return string|null 租户 ID；未携带 null。示例："t01"
     */
    public function getTenantId()
    {
        return $this->tenantId;
    }
    
    /**
     * 返回代理主体 act 结构。
     *
     * 使用范围：服务代表用户操作时的溯源。
     * 适用场景：审计同时记录实际用户与服务代理链。
     *
     * 函数逻辑：
     * 1. 返回 act 属性。
     *
     * @return array|null act 结构；未携带 null。示例：["sub"=>"user:380354"]
     */
    public function getAct()
    {
        return $this->act;
    }
    
    /**
     * 判断主体类型是否匹配。
     *
     * 使用范围：业务层快速类型分支。
     * 适用场景：仅允许 user 类型访问的接口前置判断。
     *
     * 函数逻辑：
     * 1. subjectType === type 严格比较。
     *
     * @param string $type 目标类型｜白名单成员。示例："service"
     * @return bool true=匹配。示例：true
     */
    public function isType(string $type)
    {
        return $this->subjectType === $type;
    }
    
    /**
     * 判断是否持有指定 Scope。
     *
     * 使用范围：授权细粒度判断。
     * 适用场景：精确匹配防前缀误命中（order.read 不匹配 order.readonly）。
     *
     * 函数逻辑：
     * 1. in_array 严格比较。
     *
     * @param string $scope 目标 Scope｜完整名称。示例："order.read"
     * @return bool true=持有。示例：true
     */
    public function hasScope(string $scope)
    {
        return in_array($scope, $this->scopes, true);
    }
}
