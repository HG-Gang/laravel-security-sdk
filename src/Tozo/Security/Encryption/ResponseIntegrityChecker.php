<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ResponseIntegrityChecker
 *
 * 文件功能：
 * - ResponseIntegrityInterface 首版实现，覆盖「生成」与「验证」两侧，形成响应链路闭环
 * - encrypted 模式：以响应专用加密密钥生成/解密 AEAD 信封（GCM tag 即完整性证明）
 * - signed 模式：生成/验证方向绑定（direction=response）的应用层 HMAC 签名
 *
 * 安全边界：
 * - mode 固定，不接受运行时二选一
 * - 响应密钥为独立用途，Profile 校验阶段已强制与请求密钥不同
 * - 生成侧断言写方向状态（active）；验证侧接受迁移期 verify_only/decrypt_only
 * - 签名原文由 responseCanonical() 单一来源产出，杜绝两侧规则漂移
 * - 任何验证失败抛出 ResponseIntegrityException，客户端不得把未验证数据交给业务
 */

namespace Tozo\Security\Encryption;

use Throwable;
use Tozo\Security\Profile;
use Tozo\Security\Key\KeyUsage;
use Tozo\Security\Protocol\Encoding;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Contracts\ResponseIntegrityInterface;
use Tozo\Security\Exceptions\ResponseIntegrityException;
use Tozo\Security\Exceptions\InvalidCiphertextException;

class ResponseIntegrityChecker implements ResponseIntegrityInterface
{
    /**
     * signed 模式承载响应签名的 Header 名。
     * 固定在此常量而非按配置可变，是为了让调用端与被调用方不可能读写不同的头——
     * 若两端头名不一致，调用端会把有签名的响应判为「未受保护」并整体拒收。
     * 该头由本类生成与读取，业务代码不得自行写入同名头。
     */
    public const SIGNED_MODE_SIGNATURE_HEADER = 'X-Tozo-Response-Signature';
    
    /**
     * 密文处理器。encrypted 模式下复用请求方向**同一套**信封格式与 AAD 构造实现。
     * 复用而非另写一套的原因：两套实现必然随时间漂移，
     * 漂移后表现为「本端能解自己的密文，对端解不开」这类极难定位的故障。
     * 方向差异只体现在 AAD 中的 direction 字段与所用密钥，算法与信封结构完全一致。
     *
     * @var AesGcmCipher
     */
    private $cipher;
    
    /**
     * 密钥提供器。检索**响应用途**的独立 HMAC 密钥。
     * 与请求签名密钥强制分离（Profile 校验期即拦截复用）：若两者相同，
     * 攻击者可把一次请求签名原样当作响应签名使用，方向绑定失效。
     *
     * @var KeyProviderInterface
     */
    private $keys;
    
    /**
     * 构造响应完整性验证器。
     *
     * 使用范围：ServiceProvider 在 features.response_integrity 且存在 required Profile 时注册单例。
     * 适用场景：调用端收到 order-api 响应后，按 Profile 固定 mode 选择解密或验签，通过后才交给业务。
     *
     * 函数逻辑：
     * 1. 保存 AES-GCM 处理器（encrypted 模式复用其 decryptEnvelopeJson）。
     * 2. 保存密钥提供器（signed 模式检索 response_integrity.signature.key_id 对应密钥）。
     *
     * @param AesGcmCipher $cipher 密文处理器｜AEAD 加解密实现。示例：new AesGcmCipher($keys)
     * @param KeyProviderInterface $keys 密钥提供器｜响应签名密钥来源。示例：new EnvKeyProvider()
     * @return void 无返回值；依赖保存到私有属性供两个验证入口使用。
     */
    public function __construct(AesGcmCipher $cipher, KeyProviderInterface $keys)
    {
        $this->cipher = $cipher;
        $this->keys   = $keys;
    }
    
    /**
     * 解密 encrypted 模式响应信封并返回明文 Body。
     *
     * 使用范围：TozoHttpClient.verifyResponse 在 response_integrity.mode=encrypted 时调用。
     * 适用场景：服务端返回敏感数据（如订单金额），客户端解密同时借 GCM tag 确认响应未被中间人篡改。
     *
     * 函数逻辑：
     * 1. assertMode 断言 Profile 固定为 encrypted 且 required=true。
     * 2. 委托 cipher->decryptEnvelopeJson(direction=response) 做白名单/AAD/AEAD 全量校验。
     * 3. InvalidCiphertext 统一转 ResponseIntegrityException，保留原链用于内部日志。
     *
     * @param string $envelopeJson 信封 JSON｜响应 Body 的六字段版本化信封。示例：{"version":"1","algorithm":"aes_256_gcm","key_id":"resp-key","iv":"..","ciphertext":"..","tag":".."}
     * @param Profile $profile 出站 Profile｜提供 mode=encrypted 与响应专用 key_id 白名单。示例：Profile::fromConfig('svc_to_order', ...)
     * @return string 明文 Body 字节｜校验通过后的原始响应内容。示例：'{"ok":true}'
     * @throws ConfigurationException Profile 未要求完整性或 mode 不符。
     * @throws ResponseIntegrityException 信封非法/白名单不符/AEAD 校验失败（统一出口）。
     */
    public function decryptEncryptedResponse(string $envelopeJson, Profile $profile)
    {
        $this->assertMode($profile, 'encrypted');
        
        try {
            return $this->cipher->decryptEnvelopeJson($envelopeJson, $profile, 'response');
        } catch (InvalidCiphertextException $e) {
            // 统一转换为响应完整性失败，保留原异常链用于内部日志。
            throw new ResponseIntegrityException('Encrypted response verification failed', 502, $e);
        }
    }
    
    /**
     * 断言 Profile 的固定 mode 与当前验证方式一致。
     *
     * 使用范围：两个公开验证入口的第一步内部调用。
     * 适用场景：防止调用方绕过 Profile 声明、在运行时随意切换 encrypted/signed 造成策略漂移。
     *
     * 函数逻辑：
     * 1. required!==true → ConfigurationException（本验证器只服务强制完整性的 Profile）。
     * 2. mode 与期望值不等 → ConfigurationException 指明固定值。
     *
     * @param Profile $profile 出站 Profile｜读取 response_integrity 配置段。示例：Profile::fromConfig(...)
     * @param string $expectedMode 期望模式｜本次调用的验证方式。示例："encrypted"
     * @return void 一致则静默通过。
     * @throws ConfigurationException 未要求完整性或 mode 固定值不符。
     */
    private function assertMode(Profile $profile, string $expectedMode)
    {
        $config = $profile->getResponseIntegrityConfig();
        
        if (($config['required'] ?? false) !== true) {
            throw new ConfigurationException(
                "Profile [{$profile->getName()}] does not require response integrity"
            );
        }
        
        if (($config['mode'] ?? '') !== $expectedMode) {
            throw new ConfigurationException(
                "Profile [{$profile->getName()}] response_integrity.mode is fixed to [{$expectedMode}]"
            );
        }
    }
    
    /**
     * 生成 encrypted 模式响应信封（服务端侧）。
     *
     * 使用范围：ResponseIntegrityMiddleware 在业务响应写出前调用。
     * 适用场景：order-api 返回订单金额等敏感数据，用响应专用密钥加密后回传，
     *           调用端解密同时借 GCM tag 确认未被中间人篡改。
     *
     * 函数逻辑：
     * 1. assertMode 断言 Profile 固定为 encrypted 且 required=true。
     * 2. 委托 cipher->encryptString(direction=response) 生成六字段信封；
     *    该路径内部使用 response_integrity.encryption.key_id 与写方向状态断言。
     * 3. 底层配置/密钥/加密异常统一转 ResponseIntegrityException，避免半保护响应写出。
     *
     * @param string $body 最终响应 Body｜序列化后的原始字节。示例：'{"ok":true}'
     * @param Profile $profile 入站 Profile｜提供响应专用 key_id 与 client/target 绑定值。示例：Profile::fromConfig('order_inbound', ...)
     * @return string 信封 JSON｜作为新的响应 Body 写出。示例：{"version":"1","algorithm":"aes_256_gcm",...}
     * @throws ConfigurationException Profile 未要求完整性或 mode 不符。
     * @throws ResponseIntegrityException 密钥状态或底层加密失败。
     */
    public function protectEncryptedResponse(string $body, Profile $profile)
    {
        $this->assertMode($profile, 'encrypted');
        
        try {
            return $this->cipher->encryptString($body, $profile, 'response');
        } catch (ConfigurationException $e) {
            // 配置错误保持原类型，便于中间件映射为 500 而非伪装成完整性失败。
            throw $e;
        } catch (Throwable $e) {
            // 无法生成保护时不能退化为明文响应；直接失败关闭。
            throw new ResponseIntegrityException('Encrypted response generation failed', 500, $e);
        }
    }
    
    /**
     * 生成 signed 模式响应签名（服务端侧）。
     *
     * 使用范围：ResponseIntegrityMiddleware 在业务响应写出前调用。
     * 适用场景：响应本身不敏感但必须防篡改——生成 direction=response 的 HMAC 交由
     *           调用端先验证后使用，防止响应被改写或跨接口复用。
     *
     * 函数逻辑：
     * 1. assertMode 断言固定为 signed；读取 response_integrity.signature.key_id（必填）。
     * 2. KeyUsage 断言写方向状态（仅 active）：退役或只读密钥不得再生成新签名。
     * 3. 以 responseCanonical() 单一来源构造原文，输出 Base64URL 签名值。
     *
     * @param string $body 最终响应 Body｜原始字节，哈希后参与签名原文。示例：'{"ok":true}'
     * @param Profile $profile 入站 Profile｜提供 mode=signed 与响应签名 key_id。示例：Profile::fromConfig(...)
     * @return string Base64URL 签名值｜写入 X-Tozo-Response-Signature 头。示例："qE8f2w"
     * @throws ConfigurationException mode 不符或 signature.key_id 缺失。
     * @throws \Tozo\Security\Exceptions\KeyNotFoundException 密钥缺失或状态非 active。
     */
    public function protectSignedResponse(string $body, Profile $profile)
    {
        $this->assertMode($profile, 'signed');
        
        $keyId = $this->signatureKeyId($profile);
        
        // 生成方向只允许 active：verify_only 旧密钥仅供验证存量响应，不能签发新响应。
        KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_SIGN);
        
        $secret = $this->keys->getKey($keyId);
        
        return Encoding::base64UrlEncode(
            hash_hmac('sha256', $this->responseCanonical($body, $profile, $keyId), $secret, true)
        );
    }
    
    /**
     * 读取并校验 signed 模式的响应签名 key_id。
     *
     * 使用范围：protectSignedResponse 与 verifySignedResponse 共用。
     * 适用场景：两侧必须引用同一个独立用途标识；缺失属于配置错误而非验证失败。
     *
     * 函数逻辑：
     * 1. 读 response_integrity.signature.key_id；空值抛 ConfigurationException。
     *
     * @param Profile $profile 通信 Profile｜读取 response_integrity 配置段。示例：Profile::fromConfig(...)
     * @return string 响应签名用途 key_id。示例："order-response-signing"
     * @throws ConfigurationException key_id 缺失或为空。
     */
    private function signatureKeyId(Profile $profile)
    {
        $config          = $profile->getResponseIntegrityConfig();
        $signatureConfig = isset($config['signature']) && is_array($config['signature'])
            ? $config['signature']
            : [];
        
        $keyId = isset($signatureConfig['key_id']) ? (string)$signatureConfig['key_id'] : '';
        if ($keyId === '') {
            throw new ConfigurationException('response_integrity.signature.key_id is required in signed mode');
        }
        
        return $keyId;
    }
    
    /**
     * 构造 signed 模式响应签名原文（生成与验证的唯一事实来源）。
     *
     * 使用范围：protectSignedResponse 生成、verifySignedResponse 验证时成对调用。
     * 适用场景：把方向、通信双方与 Body 哈希绑定进原文，使响应签名无法被复制到
     *           请求方向、另一组 client/target 或另一份 Body 上仍然通过校验。
     *
     * 函数逻辑：
     * 1. 以 "\n" 连接六字段：信封版本、固定方向 response、client_id、target_service、
     *    Body 的 SHA-256 十六进制、响应签名 key_id。
     *
     * @param string $body 最终响应 Body｜原始字节。示例：'{"ok":true}'
     * @param Profile $profile 通信 Profile｜提供 client_id 与 target_service 绑定值。示例：Profile::fromConfig(...)
     * @param string $keyId 响应签名 key_id｜末位绑定字段。示例："order-response-signing"
     * @return string 以 "\n" 连接的签名原文（UTF-8 字节）。示例：六字段换行连接串
     */
    private function responseCanonical(string $body, Profile $profile, string $keyId)
    {
        return implode("\n", [
            AesGcmCipher::ENVELOPE_VERSION,
            'response',
            $profile->getClientId(),
            $profile->getTargetService(),
            hash('sha256', $body),
            $keyId,
        ]);
    }
    
    /**
     * 返回承载响应签名的 Header 名称。
     *
     * 使用范围：生成侧写入 Header、验证侧读取 Header 与中间件装配时共用。
     * 适用场景：两侧共享同一常量，避免大小写或拼写漂移导致签名头漏读。
     *
     * 函数逻辑：
     * 1. 返回类常量 SIGNED_MODE_SIGNATURE_HEADER。
     *
     * @return string Header 名称。示例："X-Tozo-Response-Signature"
     */
    public function getSignatureHeaderName()
    {
        return self::SIGNED_MODE_SIGNATURE_HEADER;
    }
    
    /**
     * 校验 signed 模式响应的方向绑定应用层签名。
     *
     * 使用范围：TozoHttpClient.verifyResponse 在 response_integrity.mode=signed 时调用。
     * 适用场景：响应不加密但需防篡改——服务端对最终 Body 做 direction=response 的 HMAC，客户端先验后用。
     *
     * 函数逻辑：
     * 1. assertMode 断言固定为 signed；读取 response_integrity.signature.key_id（必填）。
     * 2. 大小写不敏感提取 X-Tozo-Response-Signature 头；缺失即视为未受保护响应并拒绝。
     * 3. 以 version\nresponse\nclient\ntarget\nsha256(body)\nkeyId 重建原文，hash_equals 常量时间比对。
     *
     * @param string $body 最终响应 Body｜原始字节，哈希后参与签名原文。示例：'{"ok":true}'
     * @param array $headers 响应 Header 数组｜名称=>值，读取大小写不敏感。示例：["X-Tozo-Response-Signature"=>"qE8f"]
     * @param Profile $profile 出站 Profile｜提供 mode=signed 与响应签名 key_id。示例：Profile::fromConfig(...)
     * @return void 验证通过无返回值。
     * @throws ConfigurationException mode 不符或 signature.key_id 缺失。
     * @throws ResponseIntegrityException 缺少签名头或常量时间比较不一致。
     */
    public function verifySignedResponse(string $body, array $headers, Profile $profile)
    {
        $this->assertMode($profile, 'signed');
        
        $keyId = $this->signatureKeyId($profile);
        
        // 响应签名属于读取方向：允许 active/verify_only，retired 密钥必须拒绝。
        KeyUsage::assertUsable($this->keys, $keyId, KeyUsage::USAGE_VERIFY);
        
        $provided = $this->headerValue($headers, self::SIGNED_MODE_SIGNATURE_HEADER);
        if ($provided === null) {
            // 未受保护的响应一律拒绝。
            throw new ResponseIntegrityException('Response signature header missing');
        }
        
        $secret = $this->keys->getKey($keyId);
        
        // 原文构造与生成侧共用 responseCanonical()，保证两端字节一致。
        $expected      = hash_hmac('sha256', $this->responseCanonical($body, $profile, $keyId), $secret, true);
        $providedBytes = Encoding::base64UrlDecode($provided);
        
        if ($providedBytes === null || !hash_equals($expected, $providedBytes)) {
            throw new ResponseIntegrityException('Response signature mismatch');
        }
    }
    
    /**
     * 大小写不敏感地读取 Header 值。
     *
     * 使用范围：verifySignedResponse 提取响应签名头时调用。
     * 适用场景：不同网关/代理对 Header 大小写规范化不一致时不漏读签名。
     *
     * 函数逻辑：
     * 1. 遍历 Header 数组做 strcasecmp 匹配；值为数组时取首元素。
     *
     * @param array $headers Header 数组｜名称=>值（值可为 string 或 string[]）。示例：["x-tozo-response-signature"=>"qE8f"]
     * @param string $name 目标 Header 名｜标准名。示例："X-Tozo-Response-Signature"
     * @return string|null 匹配到的值；不存在返回 null。示例："order-signing" 或 null
     */
    private function headerValue(array $headers, string $name)
    {
        foreach ($headers as $key => $value) {
            if (strcasecmp((string)$key, $name) === 0) {
                return is_array($value) ? (string)reset($value) : (string)$value;
            }
        }
        
        return null;
    }
}
