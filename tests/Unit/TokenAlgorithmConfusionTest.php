<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * JWT 算法混淆与降级攻击防护测试
 *
 * 文件功能：
 * - 证明本 SDK 的 JWT 验证不受"算法由攻击者决定"这一类攻击影响
 * - 覆盖：alg=none、alg 篡改为 HS256（用公钥当 HMAC 密钥）、alg 篡改为
 *   不支持算法、kid 缺失/未知、以及 Header 与 Profile 固定算法不一致
 *
 * 为什么必须固化：
 * - 依赖库 firebase/php-jwt 6.10.0 存在 CVE-2025-45769（<7.0.0，低危，
 *   7.x 起要求 PHP ^8.0，与本 SDK 的 PHP >= 7.4 基线冲突，故留在 6.10.0）
 * - 本 SDK 的用法从不读取 Header alg，而是由 Profile driver 固定算法并以
 *   Key(材料, 算法) 形式传入；本测试即该防护的可执行证据
 *
 * 安全边界：
 * - 用例全部为负向断言：任何一条从"拒绝"变成"通过"都意味着防线被破坏
 * - 使用的 RSA 密钥对为仓库内测试夹具，非生产密钥
 */

namespace Tozo\Security\Tests\Unit;

use Firebase\JWT\JWT;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Token\JwtTokenVerifier;
use Tozo\Security\Contracts\ClockInterface;
use Tozo\Security\Exceptions\TokenFormatException;
use Tozo\Security\Profile;
use Tozo\Security\Exceptions\InvalidTokenException;

class TokenAlgorithmConfusionTest extends TestCase
{
    /**
     * 测试用 RSA 密钥对，static 以便整个用例类只生成一次。
     * 算法混淆用例的核心材料：需要用**同一对**密钥分别构造合法 RS256 令牌
     * 与把 alg 篡改为 HS256 的攻击令牌，才能证明服务端没有把公钥当共享密钥使用。
     * 生成 RSA 密钥对开销较大，逐用例生成会显著拖慢测试。
     *
     * @var array|null
     */
    private static $keyPair;
    
    /**
     * alg=none 的无签名 Token 必须被拒绝。
     */
    public function test_alg_none_token_is_rejected()
    {
        $token = $this->handCraftToken(
            ['alg' => 'none', 'typ' => 'JWT', 'kid' => 'jwt-private-2026-08'],
            $this->validClaims(),
            ''
        );
        
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token, $this->rs256Profile());
    }
    
    /**
     * 手工拼装 Token（用于构造合法库无法生成的攻击形态，如 alg=none）。
     *
     * @param array $header JWT Header 数组。
     * @param array $claims Payload claims 数组。
     * @param string $signature 已 Base64URL 编码的签名段（可为空串）。
     * @return string 三段式紧凑 Token。
     */
    private function handCraftToken(array $header, array $claims, string $signature)
    {
        return $this->b64((string)json_encode($header))
            . '.' . $this->b64((string)json_encode($claims))
            . '.' . $signature;
    }
    
    /**
     * Base64URL 编码（无 padding）。
     *
     * @param string $raw 原始字节。
     * @return string 编码结果。
     */
    private function b64(string $raw)
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
    
    /**
     * 生成一组在时间与身份上都合法的 claims，使失败原因只能来自算法或 kid。
     *
     * @return array claims 数组。
     */
    private function validClaims()
    {
        $now = time();
        
        return [
            'iss'          => 'tozo-auth',
            'sub'          => 'service:product-center',
            'aud'          => ['order-api'],
            'client_id'    => 'product-center',
            'subject_type' => 'service',
            'scope'        => ['order.read'],
            'jti'          => bin2hex(random_bytes(8)),
            'iat'          => $now,
            'nbf'          => $now,
            'exp'          => $now + 900,
        ];
    }
    
    private function verifier()
    {
        return new JwtTokenVerifier(
            new ArrayKeyProvider($this->keys()),
            new class implements ClockInterface {
                public function now()
                {
                    return time();
                }
            }
        );
    }
    
    private function keys()
    {
        $pair = $this->keyPair();
        
        return array_merge($this->defaultKeys(), [
            'jwt-private-2026-08' => $pair['private'],
            'jwt-public-2026-08'  => $pair['public'],
        ]);
    }
    
    private function keyPair()
    {
        if (self::$keyPair !== null) {
            return self::$keyPair;
        }
        
        $dir = dirname(__DIR__, 2) . '/tests/fixtures/';
        
        return self::$keyPair = [
            'private' => (string)file_get_contents($dir . 'jwt-test-private.pem'),
            'public'  => (string)file_get_contents($dir . 'jwt-test-public.pem'),
        ];
    }
    
    private function rs256Profile()
    {
        $config                    = $this->inboundProfile();
        $config['token']['driver'] = 'jwt_rs256';
        
        return Profile::fromConfig('order_inbound', $config, new ArrayKeyProvider($this->keys()));
    }
    
    /**
     * 经典算法混淆：把 RSA 公钥当作 HMAC 密钥签出 HS256 Token，
     * 再声明 alg=HS256 提交给 RS256 Profile —— 必须被拒绝。
     */
    public function test_hs256_token_signed_with_rsa_public_key_is_rejected()
    {
        $publicKey = $this->keyPair()['public'];
        
        // 攻击者持有的只有公钥；用它作为 HMAC 密钥自造签名。
        $token = $this->handCraftHs256Token(
            ['alg' => 'HS256', 'typ' => 'JWT', 'kid' => 'jwt-private-2026-08'],
            $this->validClaims(),
            $publicKey
        );
        
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token, $this->rs256Profile());
    }
    
    /**
     * 用指定密钥手工生成 HS256 签名 Token（模拟攻击者自造签名）。
     *
     * @param array $header JWT Header 数组（alg 可为任意值）。
     * @param array $claims Payload claims 数组。
     * @param string $secret HMAC 密钥（攻击场景下为 RSA 公钥内容）。
     * @return string 三段式紧凑 Token。
     */
    private function handCraftHs256Token(array $header, array $claims, string $secret)
    {
        $signingInput = $this->b64((string)json_encode($header))
            . '.' . $this->b64((string)json_encode($claims));
        
        return $signingInput . '.' . $this->b64(hash_hmac('sha256', $signingInput, $secret, true));
    }
    
    /**
     * Header 声明不受支持的算法时必须被拒绝，不得回退到任何默认算法。
     */
    public function test_unsupported_algorithm_header_is_rejected()
    {
        $token = $this->handCraftHs256Token(
            ['alg' => 'HS1024', 'typ' => 'JWT', 'kid' => 'jwt-private-2026-08'],
            $this->validClaims(),
            'whatever'
        );
        
        // firebase 对未知算法抛 UnexpectedValueException，SDK 映射为格式错误。
        $this->expectException(TokenFormatException::class);
        $this->verifier()->verify($token, $this->rs256Profile());
    }
    
    /**
     * kid 不在 Profile allowed_kids 白名单内时必须被拒绝（不扫描所有公钥）。
     */
    public function test_unknown_kid_is_rejected()
    {
        $token = JWT::encode(
            $this->validClaims(),
            $this->keyPair()['private'],
            'RS256',
            'attacker-supplied-kid'
        );
        
        try {
            $this->verifier()->verify($token, $this->rs256Profile());
            $this->fail('未知 kid 的 Token 被接受了');
        } catch (InvalidTokenException $e) {
            $this->assertSame('unknown_kid', $e->getReasonCode());
        }
    }
    
    /**
     * kid 缺失时必须被拒绝：kid 是取得候选公钥的唯一入口。
     */
    public function test_missing_kid_is_rejected()
    {
        // 不传 kid，Header 只有 alg/typ。
        $token = JWT::encode($this->validClaims(), $this->keyPair()['private'], 'RS256');
        
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token, $this->rs256Profile());
    }
    
    /**
     * 真实 RS256 签发的 Token 在 HS256 Profile 下必须被拒绝：
     * 算法由 Profile 固定，不因 Token 自称而切换。
     */
    public function test_rs256_token_is_rejected_by_hs256_profile()
    {
        $token = JWT::encode(
            $this->validClaims(),
            $this->keyPair()['private'],
            'RS256',
            'jwt-private-2026-08'
        );
        
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token, $this->hs256Profile());
    }
    
    private function hs256Profile()
    {
        $config                            = $this->inboundProfile();
        $config['token']['driver']         = 'jwt_hs256';
        $config['token']['signing_key_id'] = self::HMAC_KEY;
        unset($config['token']['allowed_kids']);
        
        return Profile::fromConfig('order_inbound_hs', $config, new ArrayKeyProvider($this->keys()));
    }
    
    /**
     * 正向对照：算法、kid 与 Profile 全部匹配时必须验证通过。
     * 没有这条对照，上面的负向用例可能只是"因为别的原因失败"。
     */
    public function test_matching_algorithm_and_kid_is_accepted()
    {
        $token = JWT::encode(
            $this->validClaims(),
            $this->keyPair()['private'],
            'RS256',
            'jwt-private-2026-08'
        );
        
        $subject = $this->verifier()->verify($token, $this->rs256Profile());
        
        $this->assertSame('service:product-center', $subject->getSub());
        $this->assertSame('product-center', $subject->getClientId());
        $this->assertSame('service', $subject->getSubjectType());
    }
}
