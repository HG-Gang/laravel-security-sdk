<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * 缺陷回归测试
 *
 * 文件功能：
 * - 固化本轮审查修复的各项缺陷，防止回退
 * - 每个用例对应一个已验证可触发的具体问题，而非泛化风格检查
 *
 * 覆盖项：
 * - Facade 访问器绑定存在性（否则代理调用抛 BindingResolutionException）
 * - TozoHttpClient 必需依赖前置（否则可选参数被隐式变为必需）
 * - 信封 key_id 空值不得命中白名单
 * - HMAC-Bearer 非数字时间戳显式拒绝
 * - 加密开启但 cipher 绑定缺失时给出配置原因码而非未预期异常
 * - 包内配置文件不得带 UTF-8 BOM
 */

namespace Tozo\Security\Tests\Unit;

use ReflectionMethod;
use Tozo\Security\Payload;
use Illuminate\Http\Request;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Clock\SystemClock;
use Tozo\Security\Http\TozoHttpClient;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Signature\HmacSha256Signer;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Contracts\HttpClientInterface;
use Tozo\Security\Profile;
use Tozo\Security\Storage\LaravelCacheReplayStore;
use Tozo\Security\Exceptions\InvalidCiphertextException;
use Tozo\Security\Authentication\HmacBearerAuthenticator;
use Tozo\Security\Laravel\Middleware\InboundAuthenticatorMiddleware;
use Tozo\Security\Exceptions\InvalidSignatureException;

class DefectRegressionTest extends TestCase
{
    /**
     * Facade::getFacadeAccessor() 返回的容器键必须已绑定，
     * 否则 TozoSecurity::get()/post() 等代理调用在运行期才失败。
     */
    public function test_facade_accessor_is_bound_in_container()
    {
        $container = $this->makeContainer();
        
        $accessor = new ReflectionMethod(\Tozo\Security\Facade::class, 'getFacadeAccessor');
        $accessor->setAccessible(true);
        $key = $accessor->invoke(null);
        
        $this->assertTrue($container->bound($key), "Facade 访问器 [{$key}] 未在容器中绑定");
        $this->assertInstanceOf(HttpClientInterface::class, $container->make($key));
    }
    
    /**
     * http_client 关闭时不注册访问器绑定，保持“未启用功能不可解析”的语义。
     */
    public function test_facade_accessor_is_absent_when_http_client_disabled()
    {
        $container = $this->makeContainer(['features.http_client' => false]);
        
        $this->assertFalse($container->bound('tozo_security'));
    }
    
    /**
     * 必需依赖必须位于可选参数之前：否则 PHP 会把前面的可选参数隐式视为必需，
     * 使 new TozoHttpClient($auditSink) 这种最小构造无法成立。
     */
    public function test_http_client_requires_only_the_audit_sink()
    {
        $reflection = new ReflectionMethod(TozoHttpClient::class, '__construct');
        
        $this->assertSame(
            1,
            $reflection->getNumberOfRequiredParameters(),
            'TozoHttpClient 必需参数数量不为 1，可选依赖被隐式变成了必需参数'
        );
        
        $parameters = $reflection->getParameters();
        $this->assertSame('auditSink', $parameters[0]->getName());
        
        // 仅传审计接收器即可构造，其余能力按 Profile 需要再注入。
        $client = new TozoHttpClient($this->createMock(AuditSinkInterface::class));
        $this->assertNull($client->getProfile());
    }
    
    /**
     * 该方向未配置加密密钥时，攻击者不得用空 key_id 信封命中白名单比对。
     */
    public function test_envelope_with_empty_key_id_is_rejected_when_direction_key_absent()
    {
        $keys   = new ArrayKeyProvider($this->defaultKeys());
        $cipher = new AesGcmCipher($keys);
        
        // 该 Profile 未配置 response_integrity.encryption.key_id。
        $config = $this->outboundProfile();
        unset($config['response_integrity']);
        $config['security_mode']           = 'signed_request';
        $config['token']['attach_enabled'] = false;
        $profile                           = Profile::fromConfig('no-response-key', $config, $keys);
        
        $forged = (string)json_encode([
            'version'    => '1',
            'algorithm'  => 'aes_256_gcm',
            'key_id'     => '',
            'iv'         => str_repeat('A', 16),
            'ciphertext' => 'AAAA',
            'tag'        => str_repeat('B', 22),
        ]);
        
        // 必须是信封校验失败，而不是等到密钥检索阶段才因缺钥失败。
        $this->expectException(InvalidCiphertextException::class);
        $cipher->decryptEnvelopeJson($forged, $profile, 'response');
    }
    
    /**
     * HMAC-Bearer 时间戳非数字时必须显式拒绝，与 HmacSha256Signer 口径一致，
     * 不能靠 (int) 强转为 0 再依赖时间窗比较间接失败。
     */
    public function test_hmac_bearer_rejects_non_numeric_timestamp()
    {
        $keys          = new ArrayKeyProvider([self::HMAC_KEY => str_repeat('a', 32)]);
        $authenticator = new HmacBearerAuthenticator(
            $keys,
            new LaravelCacheReplayStore($this->cacheRepository()),
            new SystemClock()
        );
        
        $config                         = $this->inboundProfile();
        $config['security_mode']        = 'token_only';
        $config['signature']['enabled'] = false;
        $config['authentication']       = ['driver' => 'hmac_bearer_sha256', 'key_id' => self::HMAC_KEY];
        unset($config['token']);
        $profile = Profile::fromConfig('bearer_inbound', $config, $keys);
        
        $payload = new Payload([
            'method'        => 'GET',
            'path'          => '/api/orders',
            'body'          => '',
            'authorization' => 'HMAC-Bearer key_id="' . self::HMAC_KEY
                . '", timestamp="not-a-number", nonce="' . str_repeat('c', 32) . '", signature="AAAA"',
        ]);
        
        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('Authorization timestamp is not numeric');
        $authenticator->authenticate($payload, $profile);
    }
    
    private function cacheRepository()
    {
        return new \Illuminate\Cache\Repository(new \Illuminate\Cache\ArrayStore());
    }
    
    /**
     * 加密 Profile 但 cipher 绑定缺失时，日志必须拿到稳定配置原因码，
     * 而不是 null 方法调用产生的未预期异常分支。
     */
    public function test_inbound_middleware_reports_configuration_reason_when_cipher_missing()
    {
        $keys   = new ArrayKeyProvider($this->defaultKeys());
        $signer = new HmacSha256Signer(
            $keys,
            new LaravelCacheReplayStore($this->cacheRepository()),
            new SystemClock()
        );
        
        $inboundConfig                  = $this->inboundProfile();
        $inboundConfig['security_mode'] = 'signed_request';
        $inboundConfig['encryption']    = ['enabled' => true, 'driver' => 'aes_256_gcm', 'key_id' => self::ENC_KEY];
        unset($inboundConfig['token']);
        $inbound = Profile::fromConfig('order_inbound', $inboundConfig, $keys);
        
        $request = $this->signedEncryptedRequest($keys, $signer);
        
        $logger     = new CollectingLogger();
        $middleware = new InboundAuthenticatorMiddleware(
            ['order_inbound' => $inbound],
            $signer,
            null,
            null,
            null,   // cipher 绑定缺失
            $logger
        );
        
        $response = $middleware->handle($request, function () {
            return 'BUSINESS_REACHED';
        });
        
        // 仍然失败关闭，且原因码是配置类而非 unexpected_inbound_failure。
        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame('{"error":"internal_error"}', (string)$response->getContent());
        $this->assertContains('invalid_security_configuration', $logger->reasonCodes());
        $this->assertNotContains('unexpected_inbound_failure', $logger->reasonCodes());
    }
    
    /**
     * 构造一个真实已加密并已签名的入站请求。
     */
    private function signedEncryptedRequest(ArrayKeyProvider $keys, HmacSha256Signer $signer)
    {
        $outboundConfig                            = $this->outboundProfile();
        $outboundConfig['security_mode']           = 'signed_request';
        $outboundConfig['token']['attach_enabled'] = false;
        unset($outboundConfig['response_integrity']);
        $outbound = Profile::fromConfig('svc_to_order', $outboundConfig, $keys);
        
        $payload = new Payload([
            'method'         => 'POST',
            'path'           => '/api/orders',
            'query'          => '',
            'content_type'   => 'application/json',
            'client_id'      => 'product-center',
            'target_service' => 'order-api',
            'body'           => '{"sku":"A-1"}',
        ]);
        
        $payload = (new AesGcmCipher($keys))->encrypt($payload, $outbound);
        $payload = $signer->sign($payload, $outbound);
        $data    = $payload->getData();
        
        $request = Request::create(
            'https://order-api.test/api/orders',
            'POST',
            [],
            [],
            [],
            [],
            (string)$data['body']
        );
        $request->headers->set('Content-Type', 'application/json');
        $request->headers->set('X-Tozo-Protocol-Version', '1');
        $request->headers->set('X-Tozo-Client-Id', 'product-center');
        $request->headers->set('X-Tozo-Key-Id', (string)$data['key_id']);
        $request->headers->set('X-Tozo-Timestamp', (string)$data['timestamp']);
        $request->headers->set('X-Tozo-Nonce', (string)$data['nonce']);
        $request->headers->set('X-Tozo-Signature', (string)$data['signature']);
        
        return $request;
    }
    
    /**
     * 包内配置文件带 BOM 会在 Laravel 应用中提前产生输出，破坏 header() 调用。
     */
    public function test_packaged_php_files_have_no_utf8_bom()
    {
        $root      = dirname(__DIR__, 2);
        $offenders = [];
        
        foreach ([$root . '/src', $root . '/config', $root . '/tests'] as $directory) {
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory));
            foreach ($iterator as $file) {
                if (!$file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }
                
                $handle = fopen($file->getPathname(), 'rb');
                $head   = (string)fread($handle, 3);
                fclose($handle);
                
                if ($head === "\xEF\xBB\xBF") {
                    $offenders[] = str_replace($root, '', $file->getPathname());
                }
            }
        }
        
        $this->assertSame([], $offenders, "以下文件带 UTF-8 BOM：\n" . implode("\n", $offenders));
    }
    
    /**
     * 响应保护中间件必须可从容器解析，否则服务端无法闭合响应完整性链路。
     */
    public function test_response_integrity_middleware_is_resolvable()
    {
        $container = $this->makeContainer();
        
        $this->assertInstanceOf(
            \Tozo\Security\Laravel\Middleware\ResponseIntegrityMiddleware::class,
            $container->make('tozo.middleware.response')
        );
    }
}

/**
 * 收集原因码的最小 PSR-3 实现；仅用于断言日志分流是否正确。
 */
class CollectingLogger extends \Psr\Log\AbstractLogger
{
    /**
     * 已记录的日志 context 列表，按写入顺序累积。
     * 用于断言原因码分流是否正确：同一异常在不同分支应产出不同原因码，
     * 若实现把它们混为一类，告警规则就无法区分「重放」与「密钥缺失」这类不同性质的故障。
     * 只收集 context 而不收集消息文本，因为可机器匹配的是原因码而非人类可读消息。
     *
     * @var array<int,array>
     */
    private $records = [];
    
    public function log($level, $message, array $context = [])
    {
        $this->records[] = $context;
    }
    
    /**
     * 返回全部已记录的 reason_code，供断言失败分流。
     */
    public function reasonCodes()
    {
        $codes = [];
        foreach ($this->records as $context) {
            if (isset($context['reason_code'])) {
                $codes[] = (string)$context['reason_code'];
            }
        }
        
        return $codes;
    }
}
