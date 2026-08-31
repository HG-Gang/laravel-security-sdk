<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use Illuminate\Http\Request;
use Tozo\Security\Tests\TestCase;
use Tozo\Security\Http\TozoHttpClient;
use Tozo\Security\Protocol\ProtocolVersion;
use Tozo\Security\Contracts\SignerInterface;
use Tozo\Security\Protocol\CanonicalRequest;
use Tozo\Security\Contracts\AuditSinkInterface;
use Tozo\Security\Contracts\PayloadCipherInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Contracts\ResponseIntegrityInterface;
use Tozo\Security\Laravel\Middleware\OutboundSignerMiddleware;

class NullableCompatibilityTest extends TestCase
{
    public function test_http_client_can_clear_default_profile_with_null()
    {
        $client = new TozoHttpClient(
            $this->mock(AuditSinkInterface::class),
            $this->mock(SignerInterface::class),
            $this->mock(PayloadCipherInterface::class),
            $this->mock(ResponseIntegrityInterface::class)
        );
        
        $profile = \Tozo\Security\Profile::fromConfig(
            'outbound',
            $this->outboundProfile(),
            new \Tozo\Security\Key\ArrayKeyProvider($this->defaultKeys())
        );
        
        $client->setProfile($profile);
        $client->setProfile(null);
        
        $this->assertNull($client->getProfile());
    }
    
    private function mock($class)
    {
        return $this->createMock($class);
    }
    
    public function test_content_type_normalization_accepts_null_as_empty()
    {
        $this->assertSame('', CanonicalRequest::normalizeContentType(null));
    }
    
    public function test_missing_protocol_version_is_rejected_as_an_unsupported_value()
    {
        $this->expectException(\Tozo\Security\Exceptions\ProtocolException::class);
        ProtocolVersion::requireSupported(null);
    }
    
    public function test_outbound_middleware_accepts_missing_default_profile_name()
    {
        $middleware = new OutboundSignerMiddleware(
            [],
            null,
            $this->mock(SignerInterface::class)
        );
        
        $this->expectException(ConfigurationException::class);
        $middleware->handle(Request::create('/health', 'GET'), function ($request) {
            return $request;
        });
    }
}
