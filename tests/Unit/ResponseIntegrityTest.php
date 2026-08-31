<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

namespace Tozo\Security\Tests\Unit;

use Tozo\Security\Tests\TestCase;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Encryption\AesGcmCipher;
use Tozo\Security\Profile;
use Tozo\Security\Exceptions\KeyNotFoundException;
use Tozo\Security\Protocol\Encoding;
use Tozo\Security\Encryption\ResponseIntegrityChecker;

class ResponseIntegrityTest extends TestCase
{
    public function test_encrypted_response_uses_response_integrity_key()
    {
        $keys    = new ArrayKeyProvider($this->defaultKeys());
        $cipher  = new AesGcmCipher($keys);
        $checker = new ResponseIntegrityChecker($cipher, $keys);
        
        $requestProfile = Profile::fromConfig(
            'request',
            $this->outboundProfile(),
            $keys
        );
        
        $envelope = $cipher->encryptString('{"ok":true}', $requestProfile, 'response');
        $this->assertSame(self::RESP_ENC_KEY, json_decode($envelope, true)['key_id']);
        
        $this->assertSame(
            '{"ok":true}',
            $checker->decryptEncryptedResponse($envelope, $requestProfile)
        );
    }
    
    public function test_signed_response_accepts_verify_only_response_key()
    {
        $responseKey                  = 'response-signing';
        $keys                         = new ArrayKeyProvider(
            array_merge($this->defaultKeys(), [$responseKey => str_repeat('d', 32)]),
            [$responseKey => 'verify_only']
        );
        $config                       = $this->outboundProfile();
        $config['response_integrity'] = [
            'required'  => true,
            'mode'      => 'signed',
            'signature' => ['key_id' => $responseKey],
        ];
        $profile                      = Profile::fromConfig('signed-response', $config, $keys);
        $body                         = '{"ok":true}';
        $canonical                    = implode("\n", [
            '1',
            'response',
            $profile->getClientId(),
            $profile->getTargetService(),
            hash('sha256', $body),
            $responseKey,
        ]);
        $signature                    = Encoding::base64UrlEncode(hash_hmac('sha256', $canonical, str_repeat('d', 32), true));
        
        (new ResponseIntegrityChecker(
            new AesGcmCipher($keys),
            $keys
        ))->verifySignedResponse($body, [
            'X-Tozo-Response-Signature' => $signature,
        ], $profile);
        
        $this->addToAssertionCount(1);
    }
    
    public function test_signed_response_rejects_retired_response_key()
    {
        $responseKey                  = 'response-signing';
        $keys                         = new ArrayKeyProvider(
            array_merge($this->defaultKeys(), [$responseKey => str_repeat('d', 32)]),
            [$responseKey => 'retired']
        );
        $config                       = $this->outboundProfile();
        $config['response_integrity'] = [
            'required'  => true,
            'mode'      => 'signed',
            'signature' => ['key_id' => $responseKey],
        ];
        $profile                      = Profile::fromConfig('signed-response', $config, $keys);
        $body                         = '{"ok":true}';
        $canonical                    = implode("\n", [
            '1',
            'response',
            $profile->getClientId(),
            $profile->getTargetService(),
            hash('sha256', $body),
            $responseKey,
        ]);
        $signature                    = Encoding::base64UrlEncode(hash_hmac('sha256', $canonical, str_repeat('d', 32), true));
        
        $this->expectException(KeyNotFoundException::class);
        (new ResponseIntegrityChecker(new AesGcmCipher($keys), $keys))
            ->verifySignedResponse($body, [
                'X-Tozo-Response-Signature' => $signature,
            ], $profile);
    }
}
