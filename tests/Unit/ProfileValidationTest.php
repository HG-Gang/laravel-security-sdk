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
use Tozo\Security\Exceptions\ConfigurationException;

class ProfileValidationTest extends TestCase
{
    public function test_valid_outbound_profile_passes()
    {
        $this->validate([]);
        $this->addToAssertionCount(1);
    }
    
    private function validate(array $overrides)
    {
        $config = array_merge($this->outboundProfile(), $overrides);
        \Tozo\Security\Profile::fromConfig('p', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_signature_enabled_matches_profile_configuration()
    {
        $enabled                                   = \Tozo\Security\Profile::fromConfig(
            'enabled',
            $this->outboundProfile(),
            new ArrayKeyProvider($this->defaultKeys())
        );
        $disabledConfig                            = $this->outboundProfile();
        $disabledConfig['security_mode']           = 'token_only';
        $disabledConfig['signature']['enabled']    = false;
        $disabledConfig['token']['attach_enabled'] = true;
        $disabled                                  = \Tozo\Security\Profile::fromConfig(
            'disabled',
            $disabledConfig,
            new ArrayKeyProvider($this->defaultKeys())
        );
        
        $this->assertTrue($enabled->isSignatureEnabled());
        $this->assertFalse($disabled->isSignatureEnabled());
    }
    
    public function test_missing_direction_fails()
    {
        $this->expectException(ConfigurationException::class);
        $this->validate(['direction' => '']);
    }
    
    public function test_unknown_security_mode_fails()
    {
        $this->expectException(ConfigurationException::class);
        $this->validate(['security_mode' => 'signature_or_token']);
    }
    
    public function test_token_only_forbids_signature()
    {
        $this->expectException(ConfigurationException::class);
        $this->validate([
            'security_mode' => 'token_only',
            'token'         => array_merge($this->outboundProfile()['token'], ['attach_enabled' => true]),
        ]);
    }
    
    public function test_signed_request_requires_signature()
    {
        $this->expectException(ConfigurationException::class);
        $this->validate([
            'security_mode' => 'signed_request',
            'signature'     => array_merge($this->outboundProfile()['signature'], ['enabled' => false]),
            'token'         => array_merge($this->outboundProfile()['token'], ['attach_enabled' => false]),
        ]);
    }
    
    public function test_plus_mode_requires_both_legs_inbound()
    {
        $inbound                            = $this->inboundProfile();
        $inbound['token']['verify_enabled'] = false;
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('i', $inbound, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_response_encryption_key_must_differ_from_request_key()
    {
        $this->expectException(ConfigurationException::class);
        $this->validate([
            'encryption'         => ['enabled' => true, 'driver' => 'aes_256_gcm', 'key_id' => self::ENC_KEY],
            'response_integrity' => [
                'required'   => true,
                'mode'       => 'encrypted',
                'encryption' => ['key_id' => self::ENC_KEY],
            ],
        ]);
    }
    
    public function test_wildcard_scope_is_rejected()
    {
        $this->expectException(ConfigurationException::class);
        $this->validate(['scope' => ['allowed_scopes' => ['order.*']]]);
    }
    
    public function test_inbound_verify_requires_expected_client_id()
    {
        $inbound = $this->inboundProfile();
        unset($inbound['token']['expected_client_id']);
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('i', $inbound, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_inbound_token_verification_requires_authentication_driver()
    {
        $inbound                   = $this->inboundProfile();
        $inbound['authentication'] = [];
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('missing-auth-driver', $inbound, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_rs256_verify_requires_kid_whitelist()
    {
        $inbound = $this->inboundProfile();
        unset($inbound['token']['allowed_kids']);
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('i', $inbound, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_issue_requires_subject_id()
    {
        $config = $this->outboundProfile();
        unset($config['subject_id']);
        $config['token'] = array_merge($config['token'], ['issue_enabled' => true]);
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('p', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_inbound_profile_rejects_token_attach_enabled()
    {
        $config                            = $this->inboundProfile();
        $config['token']['attach_enabled'] = true;
        $config['token']['signing_key_id'] = 'jwt-private-2026-08';
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('inbound-attach', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_inbound_profile_rejects_token_issue_enabled()
    {
        $config                            = $this->inboundProfile();
        $config['token']['issue_enabled']  = true;
        $config['token']['signing_key_id'] = 'jwt-private-2026-08';
        $config['subject_id']              = 'order-api';
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('inbound-issue', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_outbound_profile_rejects_token_verify_enabled()
    {
        $config                                = $this->outboundProfile();
        $config['token']['verify_enabled']     = true;
        $config['token']['expected_client_id'] = 'product-center';
        $config['token']['allowed_kids']       = ['jwt-private-2026-08' => 'jwt-public-2026-08'];
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('outbound-verify', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_token_revocation_requires_inbound_token_verification()
    {
        $config                     = $this->outboundProfile();
        $config['token_revocation'] = ['enabled' => true, 'driver' => 'cache'];
        
        $this->expectException(ConfigurationException::class);
        \Tozo\Security\Profile::fromConfig('outbound-revocation', $config, new ArrayKeyProvider($this->defaultKeys()));
    }
    
    public function test_disabled_profile_skips_validation()
    {
        $profile = \Tozo\Security\Profile::fromConfig('off', array_merge(
            $this->outboundProfile(),
            ['enabled' => false, 'direction' => 'bogus']
        ), new ArrayKeyProvider($this->defaultKeys()));
        
        $this->assertFalse($profile->isEnabled());
    }
    
    public function test_enabled_must_be_boolean()
    {
        foreach (['false', 0, 1] as $enabled) {
            $config            = $this->outboundProfile();
            $config['enabled'] = $enabled;
            
            try {
                \Tozo\Security\Profile::fromConfig(
                    'invalid-enabled',
                    $config,
                    new ArrayKeyProvider($this->defaultKeys())
                );
                $this->fail('Non-boolean enabled value was accepted');
            } catch (ConfigurationException $exception) {
                $this->assertStringContainsString('enabled', $exception->getMessage());
            }
        }
    }
    
    public function test_security_switches_must_be_boolean()
    {
        foreach ([
                     ['signature', 'enabled'],
                     ['encryption', 'enabled'],
                     ['response_integrity', 'required'],
                     ['token', 'attach_enabled'],
                     ['token', 'verify_enabled'],
                     ['token', 'issue_enabled'],
                     ['token_revocation', 'enabled'],
                 ] as $path) {
            $config                     = $this->outboundProfile();
            $config[$path[0]][$path[1]] = 'false';
            
            try {
                \Tozo\Security\Profile::fromConfig(
                    'invalid-switch',
                    $config,
                    new ArrayKeyProvider($this->defaultKeys())
                );
                $this->fail('Non-boolean security switch was accepted: ' . implode('.', $path));
            } catch (ConfigurationException $exception) {
                $this->assertStringContainsString(implode('.', $path), $exception->getMessage());
            }
        }
    }
    
    public function test_profile_identity_fields_must_be_strings()
    {
        foreach ([
                     ['direction', 1],
                     ['client_id', 0],
                     ['subject_type', true],
                     ['subject_id', 42],
                     ['target_service', 0],
                     ['security_mode', 1],
                 ] as $field) {
            $config            = $this->outboundProfile();
            $config[$field[0]] = $field[1];
            
            try {
                \Tozo\Security\Profile::fromConfig(
                    'invalid-identity-type',
                    $config,
                    new ArrayKeyProvider($this->defaultKeys())
                );
                $this->fail('Non-string identity field was accepted: ' . $field[0]);
            } catch (ConfigurationException $exception) {
                $this->assertStringContainsString($field[0], $exception->getMessage());
            }
        }
    }
}
