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
use Tozo\Security\Identity\Subject;
use Tozo\Security\Key\ArrayKeyProvider;
use Tozo\Security\Scope\ScopeAuthorizer;
use Tozo\Security\Exceptions\ScopeDeniedException;
use Tozo\Security\Exceptions\ConfigurationException;
use Tozo\Security\Exceptions\SubjectTypeMismatchException;

class ScopeAuthorizerTest extends TestCase
{
    public function test_required_scope_within_granted_and_allowed_passes()
    {
        $this->authorizer()->authorize(
            $this->subject(['scope' => ['order.read', 'order.write']]),
            $this->profile(),
            ['order.read', 'order.write']
        );
        
        $this->addToAssertionCount(1);
    }
    
    private function authorizer()
    {
        return new ScopeAuthorizer();
    }
    
    private function subject(array $overrides = [])
    {
        return new Subject(array_merge([
            'sub'          => 'service:product-center',
            'client_id'    => 'product-center',
            'iss'          => 'tozo-auth',
            'aud'          => ['order-api'],
            'subject_type' => 'service',
            'scope'        => ['order.read'],
        ], $overrides));
    }
    
    private function profile()
    {
        return \Tozo\Security\Profile::fromConfig(
            'i',
            $this->inboundProfile(),
            new ArrayKeyProvider($this->defaultKeys())
        );
    }
    
    public function test_missing_granted_scope_is_denied()
    {
        $this->expectException(ScopeDeniedException::class);
        $this->authorizer()->authorize($this->subject(), $this->profile(), ['order.write']);
    }
    
    public function test_scope_outside_profile_allowance_is_denied()
    {
        // 主体携带 profile 白名单之外的 scope：required 命中它也必须拒绝。
        $this->expectException(ScopeDeniedException::class);
        $this->authorizer()->authorize(
            $this->subject(['scope' => ['billing.admin']]),
            $this->profile(),
            ['billing.admin']
        );
    }
    
    public function test_subject_type_outside_whitelist_is_rejected()
    {
        $this->expectException(SubjectTypeMismatchException::class);
        $this->authorizer()->authorize(
            $this->subject(['subject_type' => 'user']),
            $this->profile(),
            []
        );
    }
    
    public function test_wildcard_requirement_is_configuration_error()
    {
        $this->expectException(ConfigurationException::class);
        $this->authorizer()->authorize($this->subject(), $this->profile(), ['order.*']);
    }
}
