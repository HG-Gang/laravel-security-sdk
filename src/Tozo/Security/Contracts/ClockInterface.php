<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ClockInterface
 *
 * 文件功能：
 * - 时间源契约：隔离 time() 使时间窗与过期逻辑可测试
 */

namespace Tozo\Security\Contracts;

interface ClockInterface
{
	/**
	 * 当前 Unix 时间戳契约（秒）。
	 *
	 * 使用范围：Signer.sign/verify、JwtTokenIssuer.issue 等全部时间判定。
	 * 适用场景：生产注入 SystemClock；测试注入固定时钟复现过期/越窗场景。
	 *
	 * 函数逻辑：
	 * 1. 实现方返回当前 Unix 秒级时间戳。
	 *
	 * @return int Unix 秒级时间戳。示例：1700000000
	 */
	public function now();
}
