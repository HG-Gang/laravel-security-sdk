<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * SystemClock
 *
 * 文件功能：
 * - ClockInterface 的系统时钟实现
 */

namespace Tozo\Security\Clock;

use Tozo\Security\Contracts\ClockInterface;

class SystemClock implements ClockInterface
{
	/**
	 * 返回当前 Unix 时间戳（秒）。
	 *
	 * 使用范围：签名时间戳、Token iat/nbf/exp、认证证明窗口等全部时间判定。
	 * 适用场景：生产环境唯一时间出口；测试以固定时钟实现替换本类。
	 *
	 * 函数逻辑：
	 * 1. 返回 time()。
	 *
	 * @return int Unix 秒级时间戳。示例：1700000000
	 */
	public function now()
	{
		return time();
	}
}
