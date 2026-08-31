<?php

/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ReplayStoreInterface
 *
 * 文件功能：
 * - 定义防重放状态存储契约
 * - 要求原子“只写一次”语义（record 等价 SET NX EX）与 TTL 机制
 */

namespace Tozo\Security\Contracts;

interface ReplayStoreInterface
{
    /**
     * 原子登记防重放键契约。
     *
     * 使用范围：HmacSha256Signer.verify / HmacBearerAuthenticator.authenticate 在密码学验证通过后调用。
     * 适用场景：多实例部署下同一请求被网关重发时，仅允许一方通过。
     *
     * 函数逻辑：
     * 1. 实现方以原子操作写入 key（不存在才写）。
     * 2. 已存在返回 true（重放）；首次写入返回 false；故障必须抛异常 fail-closed。
     *
     * TTL 必须随调用传入，不得依赖 setTtl() 留在实例上的状态：
     * 本接口的实现按 singleton 注册，setTtl() 与 record() 之间若被其他 Profile
     * 的调用插入（常驻进程并发或嵌套调用），长窗口 Profile 会拿到短 TTL，
     * 导致防重放窗口被静默缩短。传参使这一对操作不可分割。
     *
     * @param string $key 防重放键｜client|nonce 组合键。示例："tozo_replay|pc|5f1c..."
     * @param int|null $ttl 存活时长(秒)｜按窗口公式计算；null 时回退实例默认值（仅为兼容旧调用方）。示例：425
     * @return bool true=已存在（重放）；false=首次登记成功。示例：false（首次登记成功）
     * @throws \RuntimeException 存储不可用时抛出（由适配器包装为专用异常）。
     */
    public function record(string $key, int $ttl = null);

    /**
     * 查询防重放键存在性契约。
     *
     * 使用范围：辅助诊断与测试断言。
     * 适用场景：确认某 Nonce 是否已被消费。
     *
     * 函数逻辑：
     * 1. 实现方返回 key 是否存在；故障抛异常不降级。
     *
     * @param string $key 防重放键｜同 record。示例："tozo_replay|pc|5f1c..."
     * @return bool true=已登记。示例：true
     * @throws \RuntimeException 存储不可用。
     */
    public function isReplayed(string $key);

    /**
     * 设置实例级默认 Nonce 保留时长契约（秒）。
     *
     * 使用范围：容器装配阶段设定兜底值。
     * 适用场景：为未显式传入 TTL 的调用提供默认保留期。
     *
     * 不要在每次验证前调用本方法来"下发"本次 TTL —— 实现按 singleton 注册，
     * 该写入会被后续其他 Profile 的调用覆盖。本次 TTL 请通过 record() 参数传入。
     *
     * 函数逻辑：
     * 1. 实现方保存 ttl 作为 record() 未传 TTL 时的回退值；非法值应拒绝。
     *
     * @param int $ttl 存活时长(秒)｜正整数。示例：425
     * @return void 无返回值。
     */
    public function setTtl(int $ttl);

    /**
     * 返回防重放 driver 名称契约。
     *
     * 使用范围：日志标注与运行期后端可观测。
     * 适用场景：确认当前为 laravel_cache/redis 等实现。
     *
     * 函数逻辑：
     * 1. 返回实现方 driver 标识。
     *
     * @return string driver 标识。示例："laravel_cache"
     */
    public function getDriver();
}
