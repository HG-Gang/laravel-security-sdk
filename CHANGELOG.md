# 变更日志

本文件记录 `tozo/security-sdk` 的版本变更。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## 关于 0.0.x 阶段的兼容性承诺

当前处于 `0.0.x`，按 SemVer 规范这是初始开发阶段：**任何版本号递增都可能包含破坏性变更**。
Composer 中 `^0.0.9` 只匹配 `0.0.9` 本身，要接受后续补丁需写 `^0.0`。

唯一例外是 **Protocol v1 保持冻结**：签名规范化串的 11 个字段、顺序、连接方式与
AES-GCM 信封格式不会在 `0.0.x` 内变更。协议行为的任何改动都必须递增协议版本号，
由 `protocol/test-vectors-v1.json` 与 `composer vectors-check` 强制保证。

## [0.0.9] - 2026-08-30

### 变更

- **配置精简**：配置键从 224 个降到 3 个（`service` / `environment` / `peers`）。
  每声明一个对端自动展开为出站与入站两个 Profile 及四个用途密钥标识，
  展开结果仍经 `Profile::validate` 全量校验，未放宽任何约束。
- 出站调用改为按对端标识选路：`app('tozo.http')->to('pos-api')`，不再需要记 Profile 名。
- 密钥来源改为受控目录 `storage/app/tozo/keys/`，不再经过 `.env`。
- 接入步数从约 38 步降到 6 步。

### 移除

- `config/tozo_services.php`：`base_urls` 并入 `peers`，`tls` / `http` 下沉为 SDK 内置默认值。
- 每套 31 个环境变量的 `.env` 模板：极简配置不读 `.env`。
- 手写 HTTP Client 样板（每套 108 行）：由 SDK 的 `to()` 提供。

### 修复

- 示例控制器的重复数组键（`'health' => 'ok'` 重复 33 次，后者静默覆盖前者）。
- `return` 之后的不可达代码，以及末尾 `return` 引用未定义变量。

### 新增

- `docs/四系统实际配置文件-v0.0.9/`：45 个接入示例文件，由 `composer examples` 生成，
  `composer examples-check` 校验其未与生成规则脱节。
- 四系统 Composer 安装与两两互调操作指南、各模块使用说明书（20 章）。

### 安全

- 文档与示例中的服务域名一律使用 RFC 2606 保留域名（`example.com` / `example.test`）作为占位值，
  不含任何真实部署地址。占位域名不会解析到真实主机，照抄上线会在出站时连接失败——
  这是有意为之，防止占位值被误当成可用配置。

## [0.0.6] - 2026-08-27

### 新增

- 跨语言一致性验证：Python 与 Go 独立实现消费冻结的协议向量，逐字节比对。
  跨语言一致性刻意不依赖 PHP SDK，必须由外部实现证明。
- CI 落地：PHP 7.4 / 8.0 / 8.1 / 8.2 矩阵，含 `--prefer-lowest` 单独作业；
  协议向量作业与分发包内容检查。

## [0.0.5] - 2026-08-27

### 新增

- PHP 7.4 兼容性落地，7.4 为声明的最低版本基线。
- Protocol v1 测试向量冻结。v0.0.4 刚重写 query 与 path 规范化，
  不冻结向量则第二语言实现会重踩同类坑。

### 修复

- 本版修复 5 项缺陷，与 v0.0.4 的 16 项累计 21 项。

## [0.0.4] - 2026-08-27

### 修复

- 全量审查与闭环修复，共 16 项缺陷。
- 重写 query 与 path 规范化。
- 更正 v0.0.3 报告的两处过宽结论：query 修复此前只做了出站侧；
  Response Integrity 并非「逻辑完整」。

## [0.0.2] - 2026-08-21

### 新增

- 按设计报告实现 Signature 模块、信封 v1 AES-GCM、JWT `kid` 白名单、
  fail-closed 存储语义。

## 未发布为 Git 标签的版本

`0.0.1`、`0.0.3`、`0.0.7`、`0.0.8` 是开发过程中的内部迭代节点，
其代码状态未作为独立提交保留，因此没有对应的 Git 标签。
`0.0.7` 与 `0.0.8` 的配置文件在 `docs/` 下保留作回退参照。

历史细节见 `docs/SDK-需求变更记录.txt`。

[0.0.9]: https://github.com/HG-Gang/laravel-security-sdk/releases/tag/v0.0.9
