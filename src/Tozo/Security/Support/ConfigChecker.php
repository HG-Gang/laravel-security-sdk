<?php
/**
 * Created by PhpStorm.
 * Project name Tozo-security-sdk-php.
 * User: Huang Gang
 * Date: 2026/08/28
 * Time: 01:10
 */

/**
 * ConfigChecker
 *
 * 文件功能：
 * - 配置体检器（框架无关）：结构校验 + 可选运行时探测
 * - 结构链路（设计 §16 规则 9）：功能开关 → Profile 引用 → driver → key ID 格式 → 接口依赖
 * - ServiceProvider::boot 与 artisan tozo:security:check-config 共用同一事实来源
 *
 * 安全边界：
 * - 结构校验不读取生产密钥、不连接 Redis
 * - --runtime 仅探测密钥“存在性”与缓存连通性，任何输出不得包含密钥值
 */

namespace Tozo\Security\Support;

use Throwable;
use Tozo\Security\Profile;
use Tozo\Security\Contracts\KeyProviderInterface;
use Tozo\Security\Exceptions\ConfigurationException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;

class ConfigChecker
{
	/**
	 * key_id 合法格式：字母数字与点、横线、下划线，长度 1 到 128。
	 * 该字符集与 FileKeyProvider 的路径拼接白名单一致——放宽会让 key_id 里的
	 * 斜杠或 .. 拼出目录穿越路径。长度上限 128 是为了避免超长标识拖垮文件系统与日志。
	 * 展开器推导出的 key_id 也必须落在此集合内，否则体检会把自己生成的标识判为非法。
	 */
	public const KEY_ID_PATTERN = '/^[A-Za-z0-9._-]{1,128}$/';
	
	/**
	 * 执行配置体检。
	 *
	 * 使用范围：ServiceProvider::boot（结构级）与 tozo:security:check-config 命令（可选 --runtime）。
	 * 适用场景：部署前 CI 流水线、config:cache 之后启动之前的主动体检。
	 *
	 * 函数逻辑：
	 * 1. 结构级：逐 Profile 走 Profile::fromConfig 全量校验；跨层 feature 矩阵；default_profile 存在性；
	 *    全部引用 key_id 的格式白名单校验。
	 * 2. runtime=true 时追加：每个引用 key_id 的 hasKey 存在性探测；缓存 put/has/forget 连通性探测。
	 * 3. 汇总 errors/warnings 返回结构化结果，由调用方决定抛异常或格式化输出。
	 *
	 * @param array $config 完整配置｜tozo_security 配置树。示例：include config/tozo_security.php 的返回值
	 * @param KeyProviderInterface|null $keys 密钥提供器｜runtime 探测使用；null 时跳过密钥检查。示例：new EnvKeyProvider()
	 * @param CacheRepository|null $cache 缓存仓储｜runtime 探测 ReplayStore 后端连通性；null 跳过。示例：Laravel Cache Repository
	 * @param bool $runtime 运行时探针开关｜true 追加外部依赖探测。示例：false
	 * @return array{ok:bool,errors:string[],warnings:string[],profiles:int} 体检结果｜ok=errors 为空；profiles 为已启用数量。示例：["ok"=>true,"errors"=>[],"warnings"=>[],"profiles"=>2]
	 */
	public function check(
		array                $config,
		KeyProviderInterface $keys = null,
		CacheRepository      $cache = null,
		bool                 $runtime = false
	)
	{
		$errors   = [];
		$warnings = [];
		
		$features    = is_array($config['features'] ?? null) ? $config['features'] : [];
		$profilesCfg = is_array($config['profiles'] ?? null) ? $config['profiles'] : [];
		$appDefaults = is_array($config['defaults'] ?? null) ? $config['defaults'] : [];
		
		$registry       = [];
		$referencedKeys = [];
		
		foreach ($profilesCfg as $name => $profileConfig) {
			if (!is_array($profileConfig)) {
				$errors[] = "profile [{$name}] configuration must be an array";
				continue;
			}
			
			try {
				$profile = Profile::fromConfig((string)$name, $profileConfig, new DummyKeyProvider(), $appDefaults);
			} catch (ConfigurationException $e) {
				$errors[] = "profile [{$name}]: {$e->getMessage()}";
				continue;
			}
			
			if (!$profile->isEnabled()) {
				continue;
			}
			
			$registry[(string)$name] = $profile;
			
			// 收集引用的用途 key_id（仅格式校验；runtime 再探存在性）。
			foreach ($this->collectReferencedKeyIds($profile) as $keyId) {
				$referencedKeys[$keyId] = true;
			}
		}
		
		// 跨层矩阵：Profile 引用了未启用的功能 → 启动即失败。
		$matrix = [
			'authentication'     => static function (Profile $p) {
				return $p->isInbound() && $p->getAuthenticationDriver() !== null;
			},
			'audit'              => static function (Profile $p) {
				return $p->isOutbound();
			},
			'http_client'        => static function (Profile $p) {
				return $p->isOutbound();
			},
			'signature'          => static function (Profile $p) {
				return ($p->getSignatureConfig()['enabled'] ?? false) === true;
			},
			'encryption'         => static function (Profile $p) {
				return ($p->getEncryptionConfig()['enabled'] ?? false) === true;
			},
			'response_integrity' => static function (Profile $p) {
				return ($p->getResponseIntegrityConfig()['required'] ?? false) === true;
			},
			'token_verifier'     => static function (Profile $p) {
				return $p->isTokenVerifyEnabled();
			},
			'token_issuer'       => static function (Profile $p) {
				return $p->isTokenIssueEnabled() || $p->isTokenAttachEnabled();
			},
			'token_revocation'   => static function (Profile $p) {
				return $p->isTokenRevocationEnabled();
			},
			'scope'              => static function (Profile $p) {
				return $p->isInbound()
					&& ($p->isTokenVerifyEnabled() || $p->getAllowedScopes() !== []);
			},
		];
		
		foreach ($registry as $name => $profile) {
			foreach ($matrix as $feature => $check) {
				if ($check($profile) && empty($features[$feature])) {
					$errors[] = "profile [{$name}] uses feature [{$feature}] which is disabled in tozo_security.features";
				}
			}
		}
		
		// AuditSink 是宿主内共享绑定；体检必须提前拒绝 cache/log 混用，避免与 Provider 启动结论不一致。
		$auditDriver = null;
		foreach ($registry as $profile) {
			if (!$profile->isOutbound()) {
				continue;
			}
			
			$audit    = $profile->getAuditConfig();
			$declared = isset($audit['driver']) && is_string($audit['driver']) && $audit['driver'] !== ''
				? $audit['driver']
				: 'cache';
			
			if ($auditDriver !== null && $auditDriver !== $declared) {
				$errors[] = "outbound Profiles must use one audit driver; found [{$auditDriver}] and [{$declared}]";
				break;
			}
			
			$auditDriver = $declared;
		}
		
		// default_profile 必须指向存在的启用 Profile。
		$default = (string)($config['default_profile'] ?? '');
		if ($default !== '' && !isset($registry[$default])) {
			$errors[] = "default_profile [{$default}] does not match any enabled profile";
		}
		
		// key_id 格式白名单。
		foreach (array_keys($referencedKeys) as $keyId) {
			if (preg_match(self::KEY_ID_PATTERN, $keyId) !== 1) {
				$errors[] = "illegal key_id format [{$keyId}]";
			}
		}
		
		// 运行时探测：只报存在性与连通性，绝不输出密钥值。
		if ($runtime) {
			if ($keys !== null) {
				foreach (array_keys($referencedKeys) as $keyId) {
					if (!$keys->hasKey($keyId)) {
						$errors[] = "runtime: key [{$keyId}] is not resolvable by the configured provider";
					}
				}
			}
			
			if ($cache !== null) {
				try {
					$probe = 'tozo_probe|' . bin2hex(random_bytes(6));
					$cache->put($probe, 1, 5);
					$hit = $cache->has($probe);
					$cache->forget($probe);
					if (!$hit) {
						$errors[] = 'runtime: cache probe failed (write/read roundtrip)';
					}
				} catch (Throwable $e) {
					$errors[] = 'runtime: replay store backend unavailable';
				}
			}
		}
		
		return [
			'ok'       => $errors === [],
			'errors'   => $errors,
			'warnings' => $warnings,
			'profiles' => count($registry),
		];
	}
	
	/**
	 * 收集 Profile 引用的全部用途 key_id。
	 *
	 * 使用范围：check() 内部格式与存在性校验的数据收集步骤。
	 * 适用场景：一次性枚举签名/加密/响应完整性/Token 签名/kid 映射/认证六类引用。
	 *
	 * 函数逻辑：
	 * 1. 按段读取各 getter，非空即收入集合（去重由调用方数组键保证）。
	 *
	 * @param Profile $profile 已校验 Profile｜引用来源。示例：Profile::fromConfig(...)
	 * @return string[] 引用的 key_id 列表（可能含重复，由调用方去重）。示例：["order-signing","order-encryption"]
	 */
	private function collectReferencedKeyIds(Profile $profile)
	{
		$ids = [];
		
		foreach ([
			         $profile->getSignatureKeyId(),
			         $profile->getEncryptionKeyId(),
			         $profile->getTokenSigningKeyId(),
			         $profile->getAuthenticationKeyId(),
		         ] as $id) {
			if (is_string($id) && $id !== '') {
				$ids[] = $id;
			}
		}
		
		$ri = $profile->getResponseIntegrityConfig();
		foreach (['encryption', 'signature'] as $sub) {
			$id = $ri[$sub]['key_id'] ?? null;
			if (is_string($id) && $id !== '') {
				$ids[] = $id;
			}
		}
		
		foreach (array_values($profile->getAllowedKids()) as $id) {
			$ids[] = $id;
		}
		
		return $ids;
	}
}
