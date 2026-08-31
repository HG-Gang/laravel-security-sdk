// Created by PhpStorm.
// Project name Tozo-security-sdk-php.
// User: Huang Gang
// Date: 2026/08/28
// Time: 01:10

// Package main 是 Tozo Security Protocol v1 的 Go 独立参考实现。
//
// 目的与 Python 实现相同：验证 Protocol v1 是否真正语言无关。
// 按 protocol/README.md 的文字规则从零实现，不移植 PHP 源码，
// 再用 protocol/test-vectors-v1.json 逐条比对。
//
// Go 的 net/url 对 query 的解析与 PHP/Python 差异较大（例如 url.Values 会
// 丢失重复键顺序、不区分方括号键），因此本实现刻意不使用 url.ParseQuery，
// 而是按协议规则手工拆解字节 —— 这正是协议要求"不得依赖本语言默认序列化"的体现。
//
// 依赖：仅标准库。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	protocolVersion = "1"
	envelopeVersion = "1"
)

// base64URLEncode 按 RFC 4648 §5 编码并去掉尾部 padding。
func base64URLEncode(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// base64URLDecode 严格解码 Base64URL。
//
// 非法输入返回 ok=false，不做宽松解码：宽松解码会把被篡改的签名
// 解出一段"看起来有效"的字节，使后续常量时间比较失去意义。
func base64URLDecode(encoded string) ([]byte, bool) {
	if encoded == "" {
		return nil, false
	}

	// 只接受 Base64URL 字母表；出现 + / = 或其他字符即视为非法。
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		isAlnum := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '-' && c != '_' {
			return nil, false
		}
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}

	return decoded, true
}

// isUnreserved 判断字节是否属于 RFC 3986 未保留字符集。
func isUnreserved(c byte) bool {
	if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
		return true
	}

	return c == '-' || c == '_' || c == '.' || c == '~'
}

// percentEncode 按 RFC 3986 编码单个 query 键或值。
//
// 不使用 url.QueryEscape：它把空格编码为 +，与协议要求的 %20 不一致。
func percentEncode(value string) string {
	var builder strings.Builder

	for i := 0; i < len(value); i++ {
		c := value[i]
		if isUnreserved(c) {
			builder.WriteByte(c)
			continue
		}

		builder.WriteString(fmt.Sprintf("%%%02X", c))
	}

	return builder.String()
}

// percentDecode 解码百分号编码，并把 + 解为空格。
//
// + 表示空格是 form-urlencoded 语义；字面加号必须以 %2B 传输。
func percentDecode(value string) string {
	var out []byte

	for i := 0; i < len(value); i++ {
		c := value[i]

		switch {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(value):
			decoded, err := hex.DecodeString(value[i+1 : i+3])
			if err != nil {
				// 非法转义序列按字面量保留，与宽松解码器行为一致。
				out = append(out, c)
				continue
			}
			out = append(out, decoded[0])
			i += 2
		default:
			out = append(out, c)
		}
	}

	return string(out)
}

// normalizePath 规范化 HTTP path。
//
// 规则见 protocol/README.md §path 规范化：
// 仅带 scheme 时取 URL 的 path；剥离 query 与 fragment；折叠连续斜杠；
// 逐段解析（空段与 "." 丢弃，".." 回退一层，根目录时忽略）。
func normalizePath(path string) string {
	// 手工检测 scheme，避免不同语言 URL 解析器对 "//host" 的处理差异。
	if idx := strings.Index(path, "://"); idx > 0 && isSchemeChars(path[:idx]) {
		rest := path[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			path = rest[slash:]
		} else {
			path = "/"
		}
	}

	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		path = path[:cut]
	}

	if path == "" {
		return "/"
	}

	var segments []string
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." {
			continue
		}

		if segment == ".." {
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
			continue
		}

		segments = append(segments, segment)
	}

	if len(segments) == 0 {
		return "/"
	}

	return "/" + strings.Join(segments, "/")
}

// isSchemeChars 判断字符串是否为合法 URI scheme。
func isSchemeChars(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlnum := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '+' && c != '-' && c != '.' {
			return false
		}
	}

	return true
}

// canonicalQueryString 规范化线上原始 query 字符串。
//
// 步骤见 protocol/README.md §query 规范化。刻意不使用 url.ParseQuery：
// 它返回 map，会丢失重复键的原始顺序并把方括号键当作字面键名，
// 无法保证与其他语言产出同一字节。
func canonicalQueryString(rawQuery string) string {
	rawQuery = strings.TrimLeft(rawQuery, "?")
	if rawQuery == "" {
		return ""
	}

	var pairs []string
	for _, segment := range strings.Split(rawQuery, "&") {
		if segment == "" {
			continue
		}

		key := segment
		value := ""
		if eq := strings.Index(segment, "="); eq >= 0 {
			key = segment[:eq]
			value = segment[eq+1:]
		}

		pairs = append(pairs, percentEncode(percentDecode(key))+"="+percentEncode(percentDecode(value)))
	}

	// 按字节序排序：Go 的字符串比较本身就是字节序，与协议要求一致。
	sort.Strings(pairs)

	return strings.Join(pairs, "&")
}

// queryEntry 表示一个结构化 query 条目，保留声明顺序。
//
// 使用切片而非 map：Go 的 map 遍历顺序随机，无法复现向量的 wire 字节。
type queryEntry struct {
	Key   string
	Value interface{}
}

// buildQueryString 把结构化 query 渲染为线上字节串。
//
// 顺序列表 → 重复键；映射 → 方括号子键（保留子键名避免字节碰撞）。
func buildQueryString(entries []queryEntry) string {
	var pairs []string

	var appendPair func(key string, value interface{})
	appendPair = func(key string, value interface{}) {
		switch typed := value.(type) {
		case []queryEntry:
			// 映射：展开为 key[sub] 形态，保留子键名。
			for _, entry := range typed {
				appendPair(key+"["+entry.Key+"]", entry.Value)
			}
		case []interface{}:
			// 顺序列表：复用同一个键名。
			for _, item := range typed {
				appendPair(key, item)
			}
		case nil:
			pairs = append(pairs, percentEncode(key)+"=")
		case string:
			pairs = append(pairs, percentEncode(key)+"="+percentEncode(typed))
		default:
			pairs = append(pairs, percentEncode(key)+"="+percentEncode(fmt.Sprintf("%v", typed)))
		}
	}

	for _, entry := range entries {
		appendPair(entry.Key, entry.Value)
	}

	return strings.Join(pairs, "&")
}

// canonicalQuery 规范化结构化 query：先渲染为线上字节，再走字符串规范化。
func canonicalQuery(entries []queryEntry) string {
	if len(entries) == 0 {
		return ""
	}

	return canonicalQueryString(buildQueryString(entries))
}

// normalizeContentType 取分号前主类型，trim 后转小写。
func normalizeContentType(contentType string) string {
	if contentType == "" {
		return ""
	}

	main := contentType
	if semi := strings.Index(contentType, ";"); semi >= 0 {
		main = contentType[:semi]
	}

	return strings.ToLower(strings.TrimSpace(main))
}

// sha256Hex 返回 UTF-8 字节的 SHA-256 十六进制小写。
func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))

	return hex.EncodeToString(sum[:])
}

// buildCanonicalRequest 构造 11 字段规范化串，字段顺序固定不可调整。
func buildCanonicalRequest(
	method, path, canonicalQueryValue, contentType, body string,
	timestamp int64,
	nonce, clientID, targetService, keyID string,
) string {
	return strings.Join([]string{
		protocolVersion,
		strings.ToUpper(method),
		normalizePath(path),
		canonicalQueryValue,
		normalizeContentType(contentType),
		sha256Hex(body),
		fmt.Sprintf("%d", timestamp),
		nonce,
		clientID,
		targetService,
		keyID,
	}, "\n")
}

// signRequest 对规范化串生成 HMAC-SHA256 签名（Base64URL 无 padding）。
func signRequest(canonical, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))

	return base64URLEncode(mac.Sum(nil))
}

// buildAeadAad 构造 AES-GCM 的 7 字段方向绑定 AAD。
func buildAeadAad(direction, clientID, targetService, method, path, keyID string) string {
	return strings.Join([]string{
		envelopeVersion,
		direction,
		clientID,
		targetService,
		strings.ToUpper(method),
		normalizePath(path),
		keyID,
	}, "\n")
}

// buildResponseCanonical 构造响应签名的 6 字段原文；direction 固定为字面量 response。
func buildResponseCanonical(body, clientID, targetService, keyID string) string {
	return strings.Join([]string{
		envelopeVersion,
		"response",
		clientID,
		targetService,
		sha256Hex(body),
		keyID,
	}, "\n")
}

// replayTTL 计算 ReplayStore TTL；实现不得低于该结果。
func replayTTL(maxAgeSeconds, clockSkewSeconds, safetyMarginSeconds int) int {
	return maxAgeSeconds + 2*clockSkewSeconds + safetyMarginSeconds
}
