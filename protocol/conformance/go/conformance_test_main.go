// Created by PhpStorm.
// Project name Tozo-security-sdk-php.
// User: Huang Gang
// Date: 2026/08/28
// Time: 01:10

// Protocol v1 一致性测试 —— Go 实现消费冻结向量。
//
// 运行：
//
//	cd protocol/conformance/go && go run .
//
// 返回码：0 = 全部一致；1 = 存在不一致。
//
// 该程序只读取 protocol/test-vectors-v1.json，不修改任何向量。
// 出现不一致时必须先判断是 Go 实现理解偏差还是协议规范歧义：
// 前者改实现，后者改协议文档并升版本。
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

var (
	failures []string
	checks   int
)

// check 比对单条向量并记录结果。
func check(group, label string, expected, actual interface{}) {
	checks++

	expectedText := fmt.Sprintf("%v", expected)
	actualText := fmt.Sprintf("%v", actual)

	if expectedText != actualText {
		failures = append(failures, fmt.Sprintf(
			"[%s] %s\n    expected: %q\n    actual:   %q",
			group, label, expectedText, actualText,
		))
	}
}

// orderedEntries 把 JSON 对象按其在原文中的出现顺序转成 queryEntry 切片。
//
// Go 的 map 遍历顺序随机，直接用 map 无法复现向量的 wire 字节，
// 因此这里用 json.Decoder 逐 token 读取以保留声明顺序。
func orderedEntries(raw json.RawMessage) ([]queryEntry, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))

	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("expected JSON object, got %v", token)
	}

	var entries []queryEntry

	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}

		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %v", keyToken)
		}

		var rawValue json.RawMessage
		if err := decoder.Decode(&rawValue); err != nil {
			return nil, err
		}

		value, err := decodeValue(rawValue)
		if err != nil {
			return nil, err
		}

		entries = append(entries, queryEntry{Key: key, Value: value})
	}

	return entries, nil
}

// decodeValue 递归解析 JSON 值：对象保留顺序、数组转 []interface{}、标量转 string。
func decodeValue(raw json.RawMessage) (interface{}, error) {
	trimmed := trimSpace(raw)
	if len(trimmed) == 0 {
		return "", nil
	}

	switch trimmed[0] {
	case '{':
		return orderedEntries(raw)
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}

		var out []interface{}
		for _, item := range items {
			value, err := decodeValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}

		return out, nil
	default:
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			return text, nil
		}

		var number float64
		if err := json.Unmarshal(raw, &number); err == nil {
			return fmt.Sprintf("%v", number), nil
		}

		return "", nil
	}
}

// trimSpace 跳过 JSON 原文前导空白，用于判断值的首字符类型。
func trimSpace(raw []byte) []byte {
	return bytes.TrimLeft(raw, " \t\r\n")
}

type vectorFile struct {
	Meta struct {
		ProtocolVersion string `json:"protocol_version"`
		HmacKeyASCII    string `json:"hmac_key_ascii"`
	} `json:"_meta"`

	NormalizePath []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"normalize_path"`

	CanonicalQueryString []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"canonical_query_string"`

	CanonicalQueryArray []struct {
		Input    json.RawMessage `json:"input"`
		Wire     string          `json:"wire"`
		Expected string          `json:"expected"`
	} `json:"canonical_query_array"`

	NormalizeContentType []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"normalize_content_type"`

	Base64URLEncode []struct {
		InputHex string `json:"input_hex"`
		Expected string `json:"expected"`
	} `json:"base64url_encode"`

	Base64URLDecode []struct {
		Input       string  `json:"input"`
		ExpectedHex *string `json:"expected_hex"`
	} `json:"base64url_decode"`

	Signature []struct {
		Name  string `json:"name"`
		Input struct {
			Method        string `json:"method"`
			Path          string `json:"path"`
			Query         string `json:"query"`
			ContentType   string `json:"content_type"`
			Body          string `json:"body"`
			Timestamp     int64  `json:"timestamp"`
			Nonce         string `json:"nonce"`
			ClientID      string `json:"client_id"`
			TargetService string `json:"target_service"`
			KeyID         string `json:"key_id"`
		} `json:"input"`
		Canonical  string `json:"canonical"`
		BodySHA256 string `json:"body_sha256"`
		Signature  string `json:"signature"`
	} `json:"signature"`

	AeadAad []struct {
		Input struct {
			Direction     string `json:"direction"`
			Method        string `json:"method"`
			Path          string `json:"path"`
			KeyID         string `json:"key_id"`
			ClientID      string `json:"client_id"`
			TargetService string `json:"target_service"`
		} `json:"input"`
		Expected string `json:"expected"`
	} `json:"aead_aad"`

	ResponseSignature []struct {
		Input struct {
			Body          string `json:"body"`
			ClientID      string `json:"client_id"`
			TargetService string `json:"target_service"`
			KeyID         string `json:"key_id"`
		} `json:"input"`
		Canonical string `json:"canonical"`
		Signature string `json:"signature"`
	} `json:"response_signature"`

	ReplayTTL []struct {
		MaxAgeSeconds       int `json:"max_age_seconds"`
		ClockSkewSeconds    int `json:"clock_skew_seconds"`
		SafetyMarginSeconds int `json:"replay_safety_margin_seconds"`
		ExpectedTTLSeconds  int `json:"expected_ttl_seconds"`
	} `json:"replay_ttl"`
}

func main() {
	path := filepath.Join("..", "..", "test-vectors-v1.json")

	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("无法读取向量文件 %s: %v\n", path, err)
		os.Exit(1)
	}

	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		fmt.Printf("向量文件解析失败: %v\n", err)
		os.Exit(1)
	}

	if vectors.Meta.ProtocolVersion != protocolVersion {
		fmt.Printf("协议版本不匹配：向量 %s vs 实现 %s\n", vectors.Meta.ProtocolVersion, protocolVersion)
		os.Exit(1)
	}

	secret := vectors.Meta.HmacKeyASCII

	// ---------- path ----------
	for _, item := range vectors.NormalizePath {
		check("normalize_path", fmt.Sprintf("%q", item.Input), item.Expected, normalizePath(item.Input))
	}

	// ---------- query（字符串入口）----------
	for _, item := range vectors.CanonicalQueryString {
		check("canonical_query_string", fmt.Sprintf("%q", item.Input), item.Expected, canonicalQueryString(item.Input))
	}

	// ---------- query（结构化入口）----------
	for _, item := range vectors.CanonicalQueryArray {
		entries, err := orderedEntries(item.Input)
		if err != nil {
			failures = append(failures, fmt.Sprintf("[canonical_query_array] 解析失败: %v", err))
			continue
		}

		label := string(item.Input)
		check("canonical_query_array.wire", label, item.Wire, buildQueryString(entries))
		check("canonical_query_array", label, item.Expected, canonicalQuery(entries))
	}

	// ---------- content-type ----------
	for _, item := range vectors.NormalizeContentType {
		check("normalize_content_type", fmt.Sprintf("%q", item.Input), item.Expected, normalizeContentType(item.Input))
	}

	// ---------- base64url ----------
	for _, item := range vectors.Base64URLEncode {
		var decoded []byte
		if item.InputHex != "" {
			decoded, _ = hex.DecodeString(item.InputHex)
		}

		label := item.InputHex
		if label == "" {
			label = "(empty)"
		}

		check("base64url_encode", label, item.Expected, base64URLEncode(decoded))
	}

	for _, item := range vectors.Base64URLDecode {
		decoded, ok := base64URLDecode(item.Input)

		var actual string
		if ok {
			actual = hex.EncodeToString(decoded)
		} else {
			actual = "<nil>"
		}

		expected := "<nil>"
		if item.ExpectedHex != nil {
			expected = *item.ExpectedHex
		}

		check("base64url_decode", fmt.Sprintf("%q", item.Input), expected, actual)
	}

	// ---------- 完整签名 ----------
	for _, item := range vectors.Signature {
		source := item.Input

		canonical := buildCanonicalRequest(
			source.Method,
			source.Path,
			canonicalQueryString(source.Query),
			source.ContentType,
			source.Body,
			source.Timestamp,
			source.Nonce,
			source.ClientID,
			source.TargetService,
			source.KeyID,
		)

		check("signature.canonical", item.Name, item.Canonical, canonical)
		check("signature.body_sha256", item.Name, item.BodySHA256, sha256Hex(source.Body))
		check("signature.value", item.Name, item.Signature, signRequest(canonical, secret))
	}

	// ---------- AEAD AAD ----------
	for _, item := range vectors.AeadAad {
		source := item.Input

		check(
			"aead_aad",
			source.Direction+" "+fmt.Sprintf("%q", source.Path),
			item.Expected,
			buildAeadAad(source.Direction, source.ClientID, source.TargetService, source.Method, source.Path, source.KeyID),
		)
	}

	// ---------- 响应签名 ----------
	for _, item := range vectors.ResponseSignature {
		source := item.Input

		canonical := buildResponseCanonical(source.Body, source.ClientID, source.TargetService, source.KeyID)
		label := fmt.Sprintf("body_len=%d", len(source.Body))

		check("response_signature.canonical", label, item.Canonical, canonical)
		check("response_signature.value", label, item.Signature, signRequest(canonical, secret))
	}

	// ---------- TTL ----------
	for _, item := range vectors.ReplayTTL {
		label := fmt.Sprintf("%d/%d/%d", item.MaxAgeSeconds, item.ClockSkewSeconds, item.SafetyMarginSeconds)

		check("replay_ttl", label, item.ExpectedTTLSeconds, replayTTL(item.MaxAgeSeconds, item.ClockSkewSeconds, item.SafetyMarginSeconds))
	}

	// ---------- 输出 ----------
	fmt.Printf("%s 消费 Protocol v1 向量\n", runtime.Version())
	fmt.Printf("  比对项：%d\n", checks)
	fmt.Printf("  不一致：%d\n", len(failures))

	if len(failures) > 0 {
		fmt.Println()
		sort.Strings(failures)
		for _, failure := range failures {
			fmt.Println(failure)
		}
		fmt.Println()
		fmt.Println("结论：Go 实现与 PHP 参考实现不一致 —— 协议存在歧义或实现有误")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("结论：Go 独立实现与冻结向量逐字节一致，协议语言无关性成立")
}
