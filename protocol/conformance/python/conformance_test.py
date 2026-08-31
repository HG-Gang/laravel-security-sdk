# Created by PhpStorm.
# Project name Tozo-security-sdk-php.
# User: Huang Gang
# Date: 2026/08/28
# Time: 01:10

"""Protocol v1 一致性测试 —— Python 实现消费冻结向量。

运行：
    python protocol/conformance/python/conformance_test.py

返回码：0 = 全部一致；1 = 存在不一致。

该脚本只读取 protocol/test-vectors-v1.json，不修改任何向量。
若出现不一致，必须先判断是 Python 实现理解偏差还是协议规范歧义，
两者的处理方式不同：前者改实现，后者改协议文档并升版本。
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tozo_protocol as tp

VECTOR_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "test-vectors-v1.json"
)

failures = []
checks = 0


def check(group: str, label: str, expected, actual):
    """比对单条向量并记录结果。"""
    global checks
    checks += 1

    if expected != actual:
        failures.append(
            "[{}] {}\n    expected: {!r}\n    actual:   {!r}".format(group, label, expected, actual)
        )


def main() -> int:
    with open(VECTOR_PATH, "r", encoding="utf-8") as handle:
        vectors = json.load(handle)

    meta = vectors["_meta"]
    if meta["protocol_version"] != tp.PROTOCOL_VERSION:
        print("协议版本不匹配：向量 {} vs 实现 {}".format(meta["protocol_version"], tp.PROTOCOL_VERSION))
        return 1

    secret = meta["hmac_key_ascii"]

    # ---------- path ----------
    for item in vectors["normalize_path"]:
        check("normalize_path", repr(item["input"]), item["expected"], tp.normalize_path(item["input"]))

    # ---------- query（字符串入口）----------
    for item in vectors["canonical_query_string"]:
        check(
            "canonical_query_string",
            repr(item["input"]),
            item["expected"],
            tp.canonical_query_string(item["input"]),
        )

    # ---------- query（结构化入口）----------
    for item in vectors["canonical_query_array"]:
        label = json.dumps(item["input"], ensure_ascii=False, sort_keys=False)
        check("canonical_query_array.wire", label, item["wire"], tp.build_query_string(item["input"]))
        check("canonical_query_array", label, item["expected"], tp.canonical_query(item["input"]))

    # ---------- content-type ----------
    for item in vectors["normalize_content_type"]:
        check(
            "normalize_content_type",
            repr(item["input"]),
            item["expected"],
            tp.normalize_content_type(item["input"]),
        )

    # ---------- base64url ----------
    for item in vectors["base64url_encode"]:
        raw = bytes.fromhex(item["input_hex"]) if item["input_hex"] else b""
        check("base64url_encode", item["input_hex"] or "(empty)", item["expected"], tp.base64url_encode(raw))

    for item in vectors["base64url_decode"]:
        decoded = tp.base64url_decode(item["input"])
        actual = None if decoded is None else decoded.hex()
        check("base64url_decode", repr(item["input"]), item["expected_hex"], actual)

    # ---------- 完整签名 ----------
    for item in vectors["signature"]:
        source = item["input"]

        canonical = tp.build_canonical_request(
            source["method"],
            source["path"],
            source["query"],
            source["content_type"],
            source["body"],
            int(source["timestamp"]),
            source["nonce"],
            source["client_id"],
            source["target_service"],
            source["key_id"],
        )

        check("signature.canonical", item["name"], item["canonical"], canonical)
        check("signature.body_sha256", item["name"], item["body_sha256"], tp.sha256_hex(source["body"]))
        check("signature.value", item["name"], item["signature"], tp.sign_request(canonical, secret))

    # ---------- AEAD AAD ----------
    for item in vectors["aead_aad"]:
        source = item["input"]

        check(
            "aead_aad",
            source["direction"] + " " + repr(source["path"]),
            item["expected"],
            tp.build_aead_aad(
                source["direction"],
                source["client_id"],
                source["target_service"],
                source["method"],
                source["path"],
                source["key_id"],
            ),
        )

    # ---------- 响应签名 ----------
    for item in vectors["response_signature"]:
        source = item["input"]

        canonical = tp.build_response_canonical(
            source["body"], source["client_id"], source["target_service"], source["key_id"]
        )

        label = "body_len={}".format(len(source["body"]))
        check("response_signature.canonical", label, item["canonical"], canonical)
        check("response_signature.value", label, item["signature"], tp.sign_request(canonical, secret))

    # ---------- TTL 公式 ----------
    for item in vectors["replay_ttl"]:
        check(
            "replay_ttl",
            "{}/{}/{}".format(
                item["max_age_seconds"], item["clock_skew_seconds"], item["replay_safety_margin_seconds"]
            ),
            item["expected_ttl_seconds"],
            tp.replay_ttl(
                item["max_age_seconds"],
                item["clock_skew_seconds"],
                item["replay_safety_margin_seconds"],
            ),
        )

    # ---------- 输出 ----------
    print("Python {}.{}.{} 消费 Protocol v1 向量".format(*sys.version_info[:3]))
    print("  比对项：{}".format(checks))
    print("  不一致：{}".format(len(failures)))

    if failures:
        print()
        for failure in failures:
            print(failure)
        print()
        print("结论：Python 实现与 PHP 参考实现不一致 —— 协议存在歧义或实现有误")
        return 1

    print()
    print("结论：Python 独立实现与冻结向量逐字节一致，协议语言无关性成立")

    return 0


if __name__ == "__main__":
    sys.exit(main())
