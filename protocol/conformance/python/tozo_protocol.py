# Created by PhpStorm.
# Project name Tozo-security-sdk-php.
# User: Huang Gang
# Date: 2026/08/28
# Time: 01:10

"""Tozo Security Protocol v1 —— Python 独立参考实现。

本文件的唯一目的是验证 Protocol v1 是否真正语言无关：
它按 protocol/README.md 的文字规则从零实现，不移植 PHP 源码，
再用 protocol/test-vectors-v1.json 逐条比对。

如果某条规则只能靠"照抄 PHP 行为"才能通过，说明协议规范存在歧义，
必须在协议层面修清楚，而不是在本文件里特殊处理。

依赖：仅标准库（hashlib、hmac、base64、urllib.parse、json）。
"""

import base64
import hashlib
import hmac
from urllib.parse import quote, unquote_plus

ENVELOPE_VERSION = "1"
PROTOCOL_VERSION = "1"

# RFC 3986 未保留字符集：字母数字与 - _ . ~
# 其余字节一律百分号编码，与 PHP rawurlencode 的口径一致。
_UNRESERVED = "-_.~"


def base64url_encode(raw: bytes) -> str:
    """Base64URL 编码（RFC 4648 §5），去掉尾部 padding。"""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def base64url_decode(encoded: str):
    """严格 Base64URL 解码。

    非法输入返回 None，不做宽松解码——宽松解码会把被篡改的签名
    解出一段"看起来有效"的字节，使后续常量时间比较失去意义。
    """
    if encoded == "":
        return None

    # 只接受 Base64URL 字母表；出现 + / = 或其他字符即视为非法。
    for char in encoded:
        if not (char.isascii() and (char.isalnum() or char in "-_")):
            return None

    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return None


def _percent_encode(value: str) -> str:
    """按 RFC 3986 对单个 query 键或值做百分号编码。

    safe 只保留未保留字符；空格编码为 %20 而非 +。
    """
    return quote(value, safe=_UNRESERVED, encoding="utf-8")


def normalize_path(path: str) -> str:
    """规范化 HTTP path。

    规则（protocol/README.md §path 规范化）：
    1. 仅当带 scheme 时才取 URL 的 path 部分；纯路径不得交给 URL 解析器，
       否则前导 // 会被当作主机名而丢掉第一段。
    2. 剥离 query 与 fragment。
    3. 折叠连续斜杠。
    4. 逐段解析：空段与 "." 丢弃，".." 回退一层（根目录时忽略）。
    5. 结果以 / 开头；无段时为 /。
    """
    # 手工检测 scheme，避免不同语言 URL 解析器对 "//host" 的处理差异。
    scheme_end = path.find("://")
    if scheme_end > 0 and path[:scheme_end].replace("+", "").replace("-", "").replace(".", "").isalnum():
        rest = path[scheme_end + 3:]
        slash = rest.find("/")
        path = rest[slash:] if slash >= 0 else "/"

    for cut in ("?", "#"):
        index = path.find(cut)
        if index >= 0:
            path = path[:index]

    if path == "":
        return "/"

    segments = []
    for segment in path.split("/"):
        if segment == "" or segment == ".":
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)

    return "/" + "/".join(segments) if segments else "/"


def canonical_query_string(raw_query: str) -> str:
    """规范化线上原始 query 字符串。

    规则（protocol/README.md §query 规范化）：
    1. 去前导 ?；空串返回空串。
    2. 按 & 拆分，丢弃空段。
    3. 每段按首个 = 拆键值；无 = 时值为空串。
    4. 键值分别解码（+ 视为空格），再按 RFC 3986 重新编码。
    5. 每个 "键=值" 串按字节序排序。
    6. 用 & 连接。
    """
    raw_query = raw_query.lstrip("?")
    if raw_query == "":
        return ""

    pairs = []
    for segment in raw_query.split("&"):
        if segment == "":
            continue

        key, _, value = segment.partition("=")
        # unquote_plus 把 + 解为空格，%2B 解为字面加号——与协议规则一致。
        pairs.append(
            _percent_encode(unquote_plus(key)) + "=" + _percent_encode(unquote_plus(value))
        )

    # 按字节序排序：先编码为 UTF-8 再比较，避免不同语言的字符串排序差异。
    pairs.sort(key=lambda item: item.encode("utf-8"))

    return "&".join(pairs)


def build_query_string(query) -> str:
    """把结构化 query 渲染为线上字节串。

    - 顺序列表 → 重复键：{"tag": ["one","two"]} → tag=one&tag=two
      不使用 tag[0]=one（方括号索引是 PHP 特有语义）。
    - 映射 → 方括号子键：{"filter": {"status": "open"}} → filter%5Bstatus%5D=open
      必须保留子键名，否则不同 query 会折叠出相同字节。
    """
    pairs = []

    def append(key: str, value):
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                append("{}[{}]".format(key, sub_key), sub_value)
            return

        if isinstance(value, (list, tuple)):
            # 顺序列表复用同一个键名。
            for item in value:
                append(key, item)
            return

        text = "" if value is None else str(value)
        pairs.append(_percent_encode(key) + "=" + _percent_encode(text))

    for key, value in query.items():
        append(str(key), value)

    return "&".join(pairs)


def canonical_query(query) -> str:
    """规范化结构化 query：先渲染为线上字节，再走字符串规范化。"""
    if not query:
        return ""

    return canonical_query_string(build_query_string(query))


def normalize_content_type(content_type: str) -> str:
    """规范化 Content-Type：取分号前主类型，trim 后转小写。"""
    if content_type is None or content_type == "":
        return ""

    main = content_type.split(";", 1)[0]

    return main.strip().lower()


def sha256_hex(data: str) -> str:
    """UTF-8 编码后的 SHA-256 十六进制小写。"""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def build_canonical_request(
    method: str,
    path: str,
    query,
    content_type: str,
    body: str,
    timestamp: int,
    nonce: str,
    client_id: str,
    target_service: str,
    key_id: str,
) -> str:
    """构造 11 字段规范化串，字段顺序固定不可调整。"""
    canonical_q = canonical_query(query) if isinstance(query, dict) else canonical_query_string(query)

    return "\n".join([
        PROTOCOL_VERSION,
        method.upper(),
        normalize_path(path),
        canonical_q,
        normalize_content_type(content_type),
        sha256_hex(body),
        str(timestamp),
        nonce,
        client_id,
        target_service,
        key_id,
    ])


def sign_request(canonical: str, secret: str) -> str:
    """对规范化串生成 HMAC-SHA256 签名（Base64URL 无 padding）。"""
    digest = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).digest()

    return base64url_encode(digest)


def build_aead_aad(
    direction: str,
    client_id: str,
    target_service: str,
    method: str,
    path: str,
    key_id: str,
) -> str:
    """构造 AES-GCM 的 7 字段方向绑定 AAD。"""
    return "\n".join([
        ENVELOPE_VERSION,
        direction,
        client_id,
        target_service,
        method.upper(),
        normalize_path(path),
        key_id,
    ])


def build_response_canonical(body: str, client_id: str, target_service: str, key_id: str) -> str:
    """构造响应签名的 6 字段原文；direction 固定为字面量 response。"""
    return "\n".join([
        ENVELOPE_VERSION,
        "response",
        client_id,
        target_service,
        sha256_hex(body),
        key_id,
    ])


def replay_ttl(max_age_seconds: int, clock_skew_seconds: int, safety_margin_seconds: int) -> int:
    """ReplayStore TTL 公式；实现不得低于该结果。"""
    return max_age_seconds + 2 * clock_skew_seconds + safety_margin_seconds
