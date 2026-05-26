from __future__ import annotations

import re
from typing import Any


MAX_AUTO_FINDINGS = 12

_SECTION_RE = re.compile(
    r"(?m)(?=^\s*(?:\d+[.、．)]|[一二三四五六七八九十]+[.、．)]|[-*]\s+))"
)
_URL_RE = re.compile(r"https?://[^\s`'\"，。；、)）\]}]+")
_PATH_RE = re.compile(r"(?<![:\w])/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?)+")
_MARKDOWN_STRIP_RE = re.compile(r"[*_`#]+")
_EVIDENCE_LITERAL_RE = re.compile(
    r"`([^`]{2,160})`|'([^']{2,160})'|\"([^\"]{2,160})\""
)
_AUTH_FRAGMENT_RE = re.compile(r"\b(?:Basic|Bearer)\s+[A-Za-z0-9._~+/=-]{6,}", re.IGNORECASE)
_HEADER_FRAGMENT_RE = re.compile(
    r"\b(?:Authorization|access-control-[a-z-]+)\s*:\s*[^，。；;]+",
    re.IGNORECASE,
)
_KEY_VALUE_FRAGMENT_RE = re.compile(
    r"\b(?:agentId|corpId|jsticket|token|secret|password|pwd|authcode)\s*[:=]\s*['\"]?[^'\"，。；;\s]+",
    re.IGNORECASE,
)
_CREDENTIAL_PAIR_RE = re.compile(r"\b[A-Za-z0-9_.-]{2,}:[A-Za-z0-9_.@#$%^&*+=!-]{2,}\b")

_NEGATIVE_PHRASES = (
    "未发现",
    "不存在",
    "不可利用",
    "无法确认",
    "无法绕过",
    "无法突破",
    "无法读取",
    "无法获取",
    "没有发现",
    "均被拒绝",
    "被服务端拒绝",
    "被拒绝",
    "均返回404",
    "均返回403",
    "均返回405",
    "不可行",
    "未生效",
    "封禁",
    "被拦截",
    "失败",
    "no vulnerability",
    "not exploitable",
    "not vulnerable",
)

_REPORTABLE_KEYWORDS = (
    "漏洞",
    "安全问题",
    "配置错误",
    "敏感信息泄露",
    "信息泄露",
    "泄露",
    "暴露",
    "未授权",
    "越权",
    "绕过",
    "注入",
    "硬编码",
    "弱口令",
    "默认凭证",
    "令牌伪造",
    "路径遍历",
    "任意文件",
    "错误信息",
    "验证在认证之前",
    "返回422",
    "server头",
    "debug",
    "调试",
    "cors",
    "csrf",
    "xss",
    "ssrf",
    "rce",
    "sqli",
    "sql injection",
    "vulnerability",
    "exposure",
)

_CODE_EVIDENCE_KEYWORDS = (
    "泄露",
    "暴露",
    "硬编码",
    "默认凭证",
    "凭证",
    "密钥",
    "错误信息",
    "调试",
    "配置错误",
    "源码",
    "代码",
    "前端",
    "文件上传",
    "oauth",
    "cors",
    "upload",
    "uploadfile",
    "token",
    "secret",
    "credential",
    "authorization",
    "basic",
    "bearer",
    "agentid",
    "corpid",
    "jsticket",
)

_EVIDENCE_LINE_MARKERS = (
    "=",
    ":",
    "=>",
    "function",
    "const ",
    "let ",
    "var ",
    "authorization",
    "basic ",
    "bearer ",
    "access-control",
    "agentid",
    "corpid",
    "jsticket",
    "token",
    "secret",
    "password",
    "upload",
)

_STRONG_POSITIVE_PHRASES = (
    "已确认",
    "确认存在",
    "存在漏洞",
    "存在安全问题",
    "敏感信息泄露",
    "信息泄露",
    "配置错误",
    "硬编码",
    "未授权访问",
    "可未授权",
    "验证在认证之前",
    "返回422",
    "返回 access-control",
    "返回access-control",
    "server头暴露",
    "不验证凭证",
    "功能虚假",
    "access-control-allow-origin",
    "sql注入",
    "sql injection",
    "xss",
    "ssrf",
    "rce",
    "默认凭证",
    "弱口令",
    "路径遍历",
    "任意文件",
)
_NEGATIVE_OVERRIDE_PHRASES = (
    "未授权访问",
    "可未授权",
    "验证在认证之前",
    "返回422",
    "返回 access-control",
    "返回access-control",
    "server头暴露",
    "不验证凭证",
    "功能虚假",
    "access-control-allow-origin",
)

_NEGATIVE_RE = re.compile(
    r"(?:无|未|不|无法|没有)[^。；;,.，]{0,18}(?:泄露|漏洞|暴露|绕过|注入|未授权|可利用|端点|服务)"
)
_SECTION_PREFIX_RE = re.compile(
    r"^\s*(?:\d+[.、．)]|[一二三四五六七八九十]+[.、．)]|[-*]\s+)"
)

_TYPE_RULES = (
    ("cors", "CORS配置错误"),
    ("access-control-allow-origin", "CORS配置错误"),
    ("sql注入", "SQL注入"),
    ("sql injection", "SQL注入"),
    ("sqli", "SQL注入"),
    ("pydantic", "错误信息泄露"),
    ("错误信息", "错误信息泄露"),
    ("硬编码", "硬编码敏感信息"),
    ("默认凭证", "默认凭证"),
    ("弱口令", "弱口令"),
    ("文件上传", "文件上传风险"),
    ("路径遍历", "路径遍历"),
    ("任意文件", "任意文件风险"),
    ("未授权", "未授权访问"),
    ("越权", "越权访问"),
    ("xss", "XSS"),
    ("ssrf", "SSRF"),
    ("rce", "远程代码执行"),
    ("debug", "调试信息泄露"),
    ("调试", "调试信息泄露"),
    ("泄露", "敏感信息泄露"),
    ("暴露", "敏感信息暴露"),
)


def report_is_present(report: Any) -> bool:
    return report not in (None, {}, [])


def build_fallback_report_from_conclusion(
    description: str,
    *,
    source_context: list[str] | None = None,
) -> dict[str, Any] | None:
    text = description.strip()
    if not text:
        return None

    findings = []
    for section in _split_sections(text):
        finding = _finding_from_section(section, source_context=source_context)
        if finding is not None:
            findings.append(finding)
        if len(findings) >= MAX_AUTO_FINDINGS:
            break

    if len(findings) > 1:
        findings = [
            finding
            for finding in findings
            if str(finding.get("title", "")).strip().lower()
            not in {"结论", "conclusion", "综上所述"}
        ] or findings

    if not findings:
        return None

    return {
        "title": "漏洞报告",
        "summary": _truncate(" ".join(text.split()), 220),
        "findings": findings,
    }


def _split_sections(text: str) -> list[str]:
    parts = [part.strip() for part in _SECTION_RE.split(text) if part.strip()]
    if len(parts) > 1:
        if not _SECTION_PREFIX_RE.match(parts[0]):
            parts = parts[1:]
        return parts
    paragraphs = [part.strip() for part in re.split(r"\n{2,}", text) if part.strip()]
    return paragraphs or [text.strip()]


def _finding_from_section(
    section: str,
    *,
    source_context: list[str] | None = None,
) -> dict[str, Any] | None:
    compact = " ".join(section.split())
    lowered = compact.lower()
    if not _has_reportable_signal(lowered):
        return None

    title = _title_from_section(compact)
    endpoints = _extract_paths(compact)
    urls = _URL_RE.findall(compact)
    asset = urls[0] if urls else None
    endpoint = "、".join(endpoints[:6]) if endpoints else None
    finding_type = _infer_type(lowered)
    evidence = _build_evidence_for_section(
        section=section,
        compact=compact,
        title=title,
        finding_type=finding_type,
        asset=asset,
        endpoint=endpoint,
        source_context=source_context,
    )

    return {
        "title": title,
        "asset": asset,
        "endpoint": endpoint,
        "type": finding_type,
        "status": "已确认",
        "severity": _infer_severity(lowered),
        "finding": compact,
        "fix": None,
        "evidence": evidence,
    }


def _build_evidence_for_section(
    *,
    section: str,
    compact: str,
    title: str,
    finding_type: str | None,
    asset: str | None,
    endpoint: str | None,
    source_context: list[str] | None,
) -> list[dict[str, Any]]:
    if _prefers_code_evidence(title, finding_type, compact):
        content = build_code_evidence_excerpt(
            finding_text=section,
            asset=asset,
            endpoint=endpoint,
            source_context=source_context,
        )
        if content:
            return [
                {
                    "kind": "code",
                    "label": "源码上下文",
                    "content": content,
                }
            ]
    return [
        {
            "kind": "code",
            "label": "结论原文",
            "content": section.strip(),
        }
    ]


def finding_prefers_code_evidence(
    *,
    title: str | None,
    finding_type: str | None,
    finding_text: str | None,
) -> bool:
    return _prefers_code_evidence(title or "", finding_type, finding_text or "")


def build_code_evidence_excerpt(
    *,
    finding_text: str,
    asset: str | None = None,
    endpoint: str | None = None,
    source_context: list[str] | None = None,
) -> str | None:
    fragments: list[str] = []
    for seed in (asset, endpoint):
        if seed:
            fragments.append(seed)

    terms = _dedupe_lines(
        [seed for seed in (asset, endpoint) if seed]
        + _URL_RE.findall(finding_text)
        + _extract_paths(finding_text)
    )
    fragments.extend(_extract_evidence_fragments(finding_text))
    for context in source_context or []:
        if not terms or _context_matches_terms(context, terms):
            fragments.extend(_extract_evidence_fragments(context))

    lines = _dedupe_lines(fragments)
    if not lines:
        lines = _dedupe_lines(_context_clauses(finding_text))
    if not lines:
        return None
    return "\n".join(lines[:14])


def _prefers_code_evidence(
    title: str,
    finding_type: str | None,
    finding_text: str,
) -> bool:
    haystack = " ".join(
        part
        for part in (title, finding_type or "", finding_text)
        if part
    ).lower()
    if any(
        keyword in haystack
        for keyword in (
            "硬编码",
            "默认凭证",
            "客户端凭证",
            "密钥",
            "basic ",
            "bearer ",
            "secret",
            "default credential",
            "hardcoded credential",
        )
    ):
        return True

    has_source_marker = any(
        keyword in haystack
        for keyword in (
            "源码",
            "源代码",
            "前端",
            "bundle",
            "chunk",
            ".js",
            "js文件",
            "静态文件",
            "代码",
            "文件中",
        )
    )
    has_leak_marker = any(
        keyword in haystack
        for keyword in (
            "泄露",
            "暴露",
            "敏感信息",
            "端点列表",
            "api端点",
            "业务数据模型",
        )
    )
    return has_source_marker and has_leak_marker


def _extract_evidence_fragments(text: str) -> list[str]:
    compact = " ".join(text.split()).strip()
    if not compact:
        return []

    fragments: list[str] = []
    fragments.extend(match.group(0).strip() for match in _HEADER_FRAGMENT_RE.finditer(compact))
    fragments.extend(match.group(0).strip() for match in _AUTH_FRAGMENT_RE.finditer(compact))
    fragments.extend(match.group(0).strip() for match in _KEY_VALUE_FRAGMENT_RE.finditer(compact))
    for match in _CREDENTIAL_PAIR_RE.finditer(compact):
        value = match.group(0).strip()
        if not value.lower().startswith(("http:", "https:")):
            fragments.append(value)
    fragments.extend(_URL_RE.findall(compact))
    fragments.extend(_extract_paths(compact))

    for match in _EVIDENCE_LITERAL_RE.finditer(compact):
        for group in match.groups():
            if group and _looks_like_evidence_literal(group):
                fragments.append(group.strip())

    if not fragments and _looks_like_evidence_line(compact):
        fragments.extend(_context_clauses(compact))

    return fragments


def _context_matches_terms(context: str, terms: list[str]) -> bool:
    if not terms:
        return True
    lowered = context.lower()
    for term in terms:
        value = term.strip()
        if not value:
            continue
        if value.lower() in lowered:
            return True
        if value.startswith("/") and value.split("?", 1)[0].lower() in lowered:
            return True
    return False


def _looks_like_evidence_literal(value: str) -> bool:
    text = value.strip()
    if not text or len(text) > 160:
        return False
    lowered = text.lower()
    if any(keyword in lowered for keyword in _CODE_EVIDENCE_KEYWORDS):
        return True
    if any(ch in text for ch in ("/", "\\", ":", "=", "{", "}", ".", "-")):
        return True
    if text.isascii() and len(text.split()) <= 4:
        return True
    return False


def _looks_like_evidence_line(text: str) -> bool:
    if len(text) > 260:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in _EVIDENCE_LINE_MARKERS)


def _context_clauses(text: str) -> list[str]:
    clauses = [
        " ".join(part.split()).strip()
        for part in re.split(r"[。；;\n]\s*", text)
        if part.strip()
    ]
    results: list[str] = []
    for clause in clauses:
        lowered = clause.lower()
        if (
            _URL_RE.search(clause)
            or _PATH_RE.search(clause)
            or any(keyword in lowered for keyword in _CODE_EVIDENCE_KEYWORDS)
        ):
            results.append(_truncate(clause, 240))
    return results


def _dedupe_lines(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for line in lines:
        text = " ".join(str(line).split()).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        deduped.append(_truncate(text, 240))
    return deduped


def _has_reportable_signal(lowered: str) -> bool:
    if not any(keyword in lowered for keyword in _REPORTABLE_KEYWORDS):
        return False
    has_negative = any(phrase in lowered for phrase in _NEGATIVE_PHRASES) or bool(_NEGATIVE_RE.search(lowered))
    has_strong_positive = any(phrase in lowered for phrase in _STRONG_POSITIVE_PHRASES)
    if has_negative:
        return any(phrase in lowered for phrase in _NEGATIVE_OVERRIDE_PHRASES)
    return has_strong_positive


def _title_from_section(text: str) -> str:
    title = re.sub(r"^\s*(?:\d+[.、．)]|[一二三四五六七八九十]+[.、．)]|[-*]\s+)\s*", "", text)
    title = _MARKDOWN_STRIP_RE.sub("", title).strip()
    for separator in ("：", ":", "。", ".", "；", ";"):
        index = title.find(separator)
        if index > 0:
            title = title[:index].strip()
            break
    return _truncate(title or "未命名发现", 42)


def _extract_paths(text: str) -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []
    for match in _PATH_RE.findall(text):
        value = match.rstrip(".,;:：，。；、)）]}】")
        if len(value) < 2 or value in seen:
            continue
        seen.add(value)
        paths.append(value)
    return paths


def _infer_type(lowered: str) -> str | None:
    for keyword, label in _TYPE_RULES:
        if keyword in lowered:
            return label
    return None


def _infer_severity(lowered: str) -> str:
    if any(keyword in lowered for keyword in ("critical", "严重", "高危", "rce", "远程代码执行", "任意文件", "认证绕过", "sql注入")):
        return "高危"
    if any(keyword in lowered for keyword in ("cors", "csrf", "中危", "硬编码", "默认凭证", "弱口令", "未授权", "越权", "泄露", "暴露")):
        return "中危"
    if any(keyword in lowered for keyword in ("server头", "版本", "错误信息", "pydantic", "低危")):
        return "低危"
    return "待定"


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"
