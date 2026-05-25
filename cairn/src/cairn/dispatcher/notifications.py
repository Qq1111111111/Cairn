from __future__ import annotations

from typing import Any
import base64
import hashlib
import hmac
import logging
import time

import requests

LOG = logging.getLogger(__name__)
MAX_DINGTALK_MARKDOWN_CHARS = 12000
MAX_DINGTALK_FINDINGS = 6
MAX_DINGTALK_FIELD_CHARS = 900
MAX_DINGTALK_PACKET_CHARS = 2600
MAX_DINGTALK_RESPONSE_LINES = 50


def notify_dingtalk_report(
    *,
    enabled: bool = True,
    webhook: str | None,
    secret: str | None,
    project_id: str,
    intent_id: str,
    fact_id: str | None,
    worker_name: str,
    source: str,
    report: Any,
) -> None:
    if not enabled:
        LOG.info(
            "dingtalk report notification skipped project=%s intent=%s reason=disabled",
            project_id,
            intent_id,
        )
        return
    if not webhook:
        LOG.info(
            "dingtalk report notification skipped project=%s intent=%s reason=missing_webhook",
            project_id,
            intent_id,
        )
        return
    if not report:
        return

    findings = _report_findings(report)
    if not findings:
        LOG.info(
            "dingtalk report notification skipped project=%s intent=%s reason=no_findings",
            project_id,
            intent_id,
        )
        return

    title = _report_text(_report_dict(report).get("title")) or "漏洞报告"
    text = _build_report_markdown(
        title=title,
        project_id=project_id,
        intent_id=intent_id,
        fact_id=fact_id,
        worker_name=worker_name,
        source=source,
        findings=findings,
    )
    payload = {
        "msgtype": "markdown",
        "markdown": {
            "title": title,
            "text": text,
        },
        "at": {"isAtAll": False},
    }

    try:
        response = requests.post(
            webhook,
            params=_dingtalk_signature_params(secret),
            json=payload,
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        LOG.warning(
            "dingtalk report notification failed project=%s intent=%s error=%s",
            project_id,
            intent_id,
            exc,
        )
        return

    if data.get("errcode") != 0:
        LOG.warning(
            "dingtalk report notification rejected project=%s intent=%s response=%s",
            project_id,
            intent_id,
            _truncate(str(data), 300),
        )
        return

    LOG.info(
        "dingtalk report notification sent project=%s intent=%s findings=%s",
        project_id,
        intent_id,
        len(findings),
    )


def _dingtalk_signature_params(secret: str | None) -> dict[str, str]:
    if not secret:
        return {}
    timestamp = str(round(time.time() * 1000))
    sign_source = f"{timestamp}\n{secret}"
    digest = hmac.new(
        secret.encode("utf-8"),
        sign_source.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    return {
        "timestamp": timestamp,
        "sign": base64.b64encode(digest).decode("utf-8"),
    }


def _report_dict(report: Any) -> dict[str, Any]:
    if isinstance(report, dict):
        nested = report.get("report")
        if isinstance(nested, dict):
            return nested
        return report
    return {}


def _report_findings(report: Any) -> list[dict[str, Any]]:
    if isinstance(report, list):
        candidates = report
    else:
        data = _report_dict(report)
        candidates = (
            data.get("findings")
            or data.get("vulnerabilities")
            or data.get("items")
            or []
        )
        if not candidates and any(
            key in data
            for key in ("title", "finding", "description", "asset", "endpoint")
        ):
            candidates = [data]
    if not isinstance(candidates, list):
        return []
    return [item for item in candidates if isinstance(item, dict)]


def _build_report_markdown(
    *,
    title: str,
    project_id: str,
    intent_id: str,
    fact_id: str | None,
    worker_name: str,
    source: str,
    findings: list[dict[str, Any]],
) -> str:
    lines = [
        f"### {title}",
        "",
        f"- 项目：{project_id}",
        f"- 结论：{intent_id} → {fact_id or '—'}",
        f"- 执行者：{worker_name}",
        f"- 来源：{_report_source_label(source)}（{source}）",
        f"- 发现数：{len(findings)}",
        "",
    ]

    for index, finding in enumerate(findings[:MAX_DINGTALK_FINDINGS], 1):
        finding_title = _report_text(finding.get("title") or finding.get("name")) or "未命名发现"
        severity = _report_severity_label(finding.get("severity"))
        status = _report_status_label(finding.get("status"))
        finding_type = _report_type_label(finding.get("type") or finding.get("category"))
        asset = _report_text(finding.get("asset") or finding.get("target")) or ""
        endpoint = _report_text(finding.get("endpoint") or finding.get("path") or finding.get("uri")) or ""
        summary = _report_text(
            finding.get("finding") or finding.get("description") or finding.get("summary")
        ) or "—"

        lines.extend(
            [
                f"#### {index}. {finding_title}",
                f"- 状态：{status}",
                f"- 等级：{severity}",
            ]
        )
        if finding_type != "—":
            lines.append(f"- 类型：{finding_type}")
        if asset:
            lines.append(f"- 资产：{_truncate(asset, MAX_DINGTALK_FIELD_CHARS)}")
        if endpoint:
            lines.append(f"- 端点：{_truncate(endpoint, MAX_DINGTALK_FIELD_CHARS)}")
        lines.append(f"- 发现：{_truncate(summary, MAX_DINGTALK_FIELD_CHARS)}")

        fix = _report_text(
            finding.get("fix")
            or finding.get("remediation")
            or finding.get("recommendation")
        )
        if fix:
            lines.append(f"- 修复：{_truncate(fix, MAX_DINGTALK_FIELD_CHARS)}")

        evidence = _report_evidence(finding)
        if evidence:
            lines.append("")
            lines.append("**证据**")
            for evidence_index, item in enumerate(evidence, 1):
                lines.extend(_render_evidence(item, evidence_index))
        lines.append("")

    if len(findings) > MAX_DINGTALK_FINDINGS:
        lines.append(f"...另有 {len(findings) - MAX_DINGTALK_FINDINGS} 个发现，请在 Cairn 中查看完整报告。")

    return _truncate("\n".join(lines).strip(), MAX_DINGTALK_MARKDOWN_CHARS)


def _report_evidence(finding: dict[str, Any]) -> list[dict[str, Any]]:
    raw = finding.get("evidence")
    if raw is None:
        direct: dict[str, Any] = {
            "kind": "packet",
            "label": "请求/响应包",
            "request_packet": finding.get("request_packet") or finding.get("request"),
            "response_packet": finding.get("response_packet") or finding.get("response"),
        }
        return [direct] if direct["request_packet"] or direct["response_packet"] else []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        return [raw]
    text = _report_text(raw)
    return [{"kind": "code", "label": "证据", "content": text}] if text else []


def _render_evidence(evidence: dict[str, Any], index: int) -> list[str]:
    kind = (_report_text(evidence.get("kind") or evidence.get("type")) or "").lower()
    label = _report_text(evidence.get("label") or evidence.get("title")) or f"证据 {index}"
    request_packet = _report_text(
        evidence.get("request_packet")
        or evidence.get("request")
        or evidence.get("request_data")
        or evidence.get("request_body")
    )
    response_packet = _report_text(
        evidence.get("response_packet")
        or evidence.get("response")
        or evidence.get("response_data")
        or evidence.get("response_body")
    )
    content = _report_text(
        evidence.get("content")
        or evidence.get("text")
        or evidence.get("code")
        or evidence.get("snippet")
    )
    is_packet = kind == "packet" or request_packet or response_packet
    lines = [f"- {label}"]

    if is_packet:
        if request_packet:
            lines.extend(_fenced_block("请求包", request_packet, MAX_DINGTALK_PACKET_CHARS))
        if response_packet:
            limited_response = _limit_lines(response_packet, MAX_DINGTALK_RESPONSE_LINES)
            lines.extend(_fenced_block("响应包", limited_response, MAX_DINGTALK_PACKET_CHARS))
        return lines

    if content:
        lines.extend(_fenced_block(label, content, MAX_DINGTALK_PACKET_CHARS))
    return lines


def _fenced_block(label: str, text: str, limit: int) -> list[str]:
    body = _truncate(text, limit)
    return [
        f"  - {label}：",
        "```text",
        body,
        "```",
    ]


def _limit_lines(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    omitted = len(lines) - max_lines
    return "\n".join(lines[:max_lines] + [f"...已省略 {omitted} 行"])


def _report_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
    else:
        text = str(value).strip()
    return text or None


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _report_status_label(value: Any) -> str:
    text = _report_text(value)
    if not text:
        return "已确认"
    labels = {
        "confirmed": "已确认",
        "verified": "已确认",
        "suspected": "待验证",
        "pending": "待验证",
        "open": "待验证",
        "resolved": "已修复",
        "fixed": "已修复",
        "ignored": "已忽略",
    }
    return labels.get(text.lower(), text)


def _report_severity_label(value: Any) -> str:
    text = _report_text(value)
    if not text:
        return "待定"
    labels = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "moderate": "中危",
        "low": "低危",
        "info": "信息",
        "informational": "信息",
        "unknown": "待定",
    }
    return labels.get(text.lower(), text)


def _report_type_label(value: Any) -> str:
    text = _report_text(value)
    if not text:
        return "—"
    labels = {
        "hardcoded_credentials": "硬编码凭证",
        "default_credentials": "默认凭证",
        "unauthorized_access": "未授权访问",
        "missing_access_control": "缺少访问控制",
        "cors_misconfiguration": "CORS 配置错误",
        "information_disclosure": "信息泄露",
        "sensitive_information_disclosure": "敏感信息泄露",
        "api_endpoint_exposure": "API 端点泄露",
        "frontend_code_exposure": "前端代码泄露",
        "sql_injection": "SQL 注入",
        "reflected_sql_injection": "SQL 注入反射点",
        "error_information_disclosure": "错误信息泄露",
        "file_upload_exposure": "文件上传功能暴露",
        "authentication_bypass": "认证绕过",
        "auth_bypass": "认证绕过",
        "weak_authentication": "弱认证",
        "open_redirect": "开放重定向",
        "ssrf": "服务端请求伪造",
        "xss": "跨站脚本",
    }
    return labels.get(text.lower(), text)


def _report_source_label(value: Any) -> str:
    text = _report_text(value)
    if not text:
        return "来源未知"
    labels = {
        "bootstrap": "启动执行",
        "bootstrap_conclude": "启动结论",
        "explore_execute": "探索执行",
        "explore_conclude": "探索结论",
    }
    return labels.get(text.lower(), text)
