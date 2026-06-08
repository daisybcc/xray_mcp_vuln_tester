# Xray MCP 漏洞测试服务

> ⚠️ **免责声明**：本工具仅供**已获书面授权**的渗透测试或安全研究使用。  
> 对未经授权的目标使用属于违法行为，使用者须自行承担全部法律责任。

## 功能概述

通过 MCP 协议将漏洞测试能力接入 Claude Desktop 等 AI 客户端。  
配合 xray 反连平台，实现 **DNS / HTTP / RMI** 三种回调方式检测：

| 漏洞类型 | 回调方式 | 覆盖范围 |
|---------|---------|---------|
| Log4j (CVE-2021-44228) | DNS / HTTP / RMI | 基础 + 6 种绕过变体 |
| FastJSON 反序列化 | LDAP / DNS | 1.2.24 / 1.2.47 / 1.2.68 |
| SSRF | HTTP / DNS | 参数注入 + Header 注入 + 内网地址 |

---

## 环境要求

- Python 3.11+
- xray 反连平台（本地或远程部署）
- Claude Desktop（或其他 MCP 客户端）

---

## 快速开始

### 1. 安装依赖

```bash
cd xray_mcp_vuln_tester
pip install -r requirements.txt
```

### 2. 配置 xray 反连平台参数

编辑 `server.py` 顶部或通过环境变量设置：

```python
XRAY_API_BASE = "http://127.0.0.1:7777"   # xray 反连平台地址
XRAY_TOKEN    = "your_xray_token_here"    # API Token（无鉴权则留空）
XRAY_DOMAIN   = "your.xray.domain"        # 反连平台可达域名
```

也可通过环境变量覆盖（在 claude_desktop_config.json 的 `env` 中配置）。

### 3. 接入 Claude Desktop

将 `claude_desktop_config.json` 内容合并到：

- macOS：`~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows：`%APPDATA%\Claude\claude_desktop_config.json`

修改 `args` 中的路径为实际路径，重启 Claude Desktop。

---

## 可用工具

### `test_log4j`
```
参数：
  target_url     目标 URL（必填）
  extra_headers  额外请求头（可选）
```
将 JNDI Payload 注入 User-Agent / X-Forwarded-For / Referer 等 16 个 Header，等待 xray 回调。

### `test_fastjson`
```
参数：
  target_url     JSON 接口 URL（必填）
  custom_headers 自定义请求头（可选）
```
依次发送多版本 `@type` Payload，检测 JNDI 出网回调。

### `test_ssrf`
```
参数：
  target_url     目标 URL（必填）
  param_name     参数名，默认 url
  method         GET / POST，默认 GET
  custom_headers 自定义请求头（可选）
```
替换参数为反连地址，同步测试云厂商元数据地址和内网段。

### `full_scan`
```
参数：
  target_url     目标 URL（必填）
  ssrf_param     SSRF 参数名，默认 url
  method         GET / POST，默认 GET
  custom_headers 自定义请求头（可选）
```
并发执行以上三项，汇总结果。

### `check_callbacks`
```
参数：
  since_seconds  查询最近 N 秒，默认 300
```
查询 xray 平台所有回调记录，确认是否有未关联的回调。

---

## 工作流示例

在 Claude Desktop 中，你可以这样使用：

```
请对 http://test.internal/api/login 执行 Log4j 全量检测，
额外带上 Authorization: Bearer eyJxxx 头
```

Claude 会自动调用 `test_log4j` → 注入 payload → 轮询 xray → 返回结构化报告。

---

## xray 反连平台部署参考

```bash
# 启动 xray 反连服务（需有公网 IP 和域名解析）
./xray reverse --config reverse.yaml

# reverse.yaml 示例
reverse:
  domain: your.xray.domain
  token: your_xray_token_here
  http:
    enabled: true
    listen_ip: 0.0.0.0
    listen_port: 8080
  dns:
    enabled: true
    listen_ip: 0.0.0.0
    resolve_to_ip: <your_public_ip>
  api:
    enabled: true
    listen_ip: 127.0.0.1
    listen_port: 7777
    token: your_xray_token_here
```

---

## 返回结果结构

```json
{
  "vuln": "Log4j (CVE-2021-44228)",
  "target": "http://...",
  "token": "log4j-a1b2c3d4",
  "payloads_sent": 64,
  "callbacks": [
    {
      "type": "dns",
      "remote_addr": "1.2.3.4:12345",
      "raw": "...",
      "timestamp": "2024-01-01T12:00:00Z"
    }
  ],
  "callback_types": ["dns"],
  "vulnerable": true,
  "severity": "CRITICAL",
  "detail": "收到 1 个回调，类型：['dns']"
}
```
