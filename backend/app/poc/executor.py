"""PoC 执行器模块。

在沙箱容器内发送无害 HTTP 探针请求，收集完整的请求/响应报文。

策略：
- 在沙箱内执行 Python 脚本，使用 urllib.request 发送 HTTP 请求
- 不依赖 curl（沙箱镜像内无 curl）
- 输出 JSON 格式结果，包含状态码、响应头、响应体
- 支持 GET/POST、查询参数、自定义请求头、multipart 上传
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from sqlalchemy.ext.asyncio import AsyncSession

from app.poc.payloads import PocProbe
from app.services.sandbox_service import exec_in_sandbox

logger = logging.getLogger(__name__)

# 执行器和阶段标识
POC_AGENT = "poc_verify_agent"
POC_PHASE = "poc_verify"

# Python 探针运行脚本（写入沙箱后调用）
# 使用 urllib.request 发送 HTTP 请求，输出 JSON 结果
# 配置从文件读取（避免 CLI 参数被 shell split 破坏）
_PROBE_RUNNER_SCRIPT = r"""
import json, sys, urllib.request, urllib.error, io

with open(sys.argv[1]) as f:
    config = json.load(f)
method = config.get("method", "GET")
url = config["url"]
headers = config.get("headers", {})
body = config.get("body")
is_multipart = config.get("is_multipart", False)
multipart_fields = config.get("multipart_fields", {})
file_content = config.get("multipart_file_content", "")
file_name = config.get("multipart_file_name", "poc_test.txt")
content_type = config.get("content_type")

try:
    if is_multipart:
        boundary = "----PoCBoundary1234567890"
        data = b""
        for k, v in multipart_fields.items():
            data += f"--{boundary}\r\n".encode()
            data += f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode()
            data += f"{v}\r\n".encode()
        data += f"--{boundary}\r\n".encode()
        data += f'Content-Disposition: form-data; name="file"; filename="{file_name}"\r\n'.encode()
        data += b"Content-Type: text/plain\r\n\r\n"
        data += file_content.encode()
        data += f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    else:
        data = None
        if body:
            data = body.encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        if data and content_type:
            req.add_header("Content-Type", content_type)

    for k, v in headers.items():
        req.add_header(k, v)

    try:
        resp = urllib.request.urlopen(req, timeout=10)
        status = resp.getcode()
        resp_headers = dict(resp.headers)
        resp_body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers) if e.headers else {}
        resp_body = e.read().decode("utf-8", errors="replace")
except Exception as e:
    status = 0
    resp_headers = {}
    resp_body = ""
    error = str(e)

result = {"status_code": status, "headers": resp_headers, "body": resp_body}
print(json.dumps(result))
"""


def _build_full_url(probe: PocProbe, base_url: str) -> str:
    """构建完整请求 URL（含查询参数）。"""
    url = f"{base_url.rstrip('/')}{probe.path}"
    if probe.params:
        query = urlencode(probe.params)
        url = f"{url}?{query}"
    return url


def _build_config_json(probe: PocProbe, base_url: str) -> str:
    """构建探针配置 JSON 字符串。"""
    full_url = _build_full_url(probe, base_url)
    config = {
        "method": probe.method,
        "url": full_url,
        "headers": dict(probe.headers),
        "body": probe.body,
        "content_type": probe.content_type,
        "is_multipart": probe.is_multipart,
        "multipart_fields": dict(probe.multipart_fields),
        "multipart_file_content": probe.multipart_file_content,
        "multipart_file_name": probe.multipart_file_name,
    }
    return json.dumps(config)


def _build_write_config_cmd(config_json: str) -> str:
    """构建写入配置文件的命令（使用 heredoc 避免 shell 引号问题）。"""
    # heredoc 包含 > 所以 exec_command 会走 sh -c 路径，正确解析
    return (
        f"cat > /workspace/tmp/probe_config.json << 'CFG_EOF'\n{config_json}\nCFG_EOF"
    )


def _parse_probe_output(output: str) -> dict[str, Any]:
    """解析探针脚本的 JSON 输出。

    输出格式：
        {"status_code": 200, "headers": {...}, "body": "..."}
    """
    if not output:
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
        }

    try:
        parsed = json.loads(output.strip())
        return {
            "status_code": parsed.get("status_code", 0),
            "headers": parsed.get("headers", {}),
            "body": parsed.get("body", ""),
        }
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("[poc_executor] Failed to parse probe output: %s", e)
        return {
            "status_code": 0,
            "headers": {},
            "body": output[:500],
        }


async def _ensure_runner_script(
    db: AsyncSession,
    redis: Any,
    task_id: str,
) -> bool:
    """确保障箱内已写入探针脚本。"""
    check_cmd = (
        "test -f /workspace/tmp/probe_runner.py && echo 'exists' || echo 'missing'"
    )
    result = await exec_in_sandbox(
        db,
        redis,
        task_id,
        check_cmd,
        timeout=10,
        agent=POC_AGENT,
        phase=POC_PHASE,
        log_output=False,
    )
    if "exists" in result.get("stdout", ""):
        return True

    # 写入脚本
    script_cmd = f"cat > /workspace/tmp/probe_runner.py << 'PROBE_EOF'\n{_PROBE_RUNNER_SCRIPT}\nPROBE_EOF"
    write_result = await exec_in_sandbox(
        db,
        redis,
        task_id,
        script_cmd,
        timeout=10,
        agent=POC_AGENT,
        phase=POC_PHASE,
        log_output=False,
    )
    return write_result.get("exit_code") == 0


async def execute_probe(
    db: AsyncSession,
    redis: Any,
    task_id: str,
    probe: PocProbe,
    base_url: str = "http://127.0.0.1:5000",
    timeout: int = 15,
) -> dict[str, Any]:
    """执行单个探针，返回完整的请求/响应记录。

    在沙箱内通过 Python urllib 发送 HTTP 请求，收集完整报文。
    执行失败时返回 error 状态而非抛异常。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        probe: 探针定义
        base_url: 目标服务基础 URL
        timeout: 超时秒数

    Returns:
        dict: {
            "name": str,
            "request_method": str,
            "request_url": str,
            "request_headers": dict,
            "request_body": str | None,
            "response_status": int,
            "response_headers": dict,
            "response_body": str,
            "error": str | None,
            "executed_at": str,
        }
    """
    executed_at = datetime.now(timezone.utc).isoformat()

    # 确保探针脚本已写入
    await _ensure_runner_script(db, redis, task_id)

    # 构建配置 JSON 并写入沙箱文件（避免 CLI 参数被 shell split 破坏）
    config_json = _build_config_json(probe, base_url)
    write_config_cmd = _build_write_config_cmd(config_json)
    await exec_in_sandbox(
        db,
        redis,
        task_id,
        write_config_cmd,
        timeout=10,
        agent=POC_AGENT,
        phase=POC_PHASE,
        log_output=False,
    )

    # 构建完整请求 URL
    full_url = _build_full_url(probe, base_url)

    # 运行探针：简单命令，无 shell 运算符，exec_command 会正确 split
    run_cmd = "python /workspace/tmp/probe_runner.py /workspace/tmp/probe_config.json"
    logger.info("[poc_executor] Executing probe '%s': %s", probe.name, run_cmd)

    try:
        result = await exec_in_sandbox(
            db,
            redis,
            task_id,
            run_cmd,
            timeout=timeout + 5,
            agent=POC_AGENT,
            phase=POC_PHASE,
            log_output=False,  # PoC 探针日志单独记录
        )

        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code", -1)

        if exit_code != 0:
            logger.warning(
                "[poc_executor] Probe '%s' exit=%d, stderr=%s",
                probe.name,
                exit_code,
                stderr[:200],
            )

        # 解析输出
        parsed = _parse_probe_output(stdout)

        # 如果输出为空但有 stderr
        if not stdout and stderr:
            return {
                "name": probe.name,
                "request_method": probe.method,
                "request_url": full_url,
                "request_headers": dict(probe.headers),
                "request_body": probe.body or probe.multipart_file_content,
                "response_status": 0,
                "response_headers": {},
                "response_body": "",
                "error": f"Probe execution failed (exit={exit_code}): {stderr[:500]}",
                "executed_at": executed_at,
            }

        return {
            "name": probe.name,
            "request_method": probe.method,
            "request_url": full_url,
            "request_headers": dict(probe.headers),
            "request_body": probe.body or probe.multipart_file_content,
            "response_status": parsed["status_code"],
            "response_headers": parsed["headers"],
            "response_body": parsed["body"],
            "error": None,
            "executed_at": executed_at,
        }

    except Exception as e:
        logger.error("[poc_executor] Probe '%s' execution failed: %s", probe.name, e)
        return {
            "name": probe.name,
            "request_method": probe.method,
            "request_url": full_url,
            "request_headers": dict(probe.headers),
            "request_body": probe.body or probe.multipart_file_content,
            "response_status": 0,
            "response_headers": {},
            "response_body": "",
            "error": str(e)[:500],
            "executed_at": executed_at,
        }


async def execute_probes_batch(
    db: AsyncSession,
    redis: Any,
    task_id: str,
    probes: list[PocProbe],
    base_url: str = "http://127.0.0.1:5000",
    delay_between: float = 0.5,
) -> list[dict[str, Any]]:
    """批量执行探针，每个探针之间有小延迟避免压垮目标。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        probes: 探针列表
        base_url: 目标服务 URL
        delay_between: 探针间隔秒数

    Returns:
        每个探针的执行结果列表
    """
    import asyncio

    results: list[dict[str, Any]] = []
    for probe in probes:
        result = await execute_probe(db, redis, task_id, probe, base_url)
        results.append(result)
        if delay_between > 0:
            await asyncio.sleep(delay_between)

    return results
