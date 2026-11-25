"""报告格式转换器模块。

本模块负责将 ReportData 渲染为 Markdown / HTML 字符串：
- to_markdown(data, template_dir) -> str：Jinja2 渲染 report.md.j2
- to_html(data, template_dir) -> str：Jinja2 渲染 report.html.j2
- to_pdf_async(html_path, output_path) -> str：使用本机浏览器生成 PDF

文件写入在 service 层做，exporter 只返回字符串。
"""

import asyncio
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.reports.generator import ReportData

logger = logging.getLogger(__name__)

SOURCE_TYPE_ZH = {
    "git": "Git 仓库",
    "archive": "ZIP 压缩包",
    "directory": "文件夹",
    "file": "单个文件",
    "local_path": "本地路径",
}

LANGUAGE_ZH = {
    "python": "Python",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "java": "Java",
    "go": "Go",
    "php": "PHP",
    "ruby": "Ruby",
    "c": "C",
    "c++": "C++",
    "shell": "Shell",
}

FRAMEWORK_ZH = {
    "flask": "Flask",
    "fastapi": "FastAPI",
    "django": "Django",
    "express": "Express",
    "spring": "Spring",
    "spring-boot": "Spring Boot",
    "gin": "Gin",
    "laravel": "Laravel",
    "rails": "Rails",
}

SEVERITY_ZH = {
    "critical": "极高危",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

FINDING_STATUS_ZH = {
    "unverified": "疑似",
    "verified": "已验证",
    "latent": "潜在隐患",
    "false_positive": "误报",
    "adopted": "已采纳",
}

VULN_TYPE_ZH = {
    "sql_injection": "SQL 注入",
    "command_injection": "命令注入",
    "file_upload": "文件上传",
    "idor": "越权访问",
    "broken_access": "越权/权限突破",
    "sensitive_data": "敏感信息泄露",
    "sensitive_info": "敏感信息泄露",
    "insecure_config": "不安全配置",
    "path_traversal": "路径遍历",
    "deserialization": "反序列化",
    "xss": "跨站脚本",
    "ssrf": "服务端请求伪造",
    "rce": "远程代码执行",
    "other": "其他",
}

DETECTED_BY_ZH = {
    "semgrep": "静态规则扫描",
    "bandit": "Python 安全扫描",
    "taint_engine": "污点追踪分析",
    "codeql": "代码分析",
    "other": "其他",
}

PATCH_STATUS_ZH = {
    "pending": "待采纳",
    "adopted": "已采纳",
    "rejected": "已拒绝",
    "superseded": "已替代",
}

RISK_ZH = {
    "critical": "极高危",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "secure": "安全",
}

DB_TYPE_ZH = {
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "sqlite": "SQLite",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "not_detected": "未识别",
}

PRIVILEGE_ZH = {
    "anonymous": "匿名",
    "user": "普通用户",
    "admin": "管理员",
    "system": "系统级",
}


def _map_zh(value, labels: dict[str, str], empty: str = "未识别") -> str:
    if not value:
        return empty
    text = str(value).strip().lower()
    return labels.get(text, str(value))


def _format_zh_time(value, empty: str = "未记录") -> str:
    if not value:
        return empty
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.strftime("%Y年%m月%d日 %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def _map_dict_keys(value, labels: dict[str, str]) -> dict:
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        text = str(key).lower()
        result[labels.get(text, key)] = item
    return result


def _map_detected_by(value) -> str:
    if not value:
        return "未识别"
    parts = [part.strip().lower() for part in str(value).split("+") if part.strip()]
    if not parts:
        return "未识别"
    return "+".join(DETECTED_BY_ZH.get(part, part) for part in parts)


def _map_protocol(value) -> str:
    if not value:
        return "未识别"
    text = str(value).strip().lower()
    return {
        "http": "网页传输协议",
        "https": "安全网页传输协议",
        "tcp": "传输控制协议",
        "udp": "用户数据报协议",
    }.get(text, text)


def _create_env(template_dir: str) -> Environment:
    """创建 Jinja2 环境。

    Args:
        template_dir: 模板目录路径

    Returns:
        Jinja2 Environment 实例
    """
    template_path = Path(template_dir)
    if not template_path.is_absolute():
        template_path = Path.cwd() / template_path

    env = Environment(
        loader=FileSystemLoader(str(template_path)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(
        {
            "source_type_zh": lambda v: _map_zh(v, SOURCE_TYPE_ZH),
            "language_zh": lambda v: _map_zh(v, LANGUAGE_ZH),
            "framework_zh": lambda v: _map_zh(v, FRAMEWORK_ZH),
            "severity_zh": lambda v: _map_zh(v, SEVERITY_ZH),
            "status_zh": lambda v: _map_zh(v, FINDING_STATUS_ZH),
            "vuln_type_zh": lambda v: _map_zh(v, VULN_TYPE_ZH),
            "detected_by_zh": _map_detected_by,
            "protocol_zh": _map_protocol,
            "patch_status_zh": lambda v: _map_zh(v, PATCH_STATUS_ZH),
            "risk_zh": lambda v: _map_zh(v, RISK_ZH),
            "db_type_zh": lambda v: _map_zh(v, DB_TYPE_ZH),
            "privilege_zh": lambda v: _map_zh(v, PRIVILEGE_ZH),
            "time_zh": _format_zh_time,
            "vuln_dist_zh": lambda v: _map_dict_keys(v, VULN_TYPE_ZH),
            "status_dist_zh": lambda v: _map_dict_keys(v, FINDING_STATUS_ZH),
        }
    )
    return env


def _data_to_dict(data: ReportData) -> dict:
    """将 ReportData 转换为模板可用的字典。

    Jinja2 模板通过此字典的 key 访问数据。
    """
    return {
        "task": data.task,
        "project": data.project,
        "runtime_profile": data.runtime_profile,
        "findings": data.findings,
        "attack_chains": data.attack_chains,
        "statistics": data.statistics,
        "overall_risk": data.overall_risk,
        "overall_cvss": data.overall_cvss,
        "sections": data.sections,
        "generated_at": data.generated_at,
    }


def to_markdown(data: ReportData, template_dir: str) -> str:
    """用 Jinja2 渲染 Markdown 报告。

    Args:
        data: ReportData 实例
        template_dir: 模板目录路径

    Returns:
        Markdown 格式的报告字符串
    """
    env = _create_env(template_dir)
    template = env.get_template("report.md.j2")
    return template.render(**_data_to_dict(data))


def to_html(data: ReportData, template_dir: str) -> str:
    """用 Jinja2 渲染 HTML 报告。

    Args:
        data: ReportData 实例
        template_dir: 模板目录路径

    Returns:
        HTML 格式的报告字符串
    """
    env = _create_env(template_dir)
    template = env.get_template("report.html.j2")
    return template.render(**_data_to_dict(data))


async def to_pdf_async(html_path: str, output_path: str) -> str | None:
    """使用本地 Chromium/Edge 将 HTML 报告导出为 PDF。"""
    candidates = []
    env_path = os.environ.get("PDF_BROWSER_PATH")
    if env_path:
        candidates.append(env_path)
    candidates.extend(
        [
            "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
            "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
            "C:/Program Files/Google/Chrome/Application/chrome.exe",
        ]
    )
    candidates.extend([shutil.which("chrome"), shutil.which("chromium"),
                       shutil.which("chromium-browser"), shutil.which("msedge")])

    browser_path = next(
        (candidate for candidate in candidates if candidate and Path(candidate).exists()),
        None,
    )
    if not browser_path:
        logger.warning(
            "[exporter] PDF export skipped: no browser found. html_path=%s",
            html_path,
        )
        return None

    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    html_file = Path(html_path).resolve()
    if not html_file.exists():
        logger.warning("[exporter] HTML report not found: %s", html_file)
        return None

    command = [
        str(browser_path),
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--print-to-pdf-no-header",
        f"--print-to-pdf={output}",
        html_file.as_uri(),
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
    except Exception as exc:
        logger.error("[exporter] PDF export failed: %s", exc)
        return None

    if output.exists() and output.stat().st_size > 0:
        logger.info("[exporter] PDF generated: %s", output)
        return str(output)

    logger.warning("[exporter] PDF output missing after export: %s", output)
    return None
