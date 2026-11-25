"""补丁生成器模块（AI 驱动 + 规则兜底）。

本模块是 AI 补丁生成的核心，负责三步：
1. 构造 Prompt：把漏洞的 snippet / source_code / sink_code / code_context /
   vuln_type / cwe_id / 修复要求（"不改变业务逻辑、最小改动"）塞进 prompt
2. 调用 LLM：通过 llm/factory.py 拿客户端，调模型生成修复后的代码；
   若 LLM 不可用（demo 模式或未配置 API Key），回退到规则引擎生成
3. 生成 Diff：用 Python 标准库 difflib.unified_diff 把 original_code 和
   patched_code 拼成 unified diff 格式（方便前端展示）

输出：original_code / patched_code / diff_content / description / llm_model / token_usage
"""

import difflib
import logging
import re
from dataclasses import dataclass
from typing import Any

from app.models import Finding

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────


@dataclass
class PatchGenerationResult:
    """补丁生成结果。"""

    original_code: str
    patched_code: str
    diff_content: str
    description: str
    llm_model: str | None = None
    token_usage: int | None = None


# ──────────────────────────────────────────────────────────────
# Prompt 构造
# ──────────────────────────────────────────────────────────────


def build_prompt(finding: Finding) -> str:
    """构造 LLM 修复提示词。

    把漏洞的 snippet / source_code / sink_code / code_context /
    vuln_type / cwe_id / 修复要求塞进 prompt。
    """
    vuln_type = finding.vuln_type or "unknown"
    cwe_id = finding.cwe_id or "N/A"
    snippet = finding.snippet or ""
    source_code = finding.source_code or ""
    sink_code = finding.sink_code or ""
    code_context = finding.code_context or ""
    file_path = finding.file_path or "unknown"
    line_start = finding.line_start or 0

    prompt = f"""You are a security engineer. Fix the following vulnerability with a minimal patch.

## Vulnerability Info
- Type: {vuln_type}
- CWE: {cwe_id}
- File: {file_path}
- Line: {line_start}

## Vulnerable Code
```python
{snippet or sink_code}
```

## Source (Input)
```python
{source_code}
```

## Code Context
```
{code_context}
```

## Requirements
1. Do NOT change business logic
2. Make the MINIMAL change to fix the vulnerability
3. Return ONLY the patched code block, no explanations
4. Use parameterized queries for SQL injection
5. Use shell=False for command execution
6. Validate file extensions for file upload
7. Add authorization checks for access control
8. Use html.escape() for XSS prevention
9. Use os.path.basename() for path traversal prevention

## Patched Code:
"""
    return prompt


# ──────────────────────────────────────────────────────────────
# 规则引擎（LLM 不可用时的兜底）
# ──────────────────────────────────────────────────────────────


def _rule_based_patch(finding: Finding, original_code: str) -> tuple[str, str]:
    """基于漏洞类型的规则化修复。

    Returns:
        (patched_code, description)
    """
    vuln_type = (finding.vuln_type or "").lower()
    cwe = (finding.cwe_id or "").lower()
    code = original_code
    description = ""

    command_pattern = re.search(
        r"(os\.system\s*\(|subprocess\.(run|call|Popen)\s*\(|shell\s*=\s*True)",
        code,
        flags=re.IGNORECASE,
    )
    sql_pattern = re.search(
        r"cursor\.execute\s*\(|conn\.execute\s*\(|db\.session\.execute\s*\(|SELECT|INSERT|UPDATE|DELETE",
        code,
        flags=re.IGNORECASE,
    )
    upload_pattern = re.search(
        r"(request\.files|\.save\s*\(|shutil\.copy|open\s*\(.+['\"]w)",
        code,
        flags=re.IGNORECASE,
    )
    xss_pattern = re.search(
        r"(return\s+rendered_html|return\s+.*comment|render_template_string|rendered_html\s*=)",
        code,
        flags=re.IGNORECASE,
    )
    traversal_pattern = re.search(
        r"os\.path\.join\s*\(.*(request\.args|filename|name)",
        code,
        flags=re.IGNORECASE,
    )
    access_pattern = re.search(
        r"(filter_by\(.*id|\.get_or_404\s*\(|db\.session\.get\s*\(|find_by_id\s*\()",
        code,
        flags=re.IGNORECASE,
    )
    weak_hash_pattern = re.search(
        r"hashlib\.(md5|sha1)\s*\(",
        code,
        flags=re.IGNORECASE,
    )

    if (
        "command" in vuln_type
        or "rce" in vuln_type
        or "exec" in vuln_type
        or "cwe-78" in cwe
    ):
        patched, desc = _fix_command_injection(code)
    elif "sql" in vuln_type or "cwe-89" in cwe:
        patched, desc = _fix_sql_injection(code)
    elif "upload" in vuln_type or "cwe-434" in cwe:
        patched, desc = _fix_file_upload(code)
    elif "xss" in vuln_type or "cwe-79" in cwe:
        patched, desc = _fix_xss(code)
    elif ("path" in vuln_type and "traversal" in vuln_type) or "cwe-22" in cwe:
        patched, desc = _fix_path_traversal(code)
    elif "access" in vuln_type or "idor" in vuln_type or "cwe-639" in cwe:
        patched, desc = _fix_broken_access(code)
    elif "deserializ" in vuln_type or "cwe-502" in cwe:
        patched, desc = _fix_deserialization(code)
    elif "cwe-327" in cwe:
        patched, desc = _fix_weak_hash(code)
    elif "sensitive" in vuln_type or ("info" in vuln_type and "leak" in vuln_type):
        patched, desc = _fix_sensitive_data(code)
    elif "cwe-330" in cwe or "insecure_config" in vuln_type or re.search(
        r"random\.(randint|random|uniform)\s*\(",
        code,
    ):
        patched, desc = _fix_insecure_random(code)
    elif command_pattern:
        patched, desc = _fix_command_injection(code)
    elif sql_pattern:
        patched, desc = _fix_sql_injection(code)
    elif upload_pattern:
        patched, desc = _fix_file_upload(code)
    elif xss_pattern:
        patched, desc = _fix_xss(code)
    elif traversal_pattern:
        patched, desc = _fix_path_traversal(code)
    elif access_pattern:
        patched, desc = _fix_broken_access(code)
    elif weak_hash_pattern:
        patched, desc = _fix_weak_hash(code)
    else:
        patched, desc = _fix_generic(code, vuln_type)

    return patched, desc


def _fix_sql_injection(code: str) -> tuple[str, str]:
    """SQL 注入修复：字符串拼接/f-string/.format() -> 参数化查询。"""
    patched = code

    # 模式 1: cursor.execute(f"SELECT ... {var}") -> cursor.execute("SELECT ... %s", (var,))
    # 先匹配完整的 f-string SQL（含 {var}），再替换
    pattern_f = re.compile(
        r"""(cursor|db|conn)\.execute\(\s*f["'](.+?)["']\s*\)""",
        re.DOTALL,
    )
    if pattern_f.search(patched):

        def _replace_f(m):
            prefix = m.group(1)
            sql_str = m.group(2)
            # 提取所有 {var} 占位符
            vars_found = re.findall(r"\{(\w+)\}", sql_str)
            # 替换 {var} -> %s（保持原 SQL 引号风格，避免破坏字符串）
            patched_sql = re.sub(r"\{\w+\}", "%s", sql_str)
            vars_tuple = ", ".join(vars_found)
            return f'{prefix}.execute("{patched_sql}", ({vars_tuple},))'

        patched = pattern_f.sub(_replace_f, patched)
        if patched != code:
            return patched, "SQL 注入修复：f-string 改为参数化查询"

    # 模式 2: cursor.execute("SELECT ... " + var) -> cursor.execute("SELECT ... %s", (var,))
    pattern_concat = re.compile(
        r"""(cursor|db|conn)\.execute\(\s*["'](.+?)["']\s*\+\s*(\w+)\s*\)""",
        re.DOTALL,
    )
    if pattern_concat.search(patched):

        def _replace_concat(m):
            prefix = m.group(1)
            sql_part = m.group(2)
            var = m.group(3).strip()
            patched_sql = sql_part + "%s"
            return f"{prefix}.execute('{patched_sql}', ({var},))"

        patched = pattern_concat.sub(_replace_concat, patched)
        if patched != code:
            return (
                patched,
                "SQL 注入修复：字符串拼接改为参数化查询",
            )

    # 模式 3: cursor.execute("SELECT ... {}".format(var)) -> cursor.execute("SELECT ... %s", (var,))
    pattern_format = re.compile(
        r"""(cursor|db|conn)\.execute\(\s*["'](.+?)["']\.format\((.+?)\)\s*\)""",
        re.DOTALL,
    )
    if pattern_format.search(patched):

        def _replace_format(m):
            prefix = m.group(1)
            sql_part = m.group(2)
            var = m.group(3).strip()
            patched_sql = sql_part.replace("{}", "%s")
            return f'{prefix}.execute("{patched_sql}", ({var},))'

        patched = pattern_format.sub(_replace_format, patched)
        if patched != code:
            return patched, "SQL 注入修复：format 拼接改为参数化查询"

    return code, "SQL 注入已识别，但未匹配到可自动修复的代码模式"


def _fix_command_injection(code: str) -> tuple[str, str]:
    """命令注入修复：os.system/subprocess shell=True -> subprocess shell=False。"""
    patched = code

    # os.system(cmd) -> subprocess.run([..], shell=False)
    # 替换 os.system(...) 为 subprocess.run([...], shell=False)
    patched = re.sub(
        r"os\.system\(\s*([^)]+?)\s*\)",
        lambda m: f"subprocess.run([{m.group(1).strip()}], shell=False)",
        patched,
    )

    # subprocess.call(cmd, shell=True) -> subprocess.call([cmd_parts], shell=False)
    patched = re.sub(
        r"subprocess\.(call|run|Popen)\(\s*(.+?)\s*,\s*shell\s*=\s*True\s*\)",
        lambda m: f"subprocess.{m.group(1)}([{m.group(2).strip()}], shell=False)",
        patched,
        flags=re.DOTALL,
    )

    if patched != code:
        if "subprocess." in patched and not re.search(
            r"(^|\n)\s*(import subprocess|from subprocess)\b",
            patched,
        ):
            lines = patched.splitlines(keepends=True)
            insert_at = len(lines)
            for idx, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")):
                    insert_at = idx
                    break
                if stripped.startswith(("def ", "class ", "@", "#", '"""')):
                    continue
            lines.insert(insert_at, "import subprocess\n\n")
            patched = "".join(lines)
        return (
            patched,
            "命令注入修复：禁用 shell，改为参数列表执行",
        )
    return code, "命令注入已识别，但未匹配到可自动修复的代码模式"


def _fix_file_upload(code: str) -> tuple[str, str]:
    """文件上传修复：添加扩展名校验。"""
    if "ALLOWED_EXTENSIONS" not in code:
        ext_check = (
            'ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}\n\n'
            "def allowed_file(filename):\n"
            '    return "." in filename and \\\n'
            '           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS\n\n'
        )
        patched = ext_check + code
        return patched, "文件上传修复：增加允许的扩展名校验"
    return code, "文件上传修复：已存在扩展名检查"


def _fix_xss(code: str) -> tuple[str, str]:
    """XSS 修复：添加 html.escape()。"""
    if "html.escape" not in code:
        patched = "import html\n" + re.sub(
            r"return\s+(f?['\"].*?)\s*$",
            lambda m: f"return html.escape({m.group(1)})",
            code,
            flags=re.MULTILINE,
        )
        if patched != "import html\n" + code:
            return patched, "跨站脚本修复：输出内容增加 HTML 转义"
    return code, "跨站脚本已识别，但未匹配到可自动修复的代码模式"


def _fix_path_traversal(code: str) -> tuple[str, str]:
    """路径穿越修复：添加 os.path.basename() 校验。"""
    if "os.path.basename" not in code:
        patched = re.sub(
            r"open\(\s*os\.path\.join\(\s*(\w+),\s*(\w+)\s*\)",
            r"open(os.path.join(\1, os.path.basename(\2)))",
            code,
        )
        if patched != code:
            return (
                patched,
                "路径遍历修复：使用 os.path.basename() 限制路径",
            )
    return code, "路径遍历已识别，但未匹配到可自动修复的代码模式"


def _fix_broken_access(code: str) -> tuple[str, str]:
    """越权访问修复：添加权限校验。"""
    if re.search(
        r"(conn|cursor|db)\.execute\s*\(.*SELECT.*\+|SELECT.*\+.*\w+",
        code,
        flags=re.DOTALL | re.IGNORECASE,
    ):
        return _fix_sql_injection(code)
    if "current_user" in code and "if not" not in code:
        patched = code.replace(
            "def ",
            "def _check_access(current_user, resource_owner):\n"
            "    if current_user.id != resource_owner:\n"
            "        abort(403)\n\n"
            "def ",
            1,
        )
        return patched, "越权修复：增加资源归属校验"
    return code, "越权问题已识别，但未匹配到可自动修复的代码模式"


def _fix_deserialization(code: str) -> tuple[str, str]:
    """反序列化修复：pickle.loads -> restricted loader。"""
    if "pickle.loads" in code:
        patched = code.replace(
            "pickle.loads",
            "RestrictedUnpickler.loads",
        )
        return (
            patched,
            "反序列化修复：使用受限反序列化器替换 pickle.loads",
        )
    return code, "反序列化已识别，但未匹配到可自动修复的代码模式"


def _fix_weak_hash(code: str) -> tuple[str, str]:
    """弱哈希修复：MD5/SHA-1 改为 SHA-256。"""
    patched = re.sub(
        r"hashlib\.(md5|sha1)\s*\(",
        "hashlib.sha256(",
        code,
        flags=re.IGNORECASE,
    )
    if patched != code:
        return patched, "弱哈希修复：MD5/SHA-1 改为 SHA-256"
    return code, "弱哈希已识别，但未匹配到可自动修复的代码模式"


def _fix_insecure_random(code: str) -> tuple[str, str]:
    """不安全随机数修复：改用密码学安全随机源。"""
    patched = re.sub(
        r"random\.(randint|random|uniform)\s*\(",
        "random.SystemRandom().\\1(",
        code,
    )
    if patched != code:
        return patched, "不安全随机数修复：改用系统安全随机源"
    return code, "不安全随机数已识别，但未匹配到可自动修复的代码模式"


def _fix_sensitive_data(code: str) -> tuple[str, str]:
    """敏感信息泄露修复：移除调试输出。"""
    patched = re.sub(
        r"print\(\s*['\"]?(password|secret|token|key|credential)['\"]?\s*\)",
        "# [SECURITY] Removed sensitive data output",
        code,
        flags=re.IGNORECASE,
    )
    if patched != code:
        return patched, "敏感信息修复：移除凭据调试输出"
    return code, "敏感信息泄露已识别，但未匹配到可自动修复的代码模式"


def _fix_generic(code: str, vuln_type: str) -> tuple[str, str]:
    """通用兜底修复建议。"""
    return code, f"暂无可自动修复的规则（漏洞类型：{vuln_type}），请人工复核"


# ──────────────────────────────────────────────────────
# Diff 生成
# ──────────────────────────────────────────────────────


def generate_diff(
    original_code: str,
    patched_code: str,
    file_path: str = "vulnerable_code",
) -> str:
    """用 difflib.unified_diff 生成 unified diff 格式。

    Args:
        original_code: 原始代码
        patched_code: 修复后代码
        file_path: 文件路径标识（用于 diff 头部）

    Returns:
        unified diff 字符串
    """
    orig_lines = original_code.splitlines(keepends=True)
    patched_lines = patched_code.splitlines(keepends=True)

    diff_lines = list(
        difflib.unified_diff(
            orig_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="\n",
        )
    )
    return "".join(diff_lines)


# ──────────────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────


def generate_patch(finding: Finding) -> PatchGenerationResult:
    """为漏洞生成修复补丁。

    流程：
    1. 从 finding 提取原始代码（优先 sink_code，其次 snippet）
    2. 构造 LLM prompt
    3. 尝试调用 LLM（若可用），否则回退到规则引擎
    4. 用 difflib 生成 unified diff
    5. 返回完整结果

    Args:
        finding: 漏洞 ORM 对象

    Returns:
        PatchGenerationResult
    """
    # 1. 提取原始代码（优先 snippet：含完整漏洞代码行，而非 sink_code 仅函数名）
    original_code = (
        finding.code_context
        or finding.snippet
        or finding.sink_code
        or ""
    )
    if not original_code:
        original_code = finding.source_code or ""
    if not original_code:
        logger.warning("[generator] No code available for finding %s", finding.id)
        return PatchGenerationResult(
            original_code="",
            patched_code="",
            diff_content="",
            description="未找到可修复的漏洞代码，请人工复核",
            llm_model=None,
            token_usage=None,
        )

    # 2. 尝试 LLM 调用
    llm_model = None
    token_usage = None
    patched_code = None
    description = ""

    try:
        from app.core.config import get_settings

        settings = get_settings()
        if settings.LLM_MODE != "demo" and (
            settings.OPENAI_API_KEY or settings.OLLAMA_BASE_URL
        ):
            # LLM 可用，构造 prompt 并调用
            prompt = build_prompt(finding)
            try:
                from app.llm.factory import LlmFactory

                client = LlmFactory.get_client()
                response, usage = client.chat_with_usage(
                    [{"role": "user", "content": prompt}]
                )
                patched_code = _extract_code_from_response(response)
                llm_model = getattr(
                    client,
                    "model",
                    settings.OLLAMA_MODEL or settings.OPENAI_MODEL,
                )
                token_usage = usage
                description = "智能模型生成的补丁：" + str(llm_model)
                patched_code = _apply_llm_patch(
                    original_code,
                    finding.snippet or "",
                    patched_code,
                )
                logger.info(
                    "[generator] LLM patch generated for finding %s (tokens=%s)",
                    finding.id,
                    token_usage,
                )
            except Exception as e:
                logger.warning(
                    "[generator] LLM call failed, falling back to rules: %s",
                    e,
                )
                patched_code = None
    except Exception as e:
        logger.debug("[generator] LLM setup skipped: %s", e)
        patched_code = None

    # 3. 规则兜底
    if not patched_code:
        patched_code, description = _rule_based_patch(finding, original_code)
        llm_model = "rule-engine"
        token_usage = 0
        logger.info(
            "[generator] Rule-based patch for finding %s (%s)",
            finding.id,
            finding.vuln_type,
        )

    # 4. 生成 Diff
    file_path = finding.file_path or "vulnerable_code"
    diff_content = generate_diff(original_code, patched_code, file_path)

    return PatchGenerationResult(
        original_code=original_code,
        patched_code=patched_code,
        diff_content=diff_content,
        description=description,
        llm_model=llm_model,
        token_usage=token_usage,
    )


def _extract_code_from_response(response: str) -> str | None:
    """从 LLM 响应中提取代码块。

    LLM 通常会将代码包裹在 ``` ... ``` 中，也可能直接返回代码。
    """
    # 尝试提取 ```python ... ``` 或 ``` ... ```
    match = re.search(r"```(?:python)?\s*\n(.*?)```", response, re.DOTALL)
    if match:
        return match.group(1).strip()
    # 直接返回（假设是纯代码）
    if response.strip() and not response.strip().startswith("I"):
        return response.strip()
    return None


def _apply_llm_patch(
    original_code: str,
    snippet: str,
    response_code: str | None,
) -> str | None:
    """将 LLM 返回的片段式修复合并进完整源码。"""
    if not response_code:
        return None
    stripped_response = response_code.strip()
    if len(stripped_response) >= max(1, int(len(original_code) * 0.6)):
        return response_code
    if not snippet or stripped_response not in snippet and snippet.strip() not in original_code:
        return response_code

    snippet_line = snippet.strip()
    if snippet_line not in original_code:
        return response_code
    indent_match = re.match(r"^[ \t]*", snippet)
    indent = indent_match.group(0) if indent_match else ""
    response_lines = stripped_response.splitlines()
    if not response_lines:
        return response_code
    patched_snippet = "\n".join(
        [response_lines[0].strip()]
        + [
            f"{indent}{line.strip()}" if line.strip() else ""
            for line in response_lines[1:]
        ]
    )
    return original_code.replace(snippet_line, patched_snippet, 1)
