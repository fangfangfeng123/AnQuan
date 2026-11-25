"""Sanitizer 规则定义模块。

本模块定义安全过滤函数（净化器），用于在污点传播路径中识别
是否存在有效的安全过滤。当 Source 到 Sink 的传播路径中存在
Sanitizer 时，该路径被判定为非漏洞（has_sanitizer=True）。

每条 SanitizerRule 包含:
- rule_id:           规则唯一标识
- name:              规则名称
- language:          适用语言
- vuln_type:          防护的漏洞类型 (sql_injection / command_injection / file_upload / broken_access)
- patterns:          匹配模式列表（正则表达式）
- description:       规则说明

Sanitizer 规则按漏洞类型分组:
- SQL 注入防护: 参数化查询（execute with %s/?）、escape_string()、SQLAlchemy text() with bindparams
- XSS 防护:     html.escape()、bleach.clean()
- 命令注入防护:  shlex.quote()、subprocess with list args (shell=False)
- 路径穿越防护:  os.path.basename()、safe_join()、werkzeug.utils.secure_filename()
- 文件上传防护:  allowed_file() 类型校验、os.path.splitext() 扩展名检查
"""

import re
from dataclasses import dataclass, field


@dataclass
class SanitizerRule:
    """单条 Sanitizer 规则。"""

    rule_id: str
    name: str
    language: str
    vuln_type: str
    patterns: list[str]
    description: str = ""

    # 编译后的正则（内部使用）
    _compiled: list[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]

    def match(self, code_line: str) -> bool:
        """检查一行代码是否匹配此 Sanitizer 规则。

        Args:
            code_line: 源码行文本

        Returns:
            是否匹配
        """
        return any(c.search(code_line) for c in self._compiled)


# ──────────────────────────────────────────────────────
# Python Sanitizer 规则
# ──────────────────────────────────────────────────────

# SQL 注入防护
_PY_SQL_SANITIZER_PATTERNS = [
    # 参数化查询：execute(sql, params) 或 execute(sql, (param,))
    r"\.execute\s*\(\s*[^,]+\s*,\s*\(?[^)]+\)?\s*\)",  # execute("...%s...", (var,))
    r"\.execute\s*\(\s*[^,]+\s*,\s*\[",  # execute("...?", [var])
    # SQLAlchemy text() with bindparams
    r"text\s*\(\s*[^)]+\s*\)\s*\.bindparams",
    r"text\s*\(\s*['\"][^'\"]*:w\b['\"]",
    # escape functions
    r"escape_string\s*\(",
    r"mysql_escape_string\s*\(",
    r"psycopg2\.sql\s*\.",
    r"\.escape\s*\(",
]

# 命令注入防护
_PY_CMD_SANITIZER_PATTERNS = [
    r"shlex\.quote\s*\(",
    r"shlex\.split\s*\(",  # split + list args = safe
    r"subprocess\.\w+\s*\([^,]+,\s*shell\s*=\s*False",
    r"subprocess\.\w+\s*\(\s*\[",  # list form = safe
    r"pipes\.quote\s*\(",
]

# 路径穿越防护
_PY_PATH_SANITIZER_PATTERNS = [
    r"os\.path\.basename\s*\(",
    r"safe_join\s*\(",
    r"secure_filename\s*\(",
    r"werkzeug\.utils\.secure_filename\s*\(",
    r"os\.path\.normpath\s*\(",
    r"os\.path\.abspath\s*\(",
    r"realpath\s*\(",
]

# 文件上传防护（类型校验）
_PY_FILE_SANITIZER_PATTERNS = [
    r"allowed_file\s*\(",
    r"allowed_extension",
    r"ALLOWED_EXTENSIONS",
    r"os\.path\.splitext\s*\(",
    r"\.filename\.endswith\s*\(",
    r"\.filename\.rsplit\s*\(",
    r"mimetypes\.guess_type\s*\(",
    r"magic\.from_file\s*\(",
    r"verify_extension\s*\(",
    r"check_extension\s*\(",
    r"validate_file_type\s*\(",
]

# ──────────────────────────────────────────────────────
# JavaScript / Node.js Sanitizer 规则
# ──────────────────────────────────────────────────────

_JS_SQL_SANITIZER_PATTERNS = [
    r"\.query\s*\(\s*[^,]+\s*,\s*\[",  # db.query(sql, [params])
    r"\.query\s*\(\s*[^,]+\s*,\s*\{",  # db.query(sql, {replacements})
    r"mysql\.escape\s*\(",
    r"sql\.escape\s*\(",
    r"encodeURIComponent\s*\(",
    r"escape\s*\(",
]

_JS_CMD_SANITIZER_PATTERNS = [
    r"shelljs\.escape\s*\(",
    r"shell-escape\s*\(",
    r"\.split\s*\(\s*['\"]\\s+['\"]\s*\)",  # split into array = safe
]

_JS_PATH_SANITIZER_PATTERNS = [
    r"path\.basename\s*\(",
    r"path\.resolve\s*\(",
    r"path\.normalize\s*\(",
    r"sanitize\s*\(",
]

_JS_FILE_SANITIZER_PATTERNS = [
    r"ALLOWED_TYPES",
    r"allowedExtensions",
    r"mimeType\s*===\s*['\"]",
    r"path\.extname\s*\(",
    r"fileFilter\s*[:=]",
]

# ──────────────────────────────────────────────────────
# Java Sanitizer 规则
# ──────────────────────────────────────────────────────

_JAVA_SQL_SANITIZER_PATTERNS = [
    r"PreparedStatement",
    r"\.setString\s*\(",
    r"\.setInt\s*\(",
    r"\.setLong\s*\(",
    r"StringEscapeUtils\.escapeSql",
    r"ESAPI\.encoder",
    r"AntiSamy",
]

_JAVA_CMD_SANITIZER_PATTERNS = [
    r"CommandSanitizer",
    r"ESAPI\.encoder",
]

_JAVA_PATH_SANITIZER_PATTERNS = [
    r"Paths\.get\s*\(",
    r"FilenameUtils\.getName",
    r"normalizePath",
    r"sanitizeFileName",
]

# ──────────────────────────────────────────────────────
# 规则集合
# ──────────────────────────────────────────────────────

SANITIZER_RULES: list[SanitizerRule] = [
    # ── Python ──
    SanitizerRule(
        rule_id="PY-SQL-SAN-01",
        name="Python SQL 参数化查询",
        language="python",
        vuln_type="sql_injection",
        patterns=_PY_SQL_SANITIZER_PATTERNS,
        description="参数化查询（execute with params）或 escape 函数",
    ),
    SanitizerRule(
        rule_id="PY-CMD-SAN-01",
        name="Python 命令注入防护",
        language="python",
        vuln_type="command_injection",
        patterns=_PY_CMD_SANITIZER_PATTERNS,
        description="shlex.quote / subprocess with shell=False / list args",
    ),
    SanitizerRule(
        rule_id="PY-PATH-SAN-01",
        name="Python 路径穿越防护",
        language="python",
        vuln_type="file_upload",
        patterns=_PY_PATH_SANITIZER_PATTERNS,
        description="os.path.basename / secure_filename / safe_join",
    ),
    SanitizerRule(
        rule_id="PY-FILE-SAN-01",
        name="Python 文件类型校验",
        language="python",
        vuln_type="file_upload",
        patterns=_PY_FILE_SANITIZER_PATTERNS,
        description="allowed_file / splitext / endswith / mimetypes 校验",
    ),
    # ── JavaScript ──
    SanitizerRule(
        rule_id="JS-SQL-SAN-01",
        name="Node.js SQL 参数化查询",
        language="javascript",
        vuln_type="sql_injection",
        patterns=_JS_SQL_SANITIZER_PATTERNS,
        description="参数化查询或 escape 函数",
    ),
    SanitizerRule(
        rule_id="JS-CMD-SAN-01",
        name="Node.js 命令注入防护",
        language="javascript",
        vuln_type="command_injection",
        patterns=_JS_CMD_SANITIZER_PATTERNS,
        description="shell-escape / split into array",
    ),
    SanitizerRule(
        rule_id="JS-PATH-SAN-01",
        name="Node.js 路径穿越防护",
        language="javascript",
        vuln_type="file_upload",
        patterns=_JS_PATH_SANITIZER_PATTERNS,
        description="path.basename / path.resolve / sanitize",
    ),
    SanitizerRule(
        rule_id="JS-FILE-SAN-01",
        name="Node.js 文件类型校验",
        language="javascript",
        vuln_type="file_upload",
        patterns=_JS_FILE_SANITIZER_PATTERNS,
        description="ALLOWED_TYPES / extname / fileFilter",
    ),
    # ── Java ──
    SanitizerRule(
        rule_id="JAVA-SQL-SAN-01",
        name="Java SQL 参数化查询",
        language="java",
        vuln_type="sql_injection",
        patterns=_JAVA_SQL_SANITIZER_PATTERNS,
        description="PreparedStatement / setString / ESAPI",
    ),
    SanitizerRule(
        rule_id="JAVA-CMD-SAN-01",
        name="Java 命令注入防护",
        language="java",
        vuln_type="command_injection",
        patterns=_JAVA_CMD_SANITIZER_PATTERNS,
        description="CommandSanitizer / ESAPI",
    ),
    SanitizerRule(
        rule_id="JAVA-PATH-SAN-01",
        name="Java 路径穿越防护",
        language="java",
        vuln_type="file_upload",
        patterns=_JAVA_PATH_SANITIZER_PATTERNS,
        description="Paths.get / FilenameUtils.getName / normalizePath",
    ),
]


def get_sanitizer_rules(
    language: str, vuln_type: str | None = None
) -> list[SanitizerRule]:
    """获取适用于指定语言的 Sanitizer 规则。

    Args:
        language: 语言 (python / javascript / java)
        vuln_type: 可选，按漏洞类型过滤

    Returns:
        匹配的 SanitizerRule 列表
    """
    matched = [r for r in SANITIZER_RULES if r.language == language]
    if vuln_type:
        matched = [r for r in matched if r.vuln_type == vuln_type]
    return matched


def find_sanitizers_in_line(
    code_line: str, language: str, vuln_type: str | None = None
) -> list[SanitizerRule]:
    """检查一行代码匹配哪些 Sanitizer 规则。

    Args:
        code_line: 源码行文本
        language: 语言
        vuln_type: 可选，按漏洞类型过滤

    Returns:
        匹配的 SanitizerRule 列表（可能为空）
    """
    rules = get_sanitizer_rules(language, vuln_type)
    return [r for r in rules if r.match(code_line)]
