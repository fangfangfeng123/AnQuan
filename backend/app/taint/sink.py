"""Sink 规则定义模块。

本模块定义各类语言的污点汇聚点（敏感操作函数），用于污点分析引擎
识别代码中哪些位置执行了危险操作。

每条 SinkRule 包含:
- rule_id:        规则唯一标识
- name:           规则名称
- language:       适用语言 (python / javascript / java / php / go)
- framework:      适用框架 (flask / django / fastapi / express / spring / generic)
- vuln_type:      关联的漏洞类型 (sql_injection / command_injection / file_upload / broken_access / sensitive_data)
- cwe_id:         CWE 编号
- owasp:          OWASP Top 10 分类
- patterns:       匹配模式列表（正则表达式，用于在源码行中识别 Sink 调用）
- param_position: 污点数据在函数参数中的位置（0-based，-1 表示整个调用）
- description:    规则说明

Sink 规则按漏洞类型分组:
- SQL 注入:       execute() / cursor.execute() / db.session.execute() / 字符串拼接到 SQL
- 命令注入:       os.system() / subprocess.call() / subprocess.run() / subprocess.Popen()
- 文件上传:       无类型校验的 .save() / shutil.copyfileobj()
- IDOR:           可控 ID 直接查数据库（findById / filter(id=) / where id=）
- 敏感信息泄露:   硬编码密钥/密码/Token（与 Source 规则重叠，模式匹配）
"""

import re
from dataclasses import dataclass, field


@dataclass
class SinkRule:
    """单条 Sink 规则。"""

    rule_id: str
    name: str
    language: str
    framework: str
    vuln_type: str
    cwe_id: str
    owasp: str
    patterns: list[str]
    param_position: int = 0
    description: str = ""

    # 编译后的正则（内部使用）
    _compiled: list[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]

    def match(self, code_line: str) -> bool:
        """检查一行代码是否匹配此 Sink 规则。

        Args:
            code_line: 源码行文本

        Returns:
            是否匹配
        """
        return any(c.search(code_line) for c in self._compiled)

    def extract_sink_expr(self, code_line: str) -> str | None:
        """从匹配的 Sink 行中提取 Sink 表达式（函数调用部分）。

        例如 `db.session.execute(sql)` -> "db.session.execute(sql)"
            `os.system(cmd)` -> "os.system(cmd)"

        Args:
            code_line: 源码行文本

        Returns:
            Sink 表达式，未匹配则 None
        """
        for compiled in self._compiled:
            m = compiled.search(code_line)
            if m:
                # 返回匹配到的完整片段
                return m.group(0)
        return None


# ──────────────────────────────────────────────────────
# Python Sink 规则
# ──────────────────────────────────────────────────────

# SQL 执行 Sink（Python）
_PY_SQL_SINK_PATTERNS = [
    r"cursor\.execute\s*\(",
    r"\.execute\s*\(",
    r"db\.session\.execute\s*\(",
    r"db\.engine\.execute\s*\(",
    r"db\.engine\.connect\s*\(\s*\)\s*\.execute",
    r"session\.execute\s*\(",
    r"connection\.execute\s*\(",
    r"engine\.execute\s*\(",
    r"text\s*\(.*\+.*\)",  # SQLAlchemy text() with string concat
    # 字符串拼接到 SQL
    r'["\'].*SELECT.*["\']\s*\+',  # "SELECT ..." + var
    r'["\'].*INSERT.*["\']\s*\+',
    r'["\'].*UPDATE.*["\']\s*\+',
    r'["\'].*DELETE.*["\']\s*\+',
    r'f["\'].*SELECT.*\{',  # f"SELECT ...{var}"
    r'f["\'].*INSERT.*\{',
    r'f["\'].*UPDATE.*\{',
    r'f["\'].*DELETE.*\{',
    r'["\'].*WHERE.*["\']\s*\+',
    r'f["\'].*WHERE.*\{',
]

# 命令执行 Sink（Python）
_PY_CMD_SINK_PATTERNS = [
    r"os\.system\s*\(",
    r"os\.popen\s*\(",
    r"os\.spawn[lvp]?\w*\s*\(",
    r"subprocess\.call\s*\(",
    r"subprocess\.run\s*\(",
    r"subprocess\.Popen\s*\(",
    r"subprocess\.check_output\s*\(",
    r"subprocess\.check_call\s*\(",
    r"commands\.getoutput\s*\(",
    r"commands\.getstatusoutput\s*\(",
    r"exec\s*\(",  # Python 内置 exec
    r"eval\s*\(",  # Python 内置 eval
    r"pty\.spawn\s*\(",
    r"paramiko.*exec_command\s*\(",
]

# 文件上传 Sink（Python — 无类型校验的 save）
_PY_FILE_SINK_PATTERNS = [
    r"\.save\s*\(",  # f.save(path)
    r"shutil\.copyfileobj\s*\(",
    r"shutil\.copy\s*\(",
    r"open\s*\(.+,\s*['\"]w",  # open(path, 'w') write
    r"shutil\.copyfile\s*\(",
    r"\.save_storage_as\s*\(",
]

# IDOR Sink（Python — 可控 ID 直接查数据）
_PY_IDOR_SINK_PATTERNS = [
    r"\.get\s*\(\s*\w*id\b",  # Model.get(id) / Model.get(user_id)
    r"\.query\s*\(\s*\)\s*\.filter\s*\(\s*\w+\.id\s*==\s*\w+\b",  # filter(id == var)
    r"\.query\s*\(\s*\)\s*\.filter_by\s*\(\s*\w+\s*=\s*\w+\b",  # filter_by(id=var)
    r"\.get_by_id\s*\(",
    r"\.find_by\s*\(",
    r"\.get_or_404\s*\(\s*\w*,\s*\w+\b",  # get_or_404(Model, id)
    r"SELECT\s+.*\s+WHERE\s+.*=\s*['\"]?\s*['\"]?\s*\+",  # SQL with id concat
    r'f["\'].*WHERE.*\{.*\}',  # f"...WHERE id={user_id}"
    r"db\.session\.get\s*\(\s*\w+,\s*\w+\b",  # db.session.get(Model, id)
]

# ──────────────────────────────────────────────────────
# JavaScript / Node.js Sink 规则
# ──────────────────────────────────────────────────────

_JS_SQL_SINK_PATTERNS = [
    r"\.query\s*\(",
    r"\.execute\s*\(",
    r"sequelize\.query\s*\(",
    r"mongoose\.model\s*\(.*\)\s*\.\w+\s*\(",
    r"\.find\s*\(",
    r"\.findById\s*\(",
    r"\.findOne\s*\(",
    r"\+.*SELECT\b",
    r"`.*SELECT.*\$\{",
    r"\+.*INSERT\b",
    r"\+.*UPDATE\b",
    r"\+.*DELETE\b",
    r"`.*WHERE.*\$\{",
]

_JS_CMD_SINK_PATTERNS = [
    r"child_process\.exec\s*\(",
    r"child_process\.execSync\s*\(",
    r"child_process\.spawn\s*\(",
    r"child_process\.fork\s*\(",
    r"exec\s*\(",
    r"execSync\s*\(",
    r"spawn\s*\(",
    r"\beval\s*\(",
    r"Function\s*\(",
    r"require\s*\(\s*['\"]vm['\"]\s*\)",
]

_JS_FILE_SINK_PATTERNS = [
    r"createWriteStream\s*\(",
    r"\.pipe\s*\(\s*fs\.",
    r"writeFile\s*\(",
    r"writeFileSync\s*\(",
    r"fs\.write\s*\(",
    r"\.save\s*\(",
]

_JS_IDOR_SINK_PATTERNS = [
    r"\.findById\s*\(\s*req\.params",
    r"\.findById\s*\(\s*req\.query",
    r"\.findOne\s*\(\s*\{.*:\s*req\.params",
    r"\.findOne\s*\(\s*\{.*:\s*req\.query",
    r"\.find\s*\(\s*\{.*:\s*req\.params",
    r"\.deleteOne\s*\(\s*\{.*:\s*req\.params",
    r"\.findByIdAndDelete\s*\(\s*req\.params",
    r"\.findByIdAndRemove\s*\(\s*req\.params",
]

# ──────────────────────────────────────────────────────
# Java Sink 规则
# ──────────────────────────────────────────────────────

_JAVA_SQL_SINK_PATTERNS = [
    r"\.executeQuery\s*\(",
    r"\.executeUpdate\s*\(",
    r"\.execute\s*\(",
    r"Statement.*\.execute",
    r"PreparedStatement.*\.execute",
    r"jdbcTemplate.*\.query",
    r"jdbcTemplate.*\.update",
    r'".*SELECT.*"\s*\+',
    r'".*INSERT.*"\s*\+',
    r'".*UPDATE.*"\s*\+',
    r'".*DELETE.*"\s*\+',
    r'".*WHERE.*"\s*\+',
    r"String\.format\(.*SELECT",
]

_JAVA_CMD_SINK_PATTERNS = [
    r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec",
    r"ProcessBuilder\s*\(",
    r"Process.*\.start\s*\(",
    r"\.exec\s*\(",
]

_JAVA_FILE_SINK_PATTERNS = [
    r"FileOutputStream\s*\(",
    r"Files\.write\s*\(",
    r"transferTo\s*\(",
    r"\.transferTo\s*\(",
    r"FileWriter\s*\(",
    r"BufferedWriter\s*\(",
]

_JAVA_IDOR_SINK_PATTERNS = [
    r"findById\s*\(",
    r"getOne\s*\(",
    r"findOne\s*\(",
    r"\.get\s*\(\s*\w+Id\b",
    r"repository.*findBy",
]

# ──────────────────────────────────────────────────────
# 规则集合
# ──────────────────────────────────────────────────────

SINK_RULES: list[SinkRule] = [
    # ── Python SQL 注入 Sink ──
    SinkRule(
        rule_id="PY-SQL-SINK-01",
        name="Python SQL 执行 Sink",
        language="python",
        framework="generic",
        vuln_type="sql_injection",
        cwe_id="CWE-89",
        owasp="A03:2021",
        patterns=_PY_SQL_SINK_PATTERNS,
        description="SQL 执行函数或字符串拼接到 SQL 语句",
    ),
    # ── Python 命令注入 Sink ──
    SinkRule(
        rule_id="PY-CMD-SINK-01",
        name="Python 命令执行 Sink",
        language="python",
        framework="generic",
        vuln_type="command_injection",
        cwe_id="CWE-78",
        owasp="A03:2021",
        patterns=_PY_CMD_SINK_PATTERNS,
        description="os.system / subprocess 等命令执行函数",
    ),
    # ── Python 文件上传 Sink ──
    SinkRule(
        rule_id="PY-FILE-SINK-01",
        name="Python 文件写入 Sink",
        language="python",
        framework="generic",
        vuln_type="file_upload",
        cwe_id="CWE-434",
        owasp="A04:2021",
        patterns=_PY_FILE_SINK_PATTERNS,
        description="无类型校验的文件保存操作",
    ),
    # ── Python IDOR Sink ──
    SinkRule(
        rule_id="PY-IDOR-SINK-01",
        name="Python 可控 ID 直接查询 Sink",
        language="python",
        framework="generic",
        vuln_type="broken_access",
        cwe_id="CWE-639",
        owasp="A01:2021",
        patterns=_PY_IDOR_SINK_PATTERNS,
        description="用户可控 ID 直接用于数据库查询，缺少归属校验",
    ),
    # ── JavaScript SQL 注入 Sink ──
    SinkRule(
        rule_id="JS-SQL-SINK-01",
        name="JavaScript SQL 执行 Sink",
        language="javascript",
        framework="generic",
        vuln_type="sql_injection",
        cwe_id="CWE-89",
        owasp="A03:2021",
        patterns=_JS_SQL_SINK_PATTERNS,
        description="数据库查询函数或字符串拼接到 SQL",
    ),
    # ── JavaScript 命令注入 Sink ──
    SinkRule(
        rule_id="JS-CMD-SINK-01",
        name="JavaScript 命令执行 Sink",
        language="javascript",
        framework="generic",
        vuln_type="command_injection",
        cwe_id="CWE-78",
        owasp="A03:2021",
        patterns=_JS_CMD_SINK_PATTERNS,
        description="child_process.exec / eval 等命令执行",
    ),
    # ── JavaScript 文件上传 Sink ──
    SinkRule(
        rule_id="JS-FILE-SINK-01",
        name="JavaScript 文件写入 Sink",
        language="javascript",
        framework="generic",
        vuln_type="file_upload",
        cwe_id="CWE-434",
        owasp="A04:2021",
        patterns=_JS_FILE_SINK_PATTERNS,
        description="无类型校验的文件写入操作",
    ),
    # ── JavaScript IDOR Sink ──
    SinkRule(
        rule_id="JS-IDOR-SINK-01",
        name="JavaScript 可控 ID 直接查询 Sink",
        language="javascript",
        framework="express",
        vuln_type="broken_access",
        cwe_id="CWE-639",
        owasp="A01:2021",
        patterns=_JS_IDOR_SINK_PATTERNS,
        description="Express req.params 直接用于数据库查询",
    ),
    # ── Java SQL 注入 Sink ──
    SinkRule(
        rule_id="JAVA-SQL-SINK-01",
        name="Java SQL 执行 Sink",
        language="java",
        framework="generic",
        vuln_type="sql_injection",
        cwe_id="CWE-89",
        owasp="A03:2021",
        patterns=_JAVA_SQL_SINK_PATTERNS,
        description="JDBC Statement 执行或字符串拼接到 SQL",
    ),
    # ── Java 命令注入 Sink ──
    SinkRule(
        rule_id="JAVA-CMD-SINK-01",
        name="Java 命令执行 Sink",
        language="java",
        framework="generic",
        vuln_type="command_injection",
        cwe_id="CWE-78",
        owasp="A03:2021",
        patterns=_JAVA_CMD_SINK_PATTERNS,
        description="Runtime.exec / ProcessBuilder 等命令执行",
    ),
    # ── Java 文件上传 Sink ──
    SinkRule(
        rule_id="JAVA-FILE-SINK-01",
        name="Java 文件写入 Sink",
        language="java",
        framework="generic",
        vuln_type="file_upload",
        cwe_id="CWE-434",
        owasp="A04:2021",
        patterns=_JAVA_FILE_SINK_PATTERNS,
        description="无类型校验的文件写入操作",
    ),
    # ── Java IDOR Sink ──
    SinkRule(
        rule_id="JAVA-IDOR-SINK-01",
        name="Java 可控 ID 直接查询 Sink",
        language="java",
        framework="spring-boot",
        vuln_type="broken_access",
        cwe_id="CWE-639",
        owasp="A01:2021",
        patterns=_JAVA_IDOR_SINK_PATTERNS,
        description="Spring Data Repository 直接用 PathVariable 查询",
    ),
]


def get_sink_rules(
    language: str, framework: str = "generic", vuln_type: str | None = None
) -> list[SinkRule]:
    """获取适用于指定语言和框架的 Sink 规则。

    策略：返回所有匹配 language 的规则（Sink 规则按 framework 过滤，
    generic 规则总是适用）。如果指定了 framework，优先返回精确匹配，
    再补充 generic。

    Args:
        language:  语言 (python / javascript / java)
        framework: 框架
        vuln_type: 可选，按漏洞类型过滤

    Returns:
        匹配的 SinkRule 列表
    """
    # 获取该语言所有规则
    lang_rules = [r for r in SINK_RULES if r.language == language]

    # 精确匹配 framework 的规则
    matched = [r for r in lang_rules if r.framework == framework]
    # 补充 generic 规则
    generic = [r for r in lang_rules if r.framework == "generic"]
    existing_ids = {r.rule_id for r in matched}
    for r in generic:
        if r.rule_id not in existing_ids:
            matched.append(r)

    if vuln_type:
        matched = [r for r in matched if r.vuln_type == vuln_type]

    return matched


def find_sinks_in_line(
    code_line: str, language: str, framework: str = "generic"
) -> list[SinkRule]:
    """检查一行代码匹配哪些 Sink 规则。

    Args:
        code_line: 源码行文本
        language:  语言
        framework:  框架

    Returns:
        匹配的 SinkRule 列表（可能为空）
    """
    rules = get_sink_rules(language, framework)
    return [r for r in rules if r.match(code_line)]
