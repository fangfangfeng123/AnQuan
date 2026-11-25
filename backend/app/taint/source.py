"""Source 规则定义模块。

本模块定义各类语言的污点源（外部输入入口），用于污点分析引擎
识别代码中哪些位置接收了不可信的外部数据。

每条 SourceRule 包含:
- rule_id:        规则唯一标识
- name:           规则名称
- language:       适用语言 (python / javascript / java / php / go)
- framework:      适用框架 (flask / django / fastapi / express / spring / generic)
- vuln_type:      关联的漏洞类型 (sql_injection / command_injection / file_upload / broken_access / sensitive_data)
- patterns:       匹配模式列表（正则表达式，用于在源码行中识别 Source 调用）
- param_position: 污点数据在函数参数中的位置（0-based）
- description:    规则说明

Source 规则按漏洞类型分组:
- SQL 注入:       HTTP 参数 (request.args.get / req.query / request.getParameter 等)
- 命令注入:       HTTP 参数同上，但 Sink 为 os.system / subprocess
- 文件上传:       request.files / req.files / MultipartFile
- IDOR:           URL 路径参数 (req.params.id / @PathVariable)
- 敏感信息泄露:   硬编码密钥/密码/Token (不依赖外部输入，模式匹配)
"""

import re
from dataclasses import dataclass, field


@dataclass
class SourceRule:
    """单条 Source 规则。"""

    rule_id: str
    name: str
    language: str
    framework: str
    vuln_type: str
    patterns: list[str]
    param_position: int = 0
    description: str = ""

    # 编译后的正则（内部使用）
    _compiled: list[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]

    def match(self, code_line: str) -> bool:
        """检查一行代码是否匹配此 Source 规则。

        Args:
            code_line: 源码行文本

        Returns:
            是否匹配
        """
        return any(c.search(code_line) for c in self._compiled)

    def extract_var(self, code_line: str) -> str | None:
        """从匹配的 Source 行中提取被赋值的变量名。

        例如 `q = request.args.get("q")` -> "q"
            `user_id = req.params.id` -> "user_id"

        Args:
            code_line: 源码行文本

        Returns:
            变量名，未匹配则 None
        """
        # 匹配 `var_name = <source_pattern>` 形式
        m = re.match(r"\s*(\w+)\s*=\s*.+", code_line)
        if m:
            return m.group(1)
        return None


# ──────────────────────────────────────────────────────
# Python Source 规则
# ──────────────────────────────────────────────────────

# Flask / FastAPI HTTP 参数（SQL注入 / 命令注入 共用）
_PY_HTTP_PATTERNS = [
    r"request\.args\.get\s*\(",
    r"request\.args\[",
    r"request\.form\.get\s*\(",
    r"request\.form\[",
    r"request\.json\.get\s*\(",
    r"request\.json\[",
    r"request\.values\.get\s*\(",
    r"request\.values\[",
    r"request\.cookies\.get\s*\(",
    r"request\.headers\.get\s*\(",
    r"request\.data\b",
    r"request\.get_json\s*\(",
]

# Django HTTP 参数
_DJANGO_HTTP_PATTERNS = [
    r"request\.GET\.get\s*\(",
    r"request\.GET\[",
    r"request\.POST\.get\s*\(",
    r"request\.POST\[",
    r"request\.META\.get\s*\(",
    r"request\.META\[",
    r"request\.COOKIES\.get\s*\(",
    r"request\.session\.get\s*\(",
]

# FastAPI 专用
_FASTAPI_HTTP_PATTERNS = [
    r"Query\s*\(",
    r"Path\s*\(",
    r"Body\s*\(",
    r"Header\s*\(",
    r"Cookie\s*\(",
]

# Python 文件上传
_PY_FILE_UPLOAD_PATTERNS = [
    r"request\.files\.get\s*\(",
    r"request\.files\[",
    r"request\.FILES\.get\s*\(",
    r"request\.FILES\[",
    r"\.save\s*\(",
]

# Python 敏感信息硬编码
_PY_SENSITIVE_PATTERNS = [
    r"password\s*=\s*['\"][^'\"]{3,}['\"]",
    r"passwd\s*=\s*['\"][^'\"]{3,}['\"]",
    r"secret\s*=\s*['\"][^'\"]{8,}['\"]",
    r"api_key\s*=\s*['\"][^'\"]{8,}['\"]",
    r"apikey\s*=\s*['\"][^'\"]{8,}['\"]",
    r"token\s*=\s*['\"][^'\"]{10,}['\"]",
    r"private_key\s*=\s*['\"]",
    r"DATABASE_URL\s*=\s*['\"]postgresql://[^'\"]+:[^'\"]+@",
]

# ──────────────────────────────────────────────────────
# JavaScript / Node.js Source 规则
# ──────────────────────────────────────────────────────

_JS_HTTP_PATTERNS = [
    r"req\.query\b",
    r"req\.body\b",
    r"req\.params\b",
    r"req\.headers\b",
    r"req\.cookies\b",
    r"req\.get\s*\(",
]

_JS_FILE_UPLOAD_PATTERNS = [
    r"req\.files\b",
    r"req\.file\b",
    r"req\.files\.\w+",
    r"multer\s*\(",
    r"upload\.single\s*\(",
    r"upload\.array\s*\(",
]

_JS_SENSITIVE_PATTERNS = [
    r"password\s*[:=]\s*['\"][^'\"]{3,}['\"]",
    r"secret\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"apiKey\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"token\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    r"MONGODB_URI\s*[:=]\s*['\"]mongodb://[^'\"]+:[^'\"]+@",
]

# ──────────────────────────────────────────────────────
# Java Source 规则
# ──────────────────────────────────────────────────────

_JAVA_HTTP_PATTERNS = [
    r"request\.getParameter\s*\(",
    r"request\.getParameterValues\s*\(",
    r"request\.getHeader\s*\(",
    r"request\.getQueryString\s*\(",
    r"@RequestParam",
    r"@RequestBody",
    r"@RequestHeader",
]

_JAVA_FILE_UPLOAD_PATTERNS = [
    r"MultipartFile",
    r"request\.getPart\s*\(",
    r"CommonsMultipartFile",
    r"@RequestPart",
]

_JAVA_IDOR_PATTERNS = [
    r"@PathVariable",
    r"request\.getPathInfo\s*\(",
]

_JAVA_SENSITIVE_PATTERNS = [
    r'password\s*=\s*"[^"]{3,}"',
    r'secret\s*=\s*"[^"]{8,}"',
    r'apiKey\s*=\s*"[^"]{8,}"',
    r'token\s*=\s*"[^"]{10,}"',
]

# ──────────────────────────────────────────────────────
# 规则集合（按语言分组）
# ──────────────────────────────────────────────────────

SOURCE_RULES: list[SourceRule] = [
    # ── Python / Flask HTTP 参数 ──
    SourceRule(
        rule_id="PY-FLASK-HTTP-01",
        name="Flask HTTP 参数输入",
        language="python",
        framework="flask",
        vuln_type="sql_injection",
        patterns=_PY_HTTP_PATTERNS,
        description="Flask request 对象获取的 HTTP 参数，可能流入 SQL 查询",
    ),
    SourceRule(
        rule_id="PY-FLASK-HTTP-02",
        name="Flask HTTP 参数（命令注入）",
        language="python",
        framework="flask",
        vuln_type="command_injection",
        patterns=_PY_HTTP_PATTERNS,
        description="Flask request 参数流入命令执行函数",
    ),
    # ── Python / Django HTTP 参数 ──
    SourceRule(
        rule_id="PY-DJANGO-HTTP-01",
        name="Django HTTP 参数输入",
        language="python",
        framework="django",
        vuln_type="sql_injection",
        patterns=_DJANGO_HTTP_PATTERNS,
        description="Django request.GET/POST 获取的 HTTP 参数",
    ),
    # ── Python / FastAPI ──
    SourceRule(
        rule_id="PY-FASTAPI-HTTP-01",
        name="FastAPI 参数注入",
        language="python",
        framework="fastapi",
        vuln_type="sql_injection",
        patterns=_FASTAPI_HTTP_PATTERNS + _PY_HTTP_PATTERNS,
        description="FastAPI Query/Path/Body 等依赖注入参数",
    ),
    # ── Python 通用（无框架） ──
    SourceRule(
        rule_id="PY-GENERIC-HTTP-01",
        name="Python 通用 HTTP 参数",
        language="python",
        framework="generic",
        vuln_type="sql_injection",
        patterns=_PY_HTTP_PATTERNS,
        description="通用 Python Web 框架的 HTTP 参数",
    ),
    # ── Python 文件上传 ──
    SourceRule(
        rule_id="PY-FILE-UPLOAD-01",
        name="Python 文件上传输入",
        language="python",
        framework="generic",
        vuln_type="file_upload",
        patterns=_PY_FILE_UPLOAD_PATTERNS,
        description="request.files 获取的上传文件，可能未做类型校验",
    ),
    # ── Python 敏感信息 ──
    SourceRule(
        rule_id="PY-SENSITIVE-01",
        name="Python 硬编码敏感信息",
        language="python",
        framework="generic",
        vuln_type="sensitive_data",
        patterns=_PY_SENSITIVE_PATTERNS,
        description="代码中硬编码的密码、密钥、Token 等敏感信息",
    ),
    # ── JavaScript / Express HTTP 参数 ──
    SourceRule(
        rule_id="JS-EXPRESS-HTTP-01",
        name="Express HTTP 参数输入",
        language="javascript",
        framework="express",
        vuln_type="sql_injection",
        patterns=_JS_HTTP_PATTERNS,
        description="Express req.query/body/params 获取的 HTTP 参数",
    ),
    SourceRule(
        rule_id="JS-EXPRESS-HTTP-02",
        name="Express HTTP 参数（命令注入）",
        language="javascript",
        framework="express",
        vuln_type="command_injection",
        patterns=_JS_HTTP_PATTERNS,
        description="Express req 参数流入命令执行函数",
    ),
    # ── JavaScript / Express IDOR ──
    SourceRule(
        rule_id="JS-EXPRESS-IDOR-01",
        name="Express 路径参数（IDOR）",
        language="javascript",
        framework="express",
        vuln_type="broken_access",
        patterns=[r"req\.params\.\w+"],
        description="Express 路径参数直接用于查询，可能缺少归属校验",
    ),
    # ── JavaScript 文件上传 ──
    SourceRule(
        rule_id="JS-FILE-UPLOAD-01",
        name="Node.js 文件上传输入",
        language="javascript",
        framework="generic",
        vuln_type="file_upload",
        patterns=_JS_FILE_UPLOAD_PATTERNS,
        description="multer 等中间件获取的上传文件",
    ),
    # ── JavaScript 敏感信息 ──
    SourceRule(
        rule_id="JS-SENSITIVE-01",
        name="Node.js 硬编码敏感信息",
        language="javascript",
        framework="generic",
        vuln_type="sensitive_data",
        patterns=_JS_SENSITIVE_PATTERNS,
        description="代码中硬编码的密码、密钥、Token 等",
    ),
    # ── Java / Spring HTTP 参数 ──
    SourceRule(
        rule_id="JAVA-SPRING-HTTP-01",
        name="Spring HTTP 参数输入",
        language="java",
        framework="spring-boot",
        vuln_type="sql_injection",
        patterns=_JAVA_HTTP_PATTERNS,
        description="Spring @RequestParam/@RequestBody 注解参数",
    ),
    # ── Java / Spring IDOR ──
    SourceRule(
        rule_id="JAVA-SPRING-IDOR-01",
        name="Spring 路径参数（IDOR）",
        language="java",
        framework="spring-boot",
        vuln_type="broken_access",
        patterns=_JAVA_IDOR_PATTERNS,
        description="@PathVariable 直接用于查询，可能缺少归属校验",
    ),
    # ── Java 文件上传 ──
    SourceRule(
        rule_id="JAVA-FILE-UPLOAD-01",
        name="Java 文件上传输入",
        language="java",
        framework="generic",
        vuln_type="file_upload",
        patterns=_JAVA_FILE_UPLOAD_PATTERNS,
        description="MultipartFile 等上传文件对象",
    ),
    # ── Java 敏感信息 ──
    SourceRule(
        rule_id="JAVA-SENSITIVE-01",
        name="Java 硬编码敏感信息",
        language="java",
        framework="generic",
        vuln_type="sensitive_data",
        patterns=_JAVA_SENSITIVE_PATTERNS,
        description="代码中硬编码的密码、密钥、Token 等",
    ),
]


def get_source_rules(
    language: str, framework: str = "generic", vuln_type: str | None = None
) -> list[SourceRule]:
    """获取适用于指定语言和框架的 Source 规则。

    优先返回精确匹配 framework 的规则；如果没有，回退到 generic。

    Args:
        language:  语言 (python / javascript / java)
        framework: 框架 (flask / django / fastapi / express / spring-boot / generic)
        vuln_type: 可选，按漏洞类型过滤

    Returns:
        匹配的 SourceRule 列表
    """
    # 先精确匹配 language + framework
    matched = [
        r for r in SOURCE_RULES if r.language == language and r.framework == framework
    ]
    # 如果没有精确匹配，回退到 generic
    if not matched:
        matched = [
            r
            for r in SOURCE_RULES
            if r.language == language and r.framework == "generic"
        ]
    else:
        # 补充 generic 规则（generic 规则总是适用的）
        generic = [
            r
            for r in SOURCE_RULES
            if r.language == language and r.framework == "generic"
        ]
        # 避免重复添加
        existing_ids = {r.rule_id for r in matched}
        for r in generic:
            if r.rule_id not in existing_ids:
                matched.append(r)

    if vuln_type:
        matched = [r for r in matched if r.vuln_type == vuln_type]

    return matched


def find_sources_in_line(
    code_line: str, language: str, framework: str = "generic"
) -> list[SourceRule]:
    """检查一行代码匹配哪些 Source 规则。

    Args:
        code_line: 源码行文本
        language:  语言
        framework: 框架

    Returns:
        匹配的 SourceRule 列表（可能为空）
    """
    rules = get_source_rules(language, framework)
    return [r for r in rules if r.match(code_line)]
