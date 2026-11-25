"""技术栈识别器模块。

本模块负责根据沙箱内扫描的文件列表、文件内容和目录结构，
识别项目的主语言、主框架、入口文件、服务端口和数据库类型。

识别流程：
1. 根据依赖清单文件确定主语言
2. 根据依赖列表和文件结构确定主框架
3. 根据项目结构 + 框架约定识别入口文件
4. 根据入口代码内容识别服务端口
5. 根据配置文件和代码模式识别数据库类型
"""

import re
from typing import Dict, List, Optional


# ── 语言识别：依赖清单文件 -> 语言 ──

MANIFEST_TO_LANGUAGE: Dict[str, str] = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "Pipfile": "python",
    "package.json": "javascript",
    "pom.xml": "java",
    "build.gradle": "java",
    "go.mod": "go",
    "composer.json": "php",
    "Gemfile": "ruby",
}

# ── 框架识别：依赖名/关键字符串 -> 框架 ──

PYTHON_FRAMEWORK_PATTERNS: List[Dict[str, str]] = [
    {"dep": "flask", "framework": "flask"},
    {"dep": "fastapi", "framework": "fastapi"},
    {"dep": "django", "framework": "django"},
    {"dep": "tornado", "framework": "tornado"},
    {"dep": "bottle", "framework": "bottle"},
    {"dep": "aiohttp", "framework": "aiohttp"},
    {"dep": "sanic", "framework": "sanic"},
]

NODE_FRAMEWORK_PATTERNS: List[Dict[str, str]] = [
    {"dep": "express", "framework": "express"},
    {"dep": "koa", "framework": "koa"},
    {"dep": "fastify", "framework": "fastify"},
    {"dep": "nest", "framework": "nestjs"},
    {"dep": "@nestjs/core", "framework": "nestjs"},
    {"dep": "next", "framework": "next.js"},
    {"dep": "nuxt", "framework": "nuxt.js"},
]

JAVA_FRAMEWORK_PATTERNS: List[Dict[str, str]] = [
    {"dep": "spring-boot", "framework": "spring-boot"},
    {"dep": "springframework", "framework": "spring"},
    {"dep": "quarkus", "framework": "quarkus"},
    {"dep": "micronaut", "framework": "micronaut"},
]

GO_FRAMEWORK_PATTERNS: List[Dict[str, str]] = [
    {"dep": "github.com/gin-gonic/gin", "framework": "gin"},
    {"dep": "github.com/labstack/echo", "framework": "echo"},
    {"dep": "github.com/gofiber/fiber", "framework": "fiber"},
]

PHP_FRAMEWORK_PATTERNS: List[Dict[str, str]] = [
    {"dep": "laravel/framework", "framework": "laravel"},
    {"dep": "symfony/symfony", "framework": "symfony"},
    {"dep": "yiisoft/yii2", "framework": "yii2"},
    {"dep": "codeigniter", "framework": "codeigniter"},
]

RUBY_FRAMEWORK_PATTERNS: List[Dict[str, str]] = [
    {"dep": "rails", "framework": "rails"},
    {"dep": "sinatra", "framework": "sinatra"},
]


# ── 入口文件识别：框架 -> 候选入口文件 ──

ENTRY_FILE_PATTERNS: Dict[str, List[str]] = {
    "flask": ["app.py", "main.py", "wsgi.py", "application.py", "run.py"],
    "fastapi": ["main.py", "app.py", "asgi.py"],
    "django": ["manage.py", "wsgi.py", "asgi.py"],
    "tornado": ["main.py", "server.py", "app.py"],
    "bottle": ["app.py", "main.py", "server.py"],
    "aiohttp": ["main.py", "app.py", "server.py"],
    "sanic": ["main.py", "server.py", "app.py"],
    "express": ["index.js", "app.js", "server.js", "main.js"],
    "koa": ["index.js", "app.js", "server.js"],
    "fastify": ["index.js", "app.js", "server.js"],
    "nestjs": ["main.ts", "main.js", "app.module.ts"],
    "next.js": ["pages/index.tsx", "pages/index.js", "app/page.tsx"],
    "spring-boot": ["src/main/java"],
    "spring": ["src/main/java"],
    "gin": ["main.go"],
    "echo": ["main.go"],
    "laravel": ["public/index.php", "artisan"],
    "symfony": ["public/index.php", "src/Kernel.php"],
    "rails": ["config/routes.rb", "config.ru"],
    "sinatra": ["app.rb", "server.rb", "config.ru"],
}


# ── 端口识别：框架 -> 默认端口 ──

FRAMEWORK_DEFAULT_PORTS: Dict[str, List[Dict]] = {
    "flask": [{"port": 5000, "protocol": "http", "description": "Flask 默认端口"}],
    "fastapi": [{"port": 8000, "protocol": "http", "description": "FastAPI 默认端口"}],
    "django": [{"port": 8000, "protocol": "http", "description": "Django 默认端口"}],
    "tornado": [{"port": 8888, "protocol": "http", "description": "Tornado 默认端口"}],
    "express": [{"port": 3000, "protocol": "http", "description": "Express 默认端口"}],
    "koa": [{"port": 3000, "protocol": "http", "description": "Koa 默认端口"}],
    "fastify": [{"port": 3000, "protocol": "http", "description": "Fastify 默认端口"}],
    "nestjs": [{"port": 3000, "protocol": "http", "description": "NestJS 默认端口"}],
    "spring-boot": [
        {"port": 8080, "protocol": "http", "description": "Spring Boot 默认端口"}
    ],
    "gin": [{"port": 8080, "protocol": "http", "description": "Gin 默认端口"}],
    "laravel": [{"port": 8000, "protocol": "http", "description": "Laravel 默认端口"}],
    "rails": [{"port": 3000, "protocol": "http", "description": "Rails 默认端口"}],
    "sinatra": [{"port": 4567, "protocol": "http", "description": "Sinatra 默认端口"}],
}


# ── 数据库识别模式 ──

DB_PATTERNS: List[Dict] = [
    {"pattern": r"postgresql://", "db_type": "postgresql"},
    {"pattern": r"postgres://", "db_type": "postgresql"},
    {"pattern": r"psycopg2", "db_type": "postgresql"},
    {"pattern": r"asyncpg", "db_type": "postgresql"},
    {"pattern": r"sqlalchemy.*postgres", "db_type": "postgresql"},
    {"pattern": r"DATABASE_URL.*postgres", "db_type": "postgresql"},
    {"pattern": r"mysql://", "db_type": "mysql"},
    {"pattern": r"pymysql", "db_type": "mysql"},
    {"pattern": r"mysql-connector", "db_type": "mysql"},
    {"pattern": r"MySQLdb", "db_type": "mysql"},
    {"pattern": r"sqlite://", "db_type": "sqlite"},
    {"pattern": r"sqlite3\.connect", "db_type": "sqlite"},
    {"pattern": r"mongodb://", "db_type": "mongodb"},
    {"pattern": r"pymongo", "db_type": "mongodb"},
    {"pattern": r"redis://", "db_type": "redis"},
    {"pattern": r"redis\.Redis", "db_type": "redis"},
    {"pattern": r"aioredis", "db_type": "redis"},
    {"pattern": r"<dependency>.*mysql", "db_type": "mysql"},
    {"pattern": r"<dependency>.*postgresql", "db_type": "postgresql"},
    {"pattern": r"<dependency>.*mongo", "db_type": "mongodb"},
    {"pattern": r"spring.datasource.url.*mysql", "db_type": "mysql"},
    {"pattern": r"spring.datasource.url.*postgres", "db_type": "postgresql"},
]


def detect_language(
    manifest_files: List[str],
    file_type_dist: str = "",
) -> str:
    """根据依赖清单文件和文件类型分布识别主语言。

    Args:
        manifest_files: 找到的依赖清单文件名列表
        file_type_dist: 文件类型分布字符串（find ... | uniq -c 输出）

    Returns:
        主语言字符串（python/javascript/java/go/php/ruby/unknown）
    """
    # 优先根据依赖清单
    for fname in manifest_files:
        lang = MANIFEST_TO_LANGUAGE.get(fname)
        if lang:
            return lang

    # 其次根据文件类型分布
    if file_type_dist:
        if ".py" in file_type_dist:
            return "python"
        if ".js" in file_type_dist or ".ts" in file_type_dist:
            return "javascript"
        if ".java" in file_type_dist:
            return "java"
        if ".go" in file_type_dist:
            return "go"
        if ".php" in file_type_dist:
            return "php"
        if ".rb" in file_type_dist:
            return "ruby"

    return "unknown"


def detect_framework(
    language: str,
    dependencies: Dict[str, Optional[str]],
) -> str:
    """根据语言和依赖列表识别主框架。

    Args:
        language: 主语言
        dependencies: 依赖字典 {name: version}

    Returns:
        框架名（flask/fastapi/django/express/spring-boot/gin 等，unknown 如果未识别）
    """
    dep_names = set(dependencies.keys())
    dep_names_lower = {d.lower() for d in dep_names}

    patterns_map: Dict[str, List[Dict[str, str]]] = {
        "python": PYTHON_FRAMEWORK_PATTERNS,
        "javascript": NODE_FRAMEWORK_PATTERNS,
        "java": JAVA_FRAMEWORK_PATTERNS,
        "go": GO_FRAMEWORK_PATTERNS,
        "php": PHP_FRAMEWORK_PATTERNS,
        "ruby": RUBY_FRAMEWORK_PATTERNS,
    }

    patterns = patterns_map.get(language, [])
    for p in patterns:
        dep_key = p["dep"].lower()
        # 精确匹配或包含匹配
        if dep_key in dep_names_lower:
            return p["framework"]
        # 部分 Maven 依赖是 groupId:artifactId 格式
        for name in dep_names:
            if dep_key in name.lower():
                return p["framework"]

    return "unknown"


def detect_entry_points(
    language: str,
    framework: str,
    file_listing: str,
) -> List[Dict]:
    """根据框架和目录结构识别入口文件。

    Args:
        language: 主语言
        framework: 主框架
        file_listing: ls/find 输出（文件列表）

    Returns:
        入口文件列表 [{"file": "app.py", "type": "wsgi_app"}, ...]
    """
    entry_candidates = ENTRY_FILE_PATTERNS.get(framework, [])
    if not entry_candidates:
        # 通用入口文件检测
        if language == "python":
            entry_candidates = ["app.py", "main.py", "run.py"]
        elif language == "javascript":
            entry_candidates = ["index.js", "app.js", "server.js"]
        elif language == "go":
            entry_candidates = ["main.go"]
        elif language == "java":
            entry_candidates = ["src/main/java"]
        elif language == "php":
            entry_candidates = ["index.php"]
        elif language == "ruby":
            entry_candidates = ["app.rb"]

    found: List[Dict] = []
    lines = [
        line.strip()
        for line in file_listing.splitlines()
        if line.strip()
    ]

    seen_files: set[str] = set()
    for candidate in entry_candidates:
        for line in lines:
            if "/" in candidate:
                if candidate not in line:
                    continue
            else:
                if line.rsplit("/", 1)[-1] != candidate:
                    continue

            relative_file = line
            if line.startswith("/workspace/source/"):
                relative_file = line[len("/workspace/source/") :]

            if relative_file in seen_files:
                continue
            seen_files.add(relative_file)

            entry_type = "entry"
            if candidate.endswith(".py"):
                entry_type = "python_entry"
            elif candidate.endswith(".js") or candidate.endswith(".ts"):
                entry_type = "js_entry"
            elif candidate.endswith(".go"):
                entry_type = "go_entry"
            elif candidate.endswith(".php"):
                entry_type = "php_entry"
            elif candidate.endswith(".rb"):
                entry_type = "ruby_entry"
            elif "main/java" in candidate:
                entry_type = "java_main"

            found.append(
                {
                    "file": relative_file,
                    "type": entry_type,
                    "line": None,
                }
            )

    return found


def detect_ports(
    framework: str,
    entry_code: str = "",
    config_files: str = "",
) -> List[Dict]:
    """识别服务端口。

    优先从代码和配置中提取显式端口，其次用框架默认端口。

    Args:
        framework: 主框架
        entry_code: 入口文件内容
        config_files: 配置文件内容（.env, settings.py 等）

    Returns:
        端口列表 [{"port": 5000, "protocol": "http", "description": "..."}]
    """
    ports: List[Dict] = []

    # 1. 从代码中提取显式端口
    combined = entry_code + "\n" + config_files
    port_patterns = [
        r"app\.run\s*\([^)]*port\s*=\s*(\d+)",
        r"uvicorn\.run\s*\([^)]*port\s*=\s*(\d+)",
        r"PORT\s*[=:]\s*['\"]?(\d{2,5})",
        r"--port\s+(\d+)",
        r"listen\s*\(\s*(\d+)",
        r"server\.listen\s*\(\s*(\d+)",
        r"\.listen\(\s*(\d+)",
        r"run\s*\(\s*['\"]host['\"].*?(\d{4,5})",
        r"server\.port\s*=\s*(\d+)",
        r"--server\.port=(\d+)",
        r"port:\s*(\d+)",
    ]
    for pattern in port_patterns:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        for port_str in matches:
            port = int(port_str)
            if 1 <= port <= 65535:
                if not any(p["port"] == port for p in ports):
                    ports.append(
                        {
                            "port": port,
                            "protocol": "http",
                            "description": f"从代码中检测到端口 {port}",
                        }
                    )

    # 2. 如果没找到显式端口，用框架默认端口
    if not ports:
        default_ports = FRAMEWORK_DEFAULT_PORTS.get(framework, [])
        ports.extend(default_ports)

    return ports


def detect_db_type(
    source_code_summary: str = "",
    config_files: str = "",
    dependencies: Dict[str, Optional[str]] = "",
) -> str:
    """识别数据库类型。

    Args:
        source_code_summary: 源码摘要（关键文件内容拼接）
        config_files: 配置文件内容
        dependencies: 依赖字典

    Returns:
        数据库类型（postgresql/mysql/sqlite/mongodb/redis/not_detected）
    """
    combined = source_code_summary + "\n" + config_files

    # 也检查依赖列表
    if dependencies:
        dep_str = (
            " ".join(dependencies.keys())
            if isinstance(dependencies, dict)
            else str(dependencies)
        )
        combined += "\n" + dep_str

    for pattern_info in DB_PATTERNS:
        if re.search(pattern_info["pattern"], combined, re.IGNORECASE):
            return pattern_info["db_type"]

    return "not_detected"


def detect_run_command(
    language: str,
    framework: str,
    entry_points: List[Dict],
) -> Optional[str]:
    """根据语言、框架和入口文件推断启动命令。

    Args:
        language: 主语言
        framework: 主框架
        entry_points: 入口文件列表

    Returns:
        启动命令字符串，无法推断时返回 None
    """
    if not entry_points:
        return None

    entry_file = entry_points[0].get("file", "")

    if language == "python":
        if framework == "django":
            return f"python manage.py runserver 0.0.0.0:8000"
        if framework == "flask":
            return f"python {entry_file}"
        if framework == "fastapi":
            return f"uvicorn {entry_file.replace('.py', '')}:app --host 0.0.0.0 --port 8000"
        return f"python {entry_file}"

    if language == "javascript":
        return "npm start"

    if language == "java":
        if framework == "spring-boot":
            return "mvn spring-boot:run"
        return "mvn compile exec:java"

    if language == "go":
        return f"go run {entry_file}"

    if language == "php":
        if framework == "laravel":
            return "php artisan serve"
        return f"php -S 0.0.0.0:8000"

    if language == "ruby":
        if framework == "rails":
            return "rails server"
        return f"ruby {entry_file}"

    return None
