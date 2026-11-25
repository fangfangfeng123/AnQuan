"""路由/接口扫描器模块。

本模块负责从源码内容中识别 HTTP 路由和 API 接口，
支持多种语言和框架的路由声明方式：

- Python Flask:    @app.route("/path"), @app.get("/path")
- Python FastAPI:  @router.get("/path"), @app.post("/path")
- Python Django:   path("url/", view), re_path, urlpatterns
- Node Express:    app.get("/path", ...), router.post("/path", ...)
- Node Koa:       router.get("/path", ...), app.use(...)
- Java Spring:     @GetMapping("/path"), @RequestMapping("/path")
- Go Gin:          r.GET("/path", ...), r.POST("/path", ...)
- Go Echo:         e.GET("/path", ...)
- PHP Laravel:     Route::get("/path", ...), Route::post(...)
- PHP Slim:        $app->get("/path", ...)
- Ruby Rails:      get "/path" => "controller#action"
- Ruby Sinatra:    get "/path" do

每个识别到的路由返回统一格式：
{
    "method": "GET|POST|PUT|DELETE|PATCH|...",
    "path": "/api/users",
    "file": "app.py",
    "line": 15,
    "handler": "get_users"  # 函数名或处理器名（可选）
}
"""

import re
from typing import Dict, List, Optional


# ── 统一路由结果结构 ──


def _make_route(
    method: str,
    path: str,
    file: str = "",
    line: Optional[int] = None,
    handler: Optional[str] = None,
) -> Dict:
    """构造统一路由字典。"""
    return {
        "method": method.upper(),
        "path": path,
        "file": file,
        "line": line,
        "handler": handler,
    }


def _find_line_number(
    content: str, pattern_str: str, start_pos: int = 0
) -> Optional[int]:
    """根据匹配位置推算行号。"""
    if start_pos < 0:
        return None
    line_num = content[:start_pos].count("\n") + 1
    return line_num


# ── Python 路由扫描 ──


def scan_python_routes(content: str, filename: str = "") -> List[Dict]:
    """扫描 Python 源码中的路由声明。

    支持：
    - Flask: @app.route("/path", methods=["GET"])
    - Flask: @app.get("/path"), @app.post("/path")
    - FastAPI: @router.get("/path"), @app.post("/path")
    - Blueprint: @bp.route("/path"), @api.route("/path")
    - Django: path("url/", view_name)
    """
    routes: List[Dict] = []
    seen = set()  # 去重

    # 1. @xxx.route("/path", methods=["GET", "POST"])
    pattern1 = re.compile(
        r"@(?:\w+)\s*\.\s*route\s*\(\s*"
        r'["\']([^"\']+)["\']'
        r"(?:.*?methods\s*=\s*\[([^\]]*)\])?",
        re.DOTALL,
    )
    for m in pattern1.finditer(content):
        path = m.group(1)
        methods_str = m.group(2) or ""
        if methods_str:
            # 提取 methods 列表中的方法名
            methods = re.findall(r'["\'](\w+)["\']', methods_str)
        else:
            methods = ["GET"]  # Flask .route() 默认 GET
        line = _find_line_number(content, m.group(0), m.start())
        for method in methods:
            key = (method.upper(), path)
            if key not in seen:
                seen.add(key)
                routes.append(_make_route(method, path, filename, line))

    # 2. @app.get("/path"), @router.post("/path"), @app.put("/path") 等
    #    支持 @app.get, @router.get, @api.get, @blueprint.get 等
    pattern2 = re.compile(
        r"@(?:\w+)\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*"
        r'["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in pattern2.finditer(content):
        method = m.group(1)
        path = m.group(2)
        key = (method.upper(), path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, path, filename, line))

    # 3. Django path("url/", view) 在 urlpatterns 中
    pattern3 = re.compile(
        r"(?:path|re_path)\s*\(\s*"
        r'["\']([^"\']+)["\']\s*,\s*'
        r"(\w+)",
    )
    for m in pattern3.finditer(content):
        path = m.group(1)
        handler = m.group(2)
        key = ("GET", path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route("GET", path, filename, line, handler))

    # 4. 提取函数名作为 handler（def xxx 紧跟在路由装饰器后面）
    for route in routes:
        if route["line"]:
            lines = content.split("\n")
            idx = route["line"]  # 1-indexed
            # 向后搜索最多 5 行找 def
            for i in range(idx, min(idx + 5, len(lines))):
                def_match = re.match(r"\s*(?:async\s+)?def\s+(\w+)", lines[i])
                if def_match:
                    route["handler"] = def_match.group(1)
                    break

    return routes


# ── Node.js 路由扫描 ──


def scan_node_routes(content: str, filename: str = "") -> List[Dict]:
    """扫描 Node.js 源码中的路由声明。

    支持：
    - Express: app.get("/path", handler), router.post("/path", handler)
    - Koa:     router.get("/path", handler)
    - Fastify: fastify.get("/path", handler)
    - 通用:    xxx.method("/path", ...)
    """
    routes: List[Dict] = []
    seen = set()

    # app.get("/path", ...), router.post("/path", ...), server.put("/path", ...)
    pattern = re.compile(
        r"(?:app|router|server|fastify|app\s*\.\s*use)\s*\.\s*"
        r"(get|post|put|delete|patch|head|options|use)\s*\(\s*"
        r'["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in pattern.finditer(content):
        method = m.group(1)
        path = m.group(2)
        if method.lower() == "use":
            method = "MIDDLEWARE"
        key = (method.upper(), path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, path, filename, line))

    # NestJS: @Controller("/api") + @Get("/users")
    controller_pattern = re.compile(r'@Controller\s*\(\s*["\']([^"\']+)["\']\s*\)')
    ctrl_match = controller_pattern.search(content)
    ctrl_prefix = ctrl_match.group(1) if ctrl_match else ""

    method_pattern = re.compile(
        r"@(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*"
        r'["\']?([^"\')]*)["\']?\s*\)',
    )
    for m in method_pattern.finditer(content):
        method = m.group(1).upper()
        path = m.group(2) or ""
        full_path = (ctrl_prefix + "/" + path).rstrip("/") if ctrl_prefix else path
        if not full_path.startswith("/"):
            full_path = "/" + full_path
        key = (method, full_path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, full_path, filename, line))

    return routes


# ── Java 路由扫描 ──


def scan_java_routes(content: str, filename: str = "") -> List[Dict]:
    """扫描 Java Spring 源码中的路由声明。

    支持：
    - @RequestMapping(value="/path", method=RequestMethod.GET)
    - @GetMapping("/path")
    - @PostMapping("/path")
    - @PutMapping, @DeleteMapping, @PatchMapping
    - @RestController 类级别 @RequestMapping
    """
    routes: List[Dict] = []
    seen = set()

    # 1. 类级别 @RequestMapping("/api") 作为前缀
    class_mapping = re.search(
        r"@(?:RestController|Controller)\b.*?"
        r'(@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\'])',
        content,
        re.DOTALL,
    )
    class_prefix = ""
    class_mapping_span = (
        None  # 记录类级别 @RequestMapping 的位置范围，避免被方法级 pattern 重复匹配
    )
    if class_mapping:
        class_prefix = class_mapping.group(2)
        class_mapping_span = class_mapping.span(
            1
        )  # group(1) 是 @RequestMapping(...) 整段

    # 2. 方法级别 @GetMapping("/path"), @PostMapping("/path") 等
    shortcut_pattern = re.compile(
        r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)"
        r'\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']\s*\)',
    )
    for m in shortcut_pattern.finditer(content):
        method_map = {
            "GetMapping": "GET",
            "PostMapping": "POST",
            "PutMapping": "PUT",
            "DeleteMapping": "DELETE",
            "PatchMapping": "PATCH",
        }
        method = method_map.get(m.group(1), m.group(1).upper())
        path = m.group(2)
        full_path = (class_prefix + path) if class_prefix else path
        key = (method, full_path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, full_path, filename, line))

    # 3. 方法级别 @RequestMapping(value="/path", method=RequestMethod.GET)
    #    用 [^@] 限制不跨越其他注解，避免类级别匹配贪吃后续方法级注解
    full_pattern = re.compile(
        r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']'
        r"(?:[^@]*?method\s*=\s*RequestMethod\.(\w+))?",
    )
    for m in full_pattern.finditer(content):
        # 跳过类级别 @RequestMapping（起始位置在类级别匹配范围内）
        if (
            class_mapping_span
            and class_mapping_span[0] <= m.start() < class_mapping_span[1]
        ):
            continue
        path = m.group(1)
        method = m.group(2) or "GET"
        full_path = (class_prefix + path) if class_prefix else path
        key = (method.upper(), full_path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, full_path, filename, line))

    return routes


# ── Go 路由扫描 ──


def scan_go_routes(content: str, filename: str = "") -> List[Dict]:
    """扫描 Go 源码中的路由声明。

    支持：
    - Gin:    r.GET("/path", handler), r.POST("/path", handler)
    - Echo:   e.GET("/path", handler)
    - Fiber:  app.Get("/path", handler)
    - 标准库:  http.HandleFunc("/path", handler)
    """
    routes: List[Dict] = []
    seen = set()

    # r.GET("/path", ...), e.POST("/path", ...)
    pattern = re.compile(
        r"\b\w+\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HandleFunc|Handle)\s*\(\s*"
        r'["\']([^"\']+)["\']',
    )
    for m in pattern.finditer(content):
        method = m.group(1)
        path = m.group(2)
        if method in ("HandleFunc", "Handle"):
            method = "GET"  # 默认
        key = (method, path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, path, filename, line))

    # router.HandleFunc("GET", "/path", handler)
    pattern2 = re.compile(
        r"\b\w+\.HandleFunc\s*\(\s*"
        r'["\'](\w+)["\']\s*,\s*'
        r'["\']([^"\']+)["\']',
    )
    for m in pattern2.finditer(content):
        method = m.group(1)
        path = m.group(2)
        key = (method.upper(), path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, path, filename, line))

    return routes


# ── PHP 路由扫描 ──


def scan_php_routes(content: str, filename: str = "") -> List[Dict]:
    """扫描 PHP 源码中的路由声明。

    支持：
    - Laravel: Route::get("/path", ...), Route::post("/path", ...)
    - Slim:    $app->get("/path", ...), $app->post("/path", ...)
    - 通用:    $router->get("/path", ...)
    """
    routes: List[Dict] = []
    seen = set()

    # Route::get("/path", ...), Route::post("/path", ...)
    pattern1 = re.compile(
        r"Route::\s*(get|post|put|delete|patch|any|match)\s*\(\s*"
        r'["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in pattern1.finditer(content):
        method = m.group(1)
        path = m.group(2)
        if method.lower() == "any" or method.lower() == "match":
            method = "ANY"
        key = (method.upper(), path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, path, filename, line))

    # $app->get("/path", ...), $router->post("/path", ...)
    pattern2 = re.compile(
        r"\$\w+\s*->\s*(get|post|put|delete|patch)\s*\(\s*"
        r'["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in pattern2.finditer(content):
        method = m.group(1)
        path = m.group(2)
        key = (method.upper(), path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, path, filename, line))

    return routes


# ── Ruby 路由扫描 ──


def scan_ruby_routes(content: str, filename: str = "") -> List[Dict]:
    """扫描 Ruby 源码中的路由声明。

    支持：
    - Rails:  get "/path" => "controller#action"
    - Rails:  post "/path" => "controller#action"
    - Rails:  resources :users
    - Sinatra: get "/path" do
    - Sinatra: post "/path" do
    """
    routes: List[Dict] = []
    seen = set()

    # get "/path" => "controller#action"
    # post "/path" => "controller#action"
    pattern1 = re.compile(
        r"\b(get|post|put|delete|patch)\s+"
        r'["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in pattern1.finditer(content):
        method = m.group(1)
        path = m.group(2)
        key = (method.upper(), path)
        if key not in seen:
            seen.add(key)
            line = _find_line_number(content, m.group(0), m.start())
            routes.append(_make_route(method, path, filename, line))

    # resources :users -> 生成标准 REST 路由
    pattern2 = re.compile(r"\bresources\s+:(\w+)")
    for m in pattern2.finditer(content):
        resource = m.group(1)
        base = "/" + resource
        rest_routes = [
            ("GET", base),
            ("GET", base + "/:id"),
            ("POST", base),
            ("PUT", base + "/:id"),
            ("DELETE", base + "/:id"),
        ]
        for method, path in rest_routes:
            key = (method, path)
            if key not in seen:
                seen.add(key)
                line = _find_line_number(content, m.group(0), m.start())
                routes.append(_make_route(method, path, filename, line))

    return routes


# ── 统一入口 ──

# 语言 -> 路由扫描函数映射
ROUTE_SCANNERS = {
    "python": scan_python_routes,
    "javascript": scan_node_routes,
    "java": scan_java_routes,
    "go": scan_go_routes,
    "php": scan_php_routes,
    "ruby": scan_ruby_routes,
}


def scan_routes(
    language: str,
    content: str,
    filename: str = "",
) -> List[Dict]:
    """根据语言选择对应路由扫描器，从源码内容中识别路由。

    Args:
        language: 主语言（python/javascript/java/go/php/ruby）
        content: 源码文件内容
        filename: 源码文件名（用于路由记录中的 file 字段）

    Returns:
        路由列表 [{"method": "GET", "path": "/api/users", "file": "app.py", "line": 15, "handler": "get_users"}]
        未识别的语言返回空列表
    """
    scanner = ROUTE_SCANNERS.get(language)
    if scanner is None:
        return []
    try:
        return scanner(content, filename)
    except Exception:
        return []


def scan_routes_from_files(
    language: str,
    files: Dict[str, str],
) -> List[Dict]:
    """批量扫描多个文件的路由。

    Args:
        language: 主语言
        files: {filename: content} 字典

    Returns:
        合并后的路由列表
    """
    all_routes: List[Dict] = []
    for filename, content in files.items():
        routes = scan_routes(language, content, filename)
        all_routes.extend(routes)
    return all_routes


def summarize_routes(routes: List[Dict]) -> Dict:
    """对路由列表做汇总统计。

    Args:
        routes: 路由列表

    Returns:
        {"total": 10, "by_method": {"GET": 5, "POST": 3, ...}, "by_path_prefix": {"/api": 5, ...}}
    """
    by_method: Dict[str, int] = {}
    by_prefix: Dict[str, int] = {}

    for route in routes:
        method = route.get("method", "UNKNOWN")
        by_method[method] = by_method.get(method, 0) + 1

        path = route.get("path", "")
        # 取第一级路径前缀
        parts = path.split("/")
        if len(parts) >= 2 and parts[1]:
            prefix = "/" + parts[1]
            by_prefix[prefix] = by_prefix.get(prefix, 0) + 1

    return {
        "total": len(routes),
        "by_method": by_method,
        "by_path_prefix": by_prefix,
    }
