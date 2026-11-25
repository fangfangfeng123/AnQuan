"""依赖清单解析器模块。

本模块负责解析各类语言的依赖清单文件，提取依赖名和版本：
- Python: requirements.txt, pyproject.toml, Pipfile
- Node.js: package.json
- Java: pom.xml (Maven), build.gradle (Gradle)
- Go: go.mod
- PHP: composer.json
- Ruby: Gemfile

所有解析器接收文件内容字符串（从沙箱中 cat 读取），
返回统一格式：{dependency_name: version | None}
"""

import json
import re
from typing import Dict, Optional


def parse_requirements_txt(content: str) -> Dict[str, Optional[str]]:
    """解析 Python requirements.txt。

    支持：
    - package==1.0.0
    - package>=1.0.0,<2.0.0
    - package~=1.0.0
    - package (无版本)
    - 忽略注释(#)和空行
    - 忽略 -r/-e 等特殊行
    """
    deps: Dict[str, Optional[str]] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            continue
        # 去掉行内注释
        if " #" in line:
            line = line.split(" #")[0].strip()
        # 匹配 package==version, package>=version, package~=version 等
        match = re.match(
            r"^([a-zA-Z0-9_.-]+)\s*([=<>~!]=.+|[=<>~].+)?",
            line,
        )
        if match:
            name = match.group(1).strip()
            version = match.group(2)
            if version:
                # 去掉操作符前缀，取第一个版本号
                version = re.sub(r"^[=<>~!]*\s*", "", version.strip())
                # 处理逗号分隔的多版本约束
                if "," in version:
                    version = version.split(",")[0].strip()
            deps[name] = version
    return deps


def parse_pyproject_toml(content: str) -> Dict[str, Optional[str]]:
    """解析 Python pyproject.toml（使用 [project] dependencies 或 poetry）。"""
    deps: Dict[str, Optional[str]] = {}
    # 尝试解析为标准 TOML（Python 3.11+ 有 tomllib）
    try:
        import tomllib
    except ImportError:
        # 没有 tomllib，用正则兜底
        return _parse_toml_regex(content)

    try:
        data = tomllib.loads(content)
    except Exception:
        return _parse_toml_regex(content)

    # [project] dependencies (PEP 621)
    project_deps = data.get("project", {}).get("dependencies", [])
    for dep_str in project_deps:
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>~!]*.+)?", dep_str.strip())
        if match:
            name = match.group(1)
            version = match.group(2)
            if version:
                version = re.sub(r"^[=<>~!]*\s*", "", version.strip())
                if "," in version:
                    version = version.split(",")[0].strip()
            deps[name] = version

    # Poetry [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, ver in poetry_deps.items():
        if name.lower() == "python":
            continue
        if isinstance(ver, str):
            deps[name] = ver
        elif isinstance(ver, dict):
            deps[name] = ver.get("version")

    return deps


def _parse_toml_regex(content: str) -> Dict[str, Optional[str]]:
    """正则兜底解析 pyproject.toml。"""
    deps: Dict[str, Optional[str]] = {}
    # 匹配 dependencies = ["package==1.0.0", ...]
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if "dependencies" in stripped and "=" in stripped:
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("]") or stripped == "":
                in_deps = False
                continue
            match = re.match(r'^"([^"]+)"', stripped)
            if match:
                dep_str = match.group(1)
                m2 = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>~!]*.+)?", dep_str)
                if m2:
                    name = m2.group(1)
                    version = m2.group(2)
                    if version:
                        version = re.sub(r"^[=<>~!]*\s*", "", version.strip())
                    deps[name] = version
    return deps


def parse_package_json(content: str) -> Dict[str, Optional[str]]:
    """解析 Node.js package.json。"""
    deps: Dict[str, Optional[str]] = {}
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    for section in ("dependencies", "devDependencies"):
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            for name, version in section_deps.items():
                # npm 版本可能带 ^ ~ 前缀
                clean_ver = version
                if isinstance(version, str):
                    clean_ver = re.sub(r"^[\^~>=]*", "", version)
                deps[name] = clean_ver
    return deps


def parse_pom_xml(content: str) -> Dict[str, Optional[str]]:
    """解析 Java Maven pom.xml 中的 <dependencies>。"""
    deps: Dict[str, Optional[str]] = {}
    # 匹配 <dependency> 块
    pattern = re.compile(
        r"<dependency>\s*"
        r"<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*"
        r"(?:<version>([^<]*)</version>)?",
        re.DOTALL,
    )
    for match in pattern.finditer(content):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = match.group(3)
        # 用 groupId:artifactId 作为 key
        key = f"{group_id}:{artifact_id}"
        deps[key] = version.strip() if version else None
    return deps


def parse_build_gradle(content: str) -> Dict[str, Optional[str]]:
    """解析 Java Gradle build.gradle。"""
    deps: Dict[str, Optional[str]] = {}
    # 匹配 implementation 'group:artifact:version'
    # 匹配 compile 'group:artifact:version'
    # 匹配 implementation "group:artifact:version"
    pattern = re.compile(
        r"(?:implementation|compile|api|testImplementation)\s+"
        r'["\']([^"\']+):([^"\']+):([^"\']+)["\']',
    )
    for match in pattern.finditer(content):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = match.group(3).strip()
        key = f"{group_id}:{artifact_id}"
        deps[key] = version
    return deps


def parse_go_mod(content: str) -> Dict[str, Optional[str]]:
    """解析 Go go.mod。"""
    deps: Dict[str, Optional[str]] = {}
    in_require_block = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "require (":
            in_require_block = True
            continue
        if in_require_block:
            if stripped == ")":
                in_require_block = False
                continue
        # 匹配 require github.com/foo/bar v1.0.0
        match = re.match(r"(?:require\s+)?([^\s]+)\s+(v[^\s]+)", stripped)
        if match:
            deps[match.group(1)] = match.group(2)
        # 也匹配单行 require
        elif stripped.startswith("require "):
            parts = stripped.replace("require ", "").split()
            if len(parts) >= 2:
                deps[parts[0]] = parts[1]
    return deps


def parse_composer_json(content: str) -> Dict[str, Optional[str]]:
    """解析 PHP composer.json。"""
    deps: Dict[str, Optional[str]] = {}
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    for section in ("require", "require-dev"):
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            for name, version in section_deps.items():
                # 忽略 php 版本要求
                if name == "php":
                    continue
                deps[name] = version if isinstance(version, str) else None
    return deps


def parse_gemfile(content: str) -> Dict[str, Optional[str]]:
    """解析 Ruby Gemfile。"""
    deps: Dict[str, Optional[str]] = {}
    # gem "rails", "6.0.0"
    # gem "rails", "~> 6.0"
    # gem "nokogiri"
    pattern = re.compile(r'gem\s+["\']([^"\']+)["\'](?:\s*,\s*["\']([^"\']+)["\'])?')
    for match in pattern.finditer(content):
        name = match.group(1)
        version = match.group(2)
        if version:
            # 去掉 ~ > 等前缀
            version = re.sub(r"^[~><=]*\s*", "", version)
        deps[name] = version
    return deps


# ── 统一入口 ──

# 依赖清单文件名 -> 解析函数映射
PARSERS: dict = {
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "Pipfile": parse_requirements_txt,  # 简化处理
    "package.json": parse_package_json,
    "pom.xml": parse_pom_xml,
    "build.gradle": parse_build_gradle,
    "go.mod": parse_go_mod,
    "composer.json": parse_composer_json,
    "Gemfile": parse_gemfile,
}


def parse_manifest(filename: str, content: str) -> Dict[str, Optional[str]]:
    """根据文件名选择对应解析器，解析依赖清单。

    Args:
        filename: 依赖清单文件名（如 requirements.txt, package.json）
        content: 文件内容字符串

    Returns:
        依赖字典 {dependency_name: version | None}
        未识别的文件返回空字典
    """
    parser = PARSERS.get(filename)
    if parser is None:
        # 尝试去掉路径前缀再匹配
        basename = filename.split("/")[-1].split("\\")[-1]
        parser = PARSERS.get(basename)
    if parser is None:
        return {}
    try:
        return parser(content)
    except Exception:
        return {}


def detect_manifest_files(file_listing: str) -> list[str]:
    """从沙箱 ls 输出中检测存在的依赖清单文件。

    Args:
        file_listing: ls /workspace/source 的输出

    Returns:
        找到的依赖清单文件名列表
    """
    found = []
    for name in PARSERS:
        if name in file_listing:
            found.append(name)
    return found
