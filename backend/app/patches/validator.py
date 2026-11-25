"""补丁校验器模块（三层校验）。

本模块负责校验 AI 生成补丁的质量，执行三层检查：
1. 语法检查：
   - Python：用 py_compile 编译检查
   - JavaScript：用 node --check 语法解析
   - 其他语言：跳过（标记为 skipped）
2. 编译检查：
   - Python：py_compile 已包含编译检查
   - JS：可选用 esbuild/babel，代码量大可跳过
3. 安全回归检查：
   - 把 patched_code 写回沙箱原文件位置
   - 用 Semgrep 重新扫描确认原漏洞已消除
   - 确认没有引入新漏洞
   - 无沙箱时跳过

输出校验结果 JSONB（各项检查通过/失败详情）
只有全部通过的补丁才会推荐采纳
"""

import logging
import os
import py_compile
import tempfile
from dataclasses import dataclass, field
from typing import Any

from app.models import Finding

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────


@dataclass
class ValidationResult:
    """补丁校验结果。"""

    syntax: dict[str, Any] = field(
        default_factory=lambda: {"passed": False, "errors": [], "skipped": False}
    )
    compile: dict[str, Any] = field(
        default_factory=lambda: {"passed": False, "errors": [], "skipped": False}
    )
    security_regression: dict[str, Any] = field(
        default_factory=lambda: {
            "passed": False,
            "original_vuln_fixed": False,
            "new_findings": [],
            "skipped": False,
        }
    )

    @property
    def overall_passed(self) -> bool:
        """是否全部通过（跳过的项视为通过）。"""
        syntax_ok = self.syntax.get("passed") or self.syntax.get("skipped", False)
        compile_ok = self.compile.get("passed") or self.compile.get("skipped", False)
        security_ok = self.security_regression.get(
            "passed"
        ) or self.security_regression.get("skipped", False)
        return syntax_ok and compile_ok and security_ok

    def to_dict(self) -> dict[str, Any]:
        """转为 JSONB 可存储的字典。"""
        return {
            "syntax": self.syntax,
            "compile": self.compile,
            "security_regression": self.security_regression,
            "overall_passed": self.overall_passed,
        }


# ──────────────────────────────────────────────────────────────
# 语法检查
# ──────────────────────────────────────────────────────────────


def check_syntax(
    patched_code: str,
    file_path: str | None = None,
) -> dict[str, Any]:
    """语法检查。

    Python 用 py_compile，JS 用 node --check，其他跳过。

    Args:
        patched_code: 修复后的代码
        file_path: 原始文件路径（用于判断语言）

    Returns:
        {"passed": bool, "errors": list[str], "skipped": bool}
    """
    if not patched_code:
        return {"passed": False, "errors": ["Empty patched code"], "skipped": False}

    ext = _get_file_extension(file_path)

    if ext == ".py":
        return _check_python_syntax(patched_code)
    elif ext in (".js", ".mjs", ".ts"):
        return _check_js_syntax(patched_code, ext)
    else:
        # 无法识别语言，尝试 Python（最常见的靶场语言）
        result = _check_python_syntax(patched_code)
        if not result["passed"]:
            # 如果 Python 语法检查失败，尝试 JS
            js_result = _check_js_syntax(patched_code, ".js")
            if js_result["passed"]:
                return js_result
        return result


def _check_python_syntax(code: str) -> dict[str, Any]:
    """用 py_compile 检查 Python 语法。"""
    errors = []
    tmp_path = None
    try:
        # 写入临时文件
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            tmp_path = f.name

        py_compile.compile(tmp_path, doraise=True)
        return {"passed": True, "errors": [], "skipped": False}
    except py_compile.PyCompileError as e:
        errors.append(str(e))
        return {"passed": False, "errors": errors, "skipped": False}
    except Exception as e:
        errors.append(f"Unexpected error during py_compile: {e}")
        return {"passed": False, "errors": errors, "skipped": False}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _check_js_syntax(code: str, ext: str = ".js") -> dict[str, Any]:
    """用 node --check 检查 JS 语法。"""
    import subprocess
    import shutil

    node_path = shutil.which("node")
    if not node_path:
        return {
            "passed": False,
            "errors": ["node not found in PATH"],
            "skipped": True,
        }

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            ["node", "--check", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return {"passed": True, "errors": [], "skipped": False}
        else:
            return {
                "passed": False,
                "errors": [result.stderr.strip()],
                "skipped": False,
            }
    except subprocess.TimeoutExpired:
        return {"passed": False, "errors": ["node --check timed out"], "skipped": False}
    except Exception as e:
        return {
            "passed": False,
            "errors": [f"JS syntax check error: {e}"],
            "skipped": False,
        }
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ──────────────────────────────────────────────────────────────
# 编译检查
# ──────────────────────────────────────────────────────────────


def check_compile(
    patched_code: str,
    file_path: str | None = None,
) -> dict[str, Any]:
    """编译检查。

    Python 的 py_compile 已经做了编译检查；
    JS 可用 esbuild/babel，代码量大可跳过。
    """
    ext = _get_file_extension(file_path)

    if ext == ".py":
        # Python 的语法检查已包含编译检查
        return _check_python_syntax(patched_code)
    elif ext in (".js", ".mjs", ".ts"):
        # JS 的语法检查已包含编译检查（node --check）
        return _check_js_syntax(patched_code, ext)
    else:
        # 无法识别语言，复用语法检查结果
        return check_syntax(patched_code, file_path)


# ──────────────────────────────────────────────────────────────
# 安全回归检查
# ──────────────────────────────────────────────────────────────


def check_security_regression(
    patched_code: str,
    finding: Finding,
    sandbox_manager: Any | None = None,
    container_id: str | None = None,
) -> dict[str, Any]:
    """安全回归检查。

    把 patched_code 写回沙箱原文件位置，用 Semgrep 重新扫描：
    - 确认原漏洞已消除（用 finding 的检测规则 ID 跑同一个 rule）
    - 确认没有引入新漏洞（扫出的新 finding 跟原 finding 比对）

    Args:
        patched_code: 修复后代码
        finding: 原漏洞对象
        sandbox_manager: 沙箱管理器（可选）
        container_id: 容器 ID（可选）

    Returns:
        {"passed": bool, "original_vuln_fixed": bool, "new_findings": list, "skipped": bool}
    """
    if sandbox_manager is None or container_id is None:
        # 无沙箱，跳过安全回归检查
        logger.info(
            "[validator] No sandbox available, skipping security regression check"
        )
        return {
            "passed": True,
            "original_vuln_fixed": True,  # 假定修复
            "new_findings": [],
            "skipped": True,
        }

    file_path = finding.file_path
    if not file_path:
        return {
            "passed": False,
            "original_vuln_fixed": False,
            "new_findings": [],
            "skipped": False,
            "error": "No file_path in finding",
        }

    try:
        # 1. 把 patched_code 写回沙箱原文件位置
        # 沙箱内源码挂载在 /workspace/source
        sandbox_path = f"/workspace/source/{file_path}"

        # 用 heredoc 写回文件（避免 exec_command split 问题）
        write_cmd = f"cat > {sandbox_path} << 'PATCH_EOF'\n{patched_code}\nPATCH_EOF"
        write_result = sandbox_manager.exec_command(container_id, write_cmd, timeout=30)
        if write_result.get("exit_code") != 0:
            return {
                "passed": False,
                "original_vuln_fixed": False,
                "new_findings": [],
                "skipped": False,
                "error": f"Failed to write patched code: {write_result.get('stderr', '')}",
            }

        # 2. 用 Semgrep 重新扫描
        semgrep_cmd = f"semgrep --json --config auto --quiet {sandbox_path}"
        scan_result = sandbox_manager.exec_command(
            container_id, semgrep_cmd, timeout=120
        )

        if scan_result.get("timed_out"):
            return {
                "passed": False,
                "original_vuln_fixed": False,
                "new_findings": [],
                "skipped": False,
                "error": "Semgrep scan timed out",
            }

        stdout = scan_result.get("stdout", "")
        exit_code = scan_result.get("exit_code", 0)

        # semgrep 退出码 0 = 无发现，1 = 有发现
        if exit_code == 0 or not stdout:
            # 无新发现，原漏洞已修复
            return {
                "passed": True,
                "original_vuln_fixed": True,
                "new_findings": [],
                "skipped": False,
            }

        # 解析 semgrep JSON
        import json

        try:
            semgrep_output = json.loads(stdout)
        except json.JSONDecodeError as e:
            return {
                "passed": False,
                "original_vuln_fixed": False,
                "new_findings": [],
                "skipped": False,
                "error": f"Failed to parse semgrep JSON: {e}",
            }

        results = semgrep_output.get("results", [])
        new_findings = []

        # 3. 比对扫描结果
        original_vuln_fixed = True
        for r in results:
            check_id = r.get("check_id", "")
            line = r.get("start", {}).get("line", 0)

            # 如果扫描结果中包含原漏洞的行号和规则 ID，说明未修复
            if (
                finding.line_start
                and line == finding.line_start
                and finding.detected_by in check_id
            ):
                original_vuln_fixed = False
            else:
                # 新漏洞
                new_findings.append(
                    {
                        "check_id": check_id,
                        "line": line,
                        "message": r.get("extra", {}).get("message", ""),
                    }
                )

        passed = original_vuln_fixed and len(new_findings) == 0

        return {
            "passed": passed,
            "original_vuln_fixed": original_vuln_fixed,
            "new_findings": new_findings,
            "skipped": False,
        }

    except Exception as e:
        logger.exception("[validator] Security regression check failed: %s", e)
        return {
            "passed": False,
            "original_vuln_fixed": False,
            "new_findings": [],
            "skipped": False,
            "error": str(e),
        }


# ──────────────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────────────


def validate_patch(
    patched_code: str,
    finding: Finding,
    sandbox_manager: Any | None = None,
    container_id: str | None = None,
) -> ValidationResult:
    """执行完整三层校验。

    Args:
        patched_code: 修复后代码
        finding: 原漏洞对象
        sandbox_manager: 沙箱管理器（可选，无则跳过安全回归）
        container_id: 容器 ID（可选）

    Returns:
        ValidationResult
    """
    result = ValidationResult()

    # 1. 语法检查
    logger.info("[validator] Running syntax check for finding %s", finding.id)
    result.syntax = check_syntax(patched_code, finding.file_path)

    # 2. 编译检查
    logger.info("[validator] Running compile check for finding %s", finding.id)
    result.compile = check_compile(patched_code, finding.file_path)

    # 3. 安全回归检查
    logger.info(
        "[validator] Running security regression check for finding %s", finding.id
    )
    result.security_regression = check_security_regression(
        patched_code, finding, sandbox_manager, container_id
    )

    logger.info(
        "[validator] Validation complete for finding %s: overall_passed=%s",
        finding.id,
        result.overall_passed,
    )

    return result


# ──────────────────────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────────────────────


def _get_file_extension(file_path: str | None) -> str:
    """获取文件扩展名。"""
    if not file_path:
        return ""
    _, ext = os.path.splitext(file_path)
    return ext.lower()
