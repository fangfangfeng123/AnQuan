"""patches 模块单元测试。

验证 generator / validator / repository 三层功能：
- generator: 规则兜底生成 SQL注入/命令注入/文件上传/XSS 补丁 + difflib Diff
- validator: Python 语法检查（合法/非法）+ 安全回归跳过
- repository: save_patch / get_patch / update_adopt_status / list
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.patches.generator import (
    PatchGenerationResult,
    generate_diff,
    generate_patch,
    build_prompt,
    _fix_sql_injection,
    _fix_command_injection,
    _fix_file_upload,
    _fix_xss,
    _fix_path_traversal,
    _fix_sensitive_data,
)
from app.patches.validator import (
    ValidationResult,
    validate_patch,
    check_syntax,
    _check_python_syntax,
)
from app.patches.repository import (
    save_patch,
    get_patch,
    get_patch_by_finding,
    update_adopt_status,
    update_validation_result,
    list_patches_by_task,
)
from app.models import FixPatch, Finding
from app.core.database import engine, AsyncSessionLocal, Base
from app.utils import generate_id


# ── Generator 测试 ──


def test_fix_sql_injection_fstring():
    """SQL 注入 f-string 修复。"""
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    patched, desc = _fix_sql_injection(code)
    assert "%s" in patched, f"Expected %s in patched: {patched}"
    assert "parameterized" in desc, f"Expected parameterized in desc: {desc}"
    print("[PASS] test_fix_sql_injection_fstring")


def test_fix_sql_injection_concat():
    """SQL 注入字符串拼接修复。"""
    code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
    patched, desc = _fix_sql_injection(code)
    assert "%s" in patched, f"Expected %s in patched: {patched}"
    print("[PASS] test_fix_sql_injection_concat")


def test_fix_sql_injection_format():
    """SQL 注入 .format() 修复。"""
    code = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))'
    patched, desc = _fix_sql_injection(code)
    assert "%s" in patched, f"Expected %s in patched: {patched}"
    print("[PASS] test_fix_sql_injection_format")


def test_fix_command_injection():
    """命令注入修复。"""
    code = "subprocess.call(user_input, shell=True)"
    patched, desc = _fix_command_injection(code)
    assert "shell=False" in patched, f"Expected shell=False in: {patched}"
    print("[PASS] test_fix_command_injection")


def test_fix_file_upload():
    """文件上传修复：添加扩展名校验。"""
    code = "def upload(f):\n    f.save('uploads/' + f.filename)"
    patched, desc = _fix_file_upload(code)
    assert "ALLOWED_EXTENSIONS" in patched, f"Expected ALLOWED_EXTENSIONS in: {patched}"
    print("[PASS] test_fix_file_upload")


def test_fix_xss():
    """XSS 修复：添加 html.escape。"""
    code = "def render(name):\n    return f'<h1>{name}</h1>'"
    patched, desc = _fix_xss(code)
    assert "html.escape" in patched or "html" in patched, (
        f"Expected html.escape in: {patched}"
    )
    print("[PASS] test_fix_xss")


def test_fix_path_traversal():
    """路径穿越修复：添加 os.path.basename。"""
    code = "f = open(os.path.join(base_dir, user_path))"
    patched, desc = _fix_path_traversal(code)
    assert "basename" in patched, f"Expected basename in: {patched}"
    print("[PASS] test_fix_path_traversal")


def test_fix_sensitive_data():
    """敏感信息泄露修复：移除调试输出。"""
    code = "print(password)"
    patched, desc = _fix_sensitive_data(code)
    assert "SECURITY" in patched or "Removed" in patched, (
        f"Expected removal in: {patched}"
    )
    print("[PASS] test_fix_sensitive_data")


def test_generate_diff():
    """Diff 生成。"""
    original = "line1\nline2\nline3\n"
    patched = "line1\nline2_fixed\nline3\n"
    diff = generate_diff(original, patched, "test.py")
    assert "---" in diff, f"Expected --- in diff: {diff}"
    assert "+++" in diff, f"Expected +++ in diff: {diff}"
    assert "line2_fixed" in diff, f"Expected line2_fixed in diff: {diff}"
    print("[PASS] test_generate_diff")


def test_generate_patch_with_finding():
    """完整补丁生成（规则引擎兜底）。"""
    finding = Finding(
        id=generate_id(),
        task_id=generate_id(),
        vuln_type="sql_injection",
        cwe_id="CWE-89",
        file_path="app.py",
        line_start=42,
        snippet='cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
        sink_code='cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
    )
    result = generate_patch(finding)
    assert isinstance(result, PatchGenerationResult)
    assert result.original_code, "Expected non-empty original_code"
    assert result.patched_code, "Expected non-empty patched_code"
    assert result.diff_content, "Expected non-empty diff_content"
    assert result.llm_model == "rule-engine", (
        f"Expected rule-engine, got: {result.llm_model}"
    )
    assert "%s" in result.patched_code, (
        f"Expected %s in patched code: {result.patched_code}"
    )
    print("[PASS] test_generate_patch_with_finding")


def test_generate_patch_no_code():
    """无代码可用时的补丁生成。"""
    finding = Finding(
        id=generate_id(),
        task_id=generate_id(),
        vuln_type="other",
    )
    result = generate_patch(finding)
    assert result.original_code == "", "Expected empty original_code"
    assert "No vulnerable code" in result.description
    print("[PASS] test_generate_patch_no_code")


def test_build_prompt():
    """Prompt 构造。"""
    finding = Finding(
        id=generate_id(),
        task_id=generate_id(),
        vuln_type="sql_injection",
        cwe_id="CWE-89",
        file_path="app.py",
        line_start=42,
        snippet="cursor.execute(sql)",
    )
    prompt = build_prompt(finding)
    assert "sql_injection" in prompt
    assert "CWE-89" in prompt
    assert "app.py" in prompt
    assert "parameterized" in prompt
    print("[PASS] test_build_prompt")


# ── Validator 测试 ──


def test_check_python_syntax_valid():
    """Python 合法语法检查。"""
    code = "def hello():\n    print('world')\n"
    result = _check_python_syntax(code)
    assert result["passed"] is True, f"Expected passed=True, got: {result}"
    assert result["skipped"] is False
    print("[PASS] test_check_python_syntax_valid")


def test_check_python_syntax_invalid():
    """Python 非法语法检查。"""
    code = "def hello(:\n    print('world'\n"
    result = _check_python_syntax(code)
    assert result["passed"] is False, f"Expected passed=False, got: {result}"
    assert len(result["errors"]) > 0, "Expected error messages"
    print("[PASS] test_check_python_syntax_invalid")


def test_check_syntax_python_file():
    """按文件扩展名判断语言的语法检查。"""
    code = "x = 1\n"
    result = check_syntax(code, "test.py")
    assert result["passed"] is True
    print("[PASS] test_check_syntax_python_file")


def test_validate_patch_no_sandbox():
    """无沙箱时的完整校验（安全回归跳过）。"""
    code = "def safe():\n    return 'safe'\n"
    finding = Finding(
        id=generate_id(),
        task_id=generate_id(),
        vuln_type="sql_injection",
        file_path="app.py",
        line_start=1,
    )
    result = validate_patch(code, finding, sandbox_manager=None, container_id=None)
    assert isinstance(result, ValidationResult)
    assert result.syntax["passed"] is True
    assert result.compile["passed"] is True
    assert result.security_regression["skipped"] is True
    assert result.overall_passed is True
    print("[PASS] test_validate_patch_no_sandbox")


def test_validate_patch_bad_syntax():
    """语法错误的补丁校验。"""
    code = "def bad(:\n"
    finding = Finding(
        id=generate_id(),
        task_id=generate_id(),
        vuln_type="sql_injection",
        file_path="app.py",
        line_start=1,
    )
    result = validate_patch(code, finding)
    assert result.syntax["passed"] is False
    assert result.overall_passed is False
    print("[PASS] test_validate_patch_bad_syntax")


# ── Repository 测试（需要内存数据库） ──


async def test_repository_crud():
    """Repository CRUD 全链路测试。"""
    # 创建内存 SQLite
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    task_id = generate_id()
    finding_id = generate_id()

    # 先插入 Project -> Task -> Finding 记录以满足外键约束
    async with AsyncSessionLocal() as db:
        from app.models import Task, Project

        project_id = generate_id()
        project = Project(
            id=project_id,
            project_name="test-project",
            source_type="upload",
            source_input="/tmp/test.zip",
        )
        task = Task(
            id=task_id,
            project_id=project_id,
            status="running",
        )
        finding = Finding(
            id=finding_id,
            task_id=task_id,
            vuln_type="sql_injection",
            cwe_id="CWE-89",
            status="unverified",
            severity="high",
            file_path="app.py",
            line_start=42,
            snippet="cursor.execute(sql)",
        )
        db.add(project)
        db.add(task)
        db.add(finding)
        await db.commit()
        print(
            f"[INFO] Inserted project={project_id}, task={task_id}, finding={finding_id}"
        )

    async with AsyncSessionLocal() as db:
        # 1. save_patch
        patch = await save_patch(
            db,
            finding_id=finding_id,
            task_id=task_id,
            original_code="print(password)",
            patched_code="# [SECURITY] Removed",
            diff_content="--- a\n+++ b\n-print(password)\n+# [SECURITY] Removed",
            description="Removed sensitive data output",
            llm_model="rule-engine",
            token_usage=0,
        )
        await db.commit()
        assert patch.id, "Expected patch ID"
        assert patch.adopt_status == "pending"
        assert patch.validated == 0
        patch_id = patch.id
        print(f"[PASS] repository.save_patch (id={patch_id})")

    async with AsyncSessionLocal() as db:
        # 2. get_patch
        fetched = await get_patch(db, patch_id)
        assert fetched is not None, "Expected patch"
        assert fetched.finding_id == finding_id
        print("[PASS] repository.get_patch")

    async with AsyncSessionLocal() as db:
        # 3. get_patch_by_finding
        by_finding = await get_patch_by_finding(db, finding_id)
        assert by_finding is not None, "Expected patch by finding"
        assert by_finding.id == patch_id
        print("[PASS] repository.get_patch_by_finding")

    async with AsyncSessionLocal() as db:
        # 4. update_adopt_status
        updated = await update_adopt_status(db, patch_id, "adopted")
        await db.commit()
        assert updated.adopt_status == "adopted"
        print("[PASS] repository.update_adopt_status")

    async with AsyncSessionLocal() as db:
        # 5. update_validation_result
        val_result = {
            "syntax": {"passed": True, "errors": []},
            "compile": {"passed": True, "errors": []},
            "security_regression": {"passed": True, "new_findings": []},
        }
        updated = await update_validation_result(db, patch_id, True, val_result)
        await db.commit()
        assert updated.validated == 1
        assert updated.validation_result["syntax"]["passed"] is True
        print("[PASS] repository.update_validation_result")

    async with AsyncSessionLocal() as db:
        # 6. list_patches_by_task
        patches = await list_patches_by_task(db, task_id)
        assert len(patches) == 1
        assert patches[0].id == patch_id
        print("[PASS] repository.list_patches_by_task")

    # 清理
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def run_sync_tests():
    """运行所有同步测试。"""
    print("\n=== Generator Tests ===")
    test_fix_sql_injection_fstring()
    test_fix_sql_injection_concat()
    test_fix_sql_injection_format()
    test_fix_command_injection()
    test_fix_file_upload()
    test_fix_xss()
    test_fix_path_traversal()
    test_fix_sensitive_data()
    test_generate_diff()
    test_generate_patch_with_finding()
    test_generate_patch_no_code()
    test_build_prompt()

    print("\n=== Validator Tests ===")
    test_check_python_syntax_valid()
    test_check_python_syntax_invalid()
    test_check_syntax_python_file()
    test_validate_patch_no_sandbox()
    test_validate_patch_bad_syntax()


async def run_async_tests():
    """运行异步测试。"""
    print("\n=== Repository Tests ===")
    await test_repository_crud()


if __name__ == "__main__":
    run_sync_tests()
    asyncio.run(run_async_tests())
    print("\n=== ALL TESTS PASSED ===")
