"""平台治理 E2E 集成测试（第10步B）。

测试覆盖：
=== 子模块1: 大盘统计 ===
1. get_dashboard_stats — 聚合查询返回正确计数
2. get_severity_distribution — 严重等级分布
3. get_trend — 趋势数据点数量正确
4. get_recent_tasks — 最近任务 JOIN project
5. API: GET /dashboard/stats — 200 响应
6. API: GET /dashboard/trend?days=7 — 200 响应

=== 子模块2: LLM 配置 ===
7. mask_api_key — 脱敏函数三种场景
8. get_all_configs — 返回3个模式，demo 激活
9. update_config — 更新后返回脱敏 key
10. activate_mode — 切换激活模式
11. test_llm_connection — demo 模式始终成功
12. API: GET /llm/config — 200 脱敏
13. API: PUT /llm/config — admin 更新成功
14. API: PUT /llm/config — developer 403
15. API: POST /llm/config/activate — 切换激活
16. API: POST /llm/test — demo 成功
17. API: GET /llm/modes — 返回模式列表

=== 子模块3: 权限角色 ===
18. require_role — admin token 通过
19. require_role — developer token 403

=== 子模块4: 审计日志增强 ===
20. list_audit_logs filter by task_id
21. list_audit_logs filter by target_id
22. list_audit_logs_by_task 便捷函数
23. API: GET /audit-logs?task_id=... — 新参数可用
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
from httpx import ASGITransport

from app.core.database import AsyncSessionLocal, Base, engine, get_db
from app.core.redis import get_redis
from app.models import AttackChain, AuditLog, Finding, LlmConfig, Project, Task
from app.utils import generate_id

# ──────────────────────────────────────────────────────
# FakeRedis
# ──────────────────────────────────────────────────────


class FakeRedis:
    """简易 Redis mock，捕获 publish 调用。"""

    def __init__(self):
        self.published = []

    async def publish(self, channel: str, message: str):
        self.published.append({"channel": channel, "message": message})

    async def ping(self):
        return True

    async def aclose(self):
        pass

    async def lrange(self, key, start, end):
        return []

    def pubsub(self):
        return FakePubSub()

    async def brpop(self, key, timeout=0):
        return None


class FakePubSub:
    async def subscribe(self, *channels):
        pass

    async def unsubscribe(self, *channels):
        pass

    async def aclose(self):
        pass

    def listen(self):
        return iter([])


# ──────────────────────────────────────────────────────
# 测试辅助：插入完整评估数据
# ──────────────────────────────────────────────────────


async def _setup_test_data(db):
    """插入 Project -> Task -> 2 Findings -> AttackChain -> AuditLog。"""
    project = Project(
        id=generate_id(),
        project_name="Platform Governance Test Project",
        source_type="upload",
        source_input="/tmp/test_pg.zip",
        tech_stack=["Python", "Flask"],
        status="active",
    )
    db.add(project)
    await db.flush()

    task = Task(
        id=generate_id(),
        project_id=project.id,
        status="completed",
        current_phase="report_gen",
        overall_risk="critical",
    )
    db.add(task)
    await db.flush()

    # Finding 1: critical, verified
    f1 = Finding(
        id=generate_id(),
        task_id=task.id,
        vuln_type="sql_injection",
        cwe_id="CWE-89",
        severity="critical",
        cvss_score=9.8,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        file_path="app.py",
        line_start=74,
        line_end=74,
        snippet='cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")',
        sink_code="cursor.execute",
        source_code="order_id = request.args.get('id')",
        detected_by="semgrep",
        confidence=0.95,
        status="verified",
        remediation="Use parameterized queries.",
    )
    db.add(f1)

    # Finding 2: high, verified
    f2 = Finding(
        id=generate_id(),
        task_id=task.id,
        vuln_type="file_upload",
        cwe_id="CWE-434",
        severity="high",
        cvss_score=8.1,
        cvss_vector="AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        file_path="upload.py",
        line_start=30,
        line_end=30,
        snippet="file.save(os.path.join(upload_dir, file.filename))",
        sink_code="file.save",
        source_code="file = request.files['upload']",
        detected_by="semgrep",
        confidence=0.90,
        status="verified",
        remediation="Validate file extensions.",
    )
    db.add(f2)
    await db.flush()

    # AttackChain
    chain = AttackChain(
        id=generate_id(),
        task_id=task.id,
        name="SQL注入 -> 文件上传",
        final_impact="通过SQL注入获取管理员凭证后上传WebShell获得RCE",
        overall_severity="critical",
        overall_cvss=9.9,
        node_count=2,
        edge_count=1,
        is_single_node=False,
    )
    db.add(chain)
    await db.flush()

    # AuditLog entries
    log1 = AuditLog(
        action="create",
        operator="admin",
        task_id=task.id,
        project_id=project.id,
        target_type="task",
        target_id=task.id,
        detail={"message": "Task created"},
    )
    db.add(log1)

    log2 = AuditLog(
        action="config_update",
        operator="admin",
        target_type="llm_config",
        target_id="openai",
        detail={"mode": "openai", "fields": ["api_key"]},
    )
    db.add(log2)

    log3 = AuditLog(
        action="start",
        operator="admin",
        task_id=task.id,
        project_id=project.id,
        target_type="task",
        target_id=task.id,
        detail={"message": "Task started"},
    )
    db.add(log3)

    await db.flush()
    return project, task, f1, f2, chain


async def _cleanup_llm_configs(db):
    """清理 LLM 配置表（避免测试间残留）。"""
    from sqlalchemy import delete

    await db.execute(delete(LlmConfig).where(LlmConfig.config_key.like("llm:%")))
    await db.flush()


# ══════════════════════════════════════════════════════
# 子模块1: 大盘统计
# ══════════════════════════════════════════════════════


async def test_dashboard_stats():
    """get_dashboard_stats 返回正确的聚合计数。"""
    from app.services.dashboard_service import get_dashboard_stats

    async with AsyncSessionLocal() as db:
        await _setup_test_data(db)
        await db.commit()

        stats = await get_dashboard_stats(db)

        assert stats["total_projects"] >= 1, (
            f"Expected >= 1 project, got {stats['total_projects']}"
        )
        assert stats["total_tasks"] >= 1, (
            f"Expected >= 1 task, got {stats['total_tasks']}"
        )
        assert stats["total_findings"] >= 2, (
            f"Expected >= 2 findings, got {stats['total_findings']}"
        )
        assert stats["verified_findings"] >= 2, (
            f"Expected >= 2 verified, got {stats['verified_findings']}"
        )
        assert stats["total_chains"] >= 1, (
            f"Expected >= 1 chain, got {stats['total_chains']}"
        )
        assert stats["max_cvss"] is not None, "max_cvss should not be None"
        assert stats["max_cvss"] >= 9.8, (
            f"Expected max_cvss >= 9.8, got {stats['max_cvss']}"
        )
        assert (
            "critical" in stats["overall_risk_distribution"]
            or stats["overall_risk_distribution"] == {}
        ), f"risk_distribution: {stats['overall_risk_distribution']}"

    print("[PASS] test_dashboard_stats")


async def test_dashboard_severity_distribution():
    """get_severity_distribution 返回正确的严重等级分布。"""
    from app.services.dashboard_service import get_severity_distribution

    async with AsyncSessionLocal() as db:
        await _setup_test_data(db)
        await db.commit()

        dist = await get_severity_distribution(db)

        assert "items" in dist
        assert "total" in dist
        assert dist["total"] >= 2, f"Expected total >= 2, got {dist['total']}"

        # 验证有 critical 和 high
        severities = {item["severity"]: item["count"] for item in dist["items"]}
        assert "critical" in severities, f"critical not in {severities}"
        assert "high" in severities, f"high not in {severities}"

    print("[PASS] test_dashboard_severity_distribution")


async def test_dashboard_trend():
    """get_trend 返回正确数量的趋势数据点。"""
    from app.services.dashboard_service import get_trend

    async with AsyncSessionLocal() as db:
        await _setup_test_data(db)
        await db.commit()

        trend = await get_trend(db, days=7)

        assert trend["days"] == 7
        assert len(trend["data_points"]) == 7, (
            f"Expected 7 data points, got {len(trend['data_points'])}"
        )

        # 验证每个点有 date 和 count
        for dp in trend["data_points"]:
            assert "date" in dp
            assert "count" in dp
            assert isinstance(dp["count"], int)

        # 今天的点应该 >= 2 (我们插入了2个 finding)
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        today_points = [dp for dp in trend["data_points"] if dp["date"] == today_str]
        if today_points:
            assert today_points[0]["count"] >= 2, (
                f"Today's count should be >= 2, got {today_points[0]['count']}"
            )

    print("[PASS] test_dashboard_trend")


async def test_dashboard_recent_tasks():
    """get_recent_tasks 返回最近任务列表（JOIN project）。"""
    from app.services.dashboard_service import get_recent_tasks

    async with AsyncSessionLocal() as db:
        await _setup_test_data(db)
        await db.commit()

        result = await get_recent_tasks(db, limit=10)

        assert "items" in result
        assert "total" in result
        assert result["total"] >= 1, f"Expected >= 1 task, got {result['total']}"

        # 验证 JOIN 返回了 project_name
        item = result["items"][0]
        assert "project_name" in item, f"project_name not in item: {item}"
        assert item["project_name"] == "Platform Governance Test Project"
        assert "id" in item
        assert "status" in item

    print("[PASS] test_dashboard_recent_tasks")


async def test_api_dashboard_stats():
    """GET /api/v1/dashboard/stats 返回 200。"""
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        await _setup_test_data(db)
        await db.commit()

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/dashboard/stats",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert "total_projects" in data
        assert "total_tasks" in data
        assert "total_findings" in data
        assert "max_cvss" in data
        assert "overall_risk_distribution" in data

    app.dependency_overrides.clear()
    print("[PASS] test_api_dashboard_stats")


async def test_api_dashboard_trend():
    """GET /api/v1/dashboard/trend?days=7 返回 200。"""
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        await _setup_test_data(db)
        await db.commit()

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/dashboard/trend?days=7",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["days"] == 7
        assert len(data["data_points"]) == 7

    app.dependency_overrides.clear()
    print("[PASS] test_api_dashboard_trend")


# ══════════════════════════════════════════════════════
# 子模块2: LLM 配置
# ══════════════════════════════════════════════════════


async def test_llm_mask_api_key():
    """mask_api_key 三种脱敏场景。"""
    from app.services.llm_config_service import mask_api_key

    # 正常长度 key: 前4后2
    result = mask_api_key("sk-abcdefghijklmnop")
    assert result == "sk-a****op", f"Expected 'sk-a****op', got '{result}'"

    # 短 key (< 8 chars)
    result = mask_api_key("short")
    assert result == "****", f"Expected '****', got '{result}'"

    # None / 空
    assert mask_api_key(None) == ""
    assert mask_api_key("") == ""

    # 刚好 8 字符
    result = mask_api_key("12345678")
    assert result == "1234****78", f"Expected '1234****78', got '{result}'"

    print("[PASS] test_llm_mask_api_key")


async def test_llm_get_all_configs():
    """get_all_configs 返回3个模式，demo 激活。"""
    from app.services.llm_config_service import get_all_configs

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

        result = await get_all_configs(db)
        await db.commit()

        assert "items" in result
        assert "active_mode" in result
        assert len(result["items"]) == 3, (
            f"Expected 3 modes, got {len(result['items'])}"
        )
        assert result["active_mode"] == "demo", (
            f"Expected active_mode='demo', got '{result['active_mode']}'"
        )

        # 验证每个 item 有脱敏 api_key
        for item in result["items"]:
            assert "mode" in item
            assert "api_key_masked" in item
            assert "enabled" in item

    print("[PASS] test_llm_get_all_configs")


async def test_llm_update_config():
    """update_config 更新后返回脱敏 key。"""
    from app.services.llm_config_service import (
        get_all_configs,
        update_config,
    )

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

        # 更新 openai 模式
        result = await update_config(
            db,
            mode="openai",
            updates={
                "api_key": "sk-test-key-12345678",
                "base_url": "https://api.openai.com/v1",
                "model": "gpt-4o",
                "max_tokens": 8192,
                "temperature": 0.3,
                "enabled": True,
            },
            operator="admin",
        )
        await db.commit()

        assert result["mode"] == "openai"
        assert result["api_key_masked"] == "sk-t****78", (
            f"Expected 'sk-t****78', got '{result['api_key_masked']}'"
        )
        assert result["model"] == "gpt-4o"
        assert result["max_tokens"] == 8192
        assert result["temperature"] == 0.3
        assert result["enabled"] is True

        # 验证写入审计日志
        from app.services.audit_service import list_audit_logs

        logs = await list_audit_logs(db, action="config_update", target_id="openai")
        assert logs["total"] >= 1, f"Expected audit log, got {logs['total']}"

    print("[PASS] test_llm_update_config")


async def test_llm_activate_mode():
    """activate_mode 切换激活模式。"""
    from app.services.llm_config_service import (
        activate_mode,
        get_all_configs,
    )

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

        # 初始激活模式应该是 demo
        result = await get_all_configs(db)
        assert result["active_mode"] == "demo"

        # 切换到 openai
        activate_result = await activate_mode(db, mode="openai", operator="admin")
        await db.commit()

        assert activate_result["active_mode"] == "openai"
        assert activate_result["success"] is True

        # 再次查询确认
        result = await get_all_configs(db)
        assert result["active_mode"] == "openai", (
            f"Expected 'openai', got '{result['active_mode']}'"
        )

    print("[PASS] test_llm_activate_mode")


async def test_llm_test_connection():
    """test_llm_connection 对 demo 模式返回成功。"""
    from app.services.llm_config_service import test_llm_connection

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

        # demo 模式总是成功
        result = await test_llm_connection(db, mode="demo")
        assert result["success"] is True, f"Demo should succeed: {result}"
        assert "latency_ms" in result
        assert "message" in result

        # openai 模式未配置 api_key 时应失败
        result = await test_llm_connection(db, mode="openai")
        assert result["success"] is False, f"Openai without key should fail: {result}"
        assert "API Key" in result["message"]

        # ollama 模式配置验证通过
        result = await test_llm_connection(db, mode="ollama")
        assert result["success"] is True

    print("[PASS] test_llm_test_connection")


async def test_api_llm_get_config():
    """GET /api/v1/llm/config 返回 200 脱敏。"""
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/llm/config",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert "items" in data
        assert "active_mode" in data
        assert len(data["items"]) == 3

        # 验证 api_key 是脱敏的
        for item in data["items"]:
            assert "api_key_masked" in item
            # 确保没有完整 key 泄露
            assert "api_key" not in item or item.get("api_key") is None

    app.dependency_overrides.clear()
    print("[PASS] test_api_llm_get_config")


async def test_api_llm_put_config():
    """PUT /api/v1/llm/config admin 更新成功。"""
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.put(
            "/api/v1/llm/config",
            json={
                "mode": "openai",
                "api_key": "sk-put-test-key-12345",
                "base_url": "https://api.openai.com/v1",
                "model": "gpt-4o-mini",
                "max_tokens": 4096,
                "temperature": 0.2,
                "enabled": True,
            },
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["mode"] == "openai"
        assert data["api_key_masked"] == "sk-p****45"
        assert data["model"] == "gpt-4o-mini"

    app.dependency_overrides.clear()
    print("[PASS] test_api_llm_put_config")


async def test_api_llm_put_config_forbidden():
    """PUT /api/v1/llm/config developer 403。"""
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 使用 developer 角色 token
        resp = await client.put(
            "/api/v1/llm/config",
            json={"mode": "openai", "model": "gpt-4o"},
            headers={
                "X-API-Token": "developer:dev-api-token-change-in-production",
            },
        )
        assert resp.status_code == 403, (
            f"Expected 403, got {resp.status_code}: {resp.text}"
        )

    app.dependency_overrides.clear()
    print("[PASS] test_api_llm_put_config_forbidden")


async def test_api_llm_activate():
    """POST /api/v1/llm/config/activate 切换激活模式。"""
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 切换到 openai
        resp = await client.post(
            "/api/v1/llm/config/activate",
            json={"mode": "openai"},
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["active_mode"] == "openai"
        assert data["success"] is True

    app.dependency_overrides.clear()
    print("[PASS] test_api_llm_activate")


async def test_api_llm_test():
    """POST /api/v1/llm/test demo 模式成功。"""
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        await _cleanup_llm_configs(db)
        await db.commit()

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/llm/test",
            json={"mode": "demo"},
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["success"] is True
        assert "latency_ms" in data
        assert "message" in data

    app.dependency_overrides.clear()
    print("[PASS] test_api_llm_test")


async def test_api_llm_modes():
    """GET /api/v1/llm/modes 返回模式列表。"""
    from app.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/llm/modes",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert "modes" in data
        assert len(data["modes"]) == 3
        assert "openai" in data["modes"]
        assert "ollama" in data["modes"]
        assert "demo" in data["modes"]

    app.dependency_overrides.clear()
    print("[PASS] test_api_llm_modes")


# ══════════════════════════════════════════════════════
# 子模块3: 权限角色
# ══════════════════════════════════════════════════════


async def test_security_require_role_admin():
    """require_role('admin') — admin token 通过。"""
    from app.core.security import get_current_role, require_role

    # Step 1: get role from token
    role = await get_current_role(
        credentials=None,
        x_api_token="dev-api-token-change-in-production",
    )
    assert role == "admin"

    # Step 2: require_role check passes
    check = require_role("admin")
    result = await check(role=role)
    assert result == "admin"

    print("[PASS] test_security_require_role_admin")


async def test_security_require_role_forbidden():
    """require_role('admin') — developer token 403。"""
    from app.core.errors import AuthorizationError
    from app.core.security import get_current_role, require_role

    # Step 1: get role from developer token
    role = await get_current_role(
        credentials=None,
        x_api_token="developer:dev-api-token-change-in-production",
    )
    assert role == "developer"

    # Step 2: require_role('admin') should reject developer
    check = require_role("admin")
    try:
        await check(role=role)
        assert False, "Should have raised AuthorizationError"
    except AuthorizationError as e:
        assert "admin" in str(e) or "developer" in str(e)

    print("[PASS] test_security_require_role_forbidden")


async def test_security_role_parsing():
    """token 格式解析 — 普通 token -> admin, role:token -> 指定角色。"""
    from app.core.security import _parse_token

    # 普通 token -> admin
    role, username = _parse_token("dev-api-token-change-in-production")
    assert role == "admin", f"Expected 'admin', got '{role}'"
    assert username == "admin"

    # developer:token -> developer
    role, username = _parse_token("developer:dev-api-token-change-in-production")
    assert role == "developer", f"Expected 'developer', got '{role}'"
    assert username == "developer"

    # security_auditor:token -> security_auditor
    role, username = _parse_token("security_auditor:dev-api-token-change-in-production")
    assert role == "security_auditor"

    print("[PASS] test_security_role_parsing")


# ══════════════════════════════════════════════════════
# 子模块4: 审计日志增强
# ══════════════════════════════════════════════════════


async def test_audit_log_filter_by_task_id():
    """list_audit_logs filter by task_id。"""
    from app.services.audit_service import list_audit_logs

    async with AsyncSessionLocal() as db:
        _, task, _, _, _ = await _setup_test_data(db)
        await db.commit()

        # 按 task_id 过滤
        result = await list_audit_logs(db, task_id=task.id)

        # 应该返回与该 task 相关的审计日志（至少2条：create + start）
        assert result["total"] >= 2, (
            f"Expected >= 2 logs for task, got {result['total']}"
        )

        # 验证所有返回的日志都属于该 task
        for item in result["items"]:
            assert item.task_id == task.id, (
                f"task_id mismatch: {item.task_id} != {task.id}"
            )

    print("[PASS] test_audit_log_filter_by_task_id")


async def test_audit_log_filter_by_target_id():
    """list_audit_logs filter by target_id。"""
    from app.services.audit_service import list_audit_logs

    async with AsyncSessionLocal() as db:
        _, task, _, _, _ = await _setup_test_data(db)
        await db.commit()

        # 按 target_id 过滤（target_id=task.id 的记录有2条）
        result = await list_audit_logs(db, target_id=task.id)

        assert result["total"] >= 2, (
            f"Expected >= 2 logs with target_id, got {result['total']}"
        )

        for item in result["items"]:
            assert item.target_id == task.id

    print("[PASS] test_audit_log_filter_by_target_id")


async def test_audit_log_by_task():
    """list_audit_logs_by_task 便捷函数。"""
    from app.services.audit_service import list_audit_logs_by_task

    async with AsyncSessionLocal() as db:
        _, task, _, _, _ = await _setup_test_data(db)
        await db.commit()

        result = await list_audit_logs_by_task(db, task_id=task.id)

        assert result["total"] >= 2
        for item in result["items"]:
            assert item.task_id == task.id

    print("[PASS] test_audit_log_by_task")


async def test_api_audit_logs_new_filters():
    """GET /api/v1/audit-logs?task_id=... — 新参数可用。"""
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        _, task, _, _, _ = await _setup_test_data(db)
        await db.commit()

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 按 task_id 过滤
        resp = await client.get(
            f"/api/v1/audit-logs?task_id={task.id}",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["total"] >= 2, f"Expected >= 2, got {data['total']}"

        for item in data["items"]:
            assert item["task_id"] == task.id

    app.dependency_overrides.clear()
    print("[PASS] test_api_audit_logs_new_filters")


# ══════════════════════════════════════════════════════
# 入口
# ══════════════════════════════════════════════════════

if __name__ == "__main__":

    async def run_all():
        # 建表（与其他 E2E 测试一致：先 drop 再 create）
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

        tests = [
            # 大盘统计
            test_dashboard_stats,
            test_dashboard_severity_distribution,
            test_dashboard_trend,
            test_dashboard_recent_tasks,
            test_api_dashboard_stats,
            test_api_dashboard_trend,
            # LLM 配置
            test_llm_mask_api_key,
            test_llm_get_all_configs,
            test_llm_update_config,
            test_llm_activate_mode,
            test_llm_test_connection,
            test_api_llm_get_config,
            test_api_llm_put_config,
            test_api_llm_put_config_forbidden,
            test_api_llm_activate,
            test_api_llm_test,
            test_api_llm_modes,
            # 权限角色
            test_security_require_role_admin,
            test_security_require_role_forbidden,
            test_security_role_parsing,
            # 审计日志增强
            test_audit_log_filter_by_task_id,
            test_audit_log_filter_by_target_id,
            test_audit_log_by_task,
            test_api_audit_logs_new_filters,
        ]

        passed = 0
        failed = 0
        for test_fn in tests:
            try:
                # 每个测试前重建表，确保干净状态
                async with engine.begin() as conn:
                    await conn.run_sync(Base.metadata.drop_all)
                    await conn.run_sync(Base.metadata.create_all)
                await test_fn()
                passed += 1
            except Exception as e:
                failed += 1
                print(f"[FAIL] {test_fn.__name__}: {type(e).__name__}: {e}")
                import traceback

                traceback.print_exc()

        print(f"\n{'=' * 60}")
        print(f"Platform Governance E2E: {passed}/{passed + failed} passed")
        if failed:
            print(f"FAILED: {failed}")
        sys.exit(1 if failed else 0)

    asyncio.run(run_all())
