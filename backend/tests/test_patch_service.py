"""修复补丁 Service + Router 集成测试。

测试覆盖：
- generate_patch_for_finding（补丁生成）
- validate_patch_by_id（三层校验）
- adopt_patch / reject_patch（状态流转 + finding 状态联动）
- get_patches_by_task / get_patch_detail / get_patch_diff_text
- export_patch_zip（ZIP 打包）
- FastAPI TestClient 端到端 API 测试
"""

import asyncio
import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.database import AsyncSessionLocal, Base, engine
from app.core.redis import get_redis
from app.core.database import get_db
from app.models import Finding, Project, Task
from app.utils import generate_id


# ──────────────────────────────────────────────────────
# FakeRedis：模拟 redis.asyncio.Redis 的 publish 方法
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
# 测试辅助
# ──────────────────────────────────────────────────────


async def _setup_db(db):
    """插入 Project → Task → Finding 外键链，返回三者。"""
    project = Project(
        id=generate_id(),
        project_name="Patch Test Project",
        source_type="upload",
        source_input="/tmp/test.zip",
        tech_stack=["Python"],
        status="active",
    )
    db.add(project)
    await db.flush()

    task = Task(
        id=generate_id(),
        project_id=project.id,
        status="running",
        current_phase="code_audit",
    )
    db.add(task)
    await db.flush()

    finding = Finding(
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
    )
    db.add(finding)
    await db.flush()
    return project, task, finding


# ──────────────────────────────────────────────────────
# Service 层测试
# ──────────────────────────────────────────────────────


async def test_generate_patch():
    """测试补丁生成。"""
    from app.services.patch_service import generate_patch_for_finding

    async with AsyncSessionLocal() as db:
        _, task, finding = await _setup_db(db)
        await db.commit()

        fake_redis = FakeRedis()
        patch_id = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        assert patch_id is not None
        assert isinstance(patch_id, str)
        print(f"[PASS] generate_patch (id={patch_id})")

        # 验证 WS 事件
        assert len(fake_redis.published) > 0
        event = json.loads(fake_redis.published[0]["message"])
        assert event["event"] == "patch_ready"
        assert event["payload"]["patch_id"] == patch_id
        assert event["payload"]["finding_id"] == finding.id
        print("[PASS] WS event patch_ready published")


async def test_generate_patch_idempotent():
    """测试同一 finding 重复生成返回同一 patch_id。"""
    from app.services.patch_service import generate_patch_for_finding

    async with AsyncSessionLocal() as db:
        _, _, finding = await _setup_db(db)
        await db.commit()

        fake_redis = FakeRedis()
        patch_id_1 = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        patch_id_2 = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        assert patch_id_1 == patch_id_2
        print(f"[PASS] idempotent (id={patch_id_1})")


async def test_validate_patch():
    """测试补丁校验。"""
    from app.services.patch_service import (
        generate_patch_for_finding,
        validate_patch_by_id,
    )

    async with AsyncSessionLocal() as db:
        _, _, finding = await _setup_db(db)
        await db.commit()

        fake_redis = FakeRedis()
        patch_id = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        result = await validate_patch_by_id(db, fake_redis, patch_id)
        await db.commit()

        assert "validated" in result
        assert "validation_result" in result
        assert isinstance(result["validation_result"], dict)
        # SQL 注入修复后应该通过语法检查
        assert result["validation_result"]["syntax"]["passed"] is True
        print(f"[PASS] validate_patch (validated={result['validated']})")


async def test_adopt_patch():
    """测试采纳补丁 + finding 状态联动。"""
    from app.enums import FindingStatus
    from app.services.patch_service import (
        adopt_patch,
        generate_patch_for_finding,
    )
    from app.services.finding_service import get_finding

    async with AsyncSessionLocal() as db:
        _, _, finding = await _setup_db(db)
        await db.commit()

        fake_redis = FakeRedis()
        patch_id = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        updated = await adopt_patch(db, fake_redis, patch_id)
        await db.commit()

        assert updated.adopt_status == "adopted"

        # finding 状态应变为 adopted
        updated_finding = await get_finding(db, finding.id)
        assert updated_finding.status == FindingStatus.ADOPTED.value
        print("[PASS] adopt_patch (finding status -> adopted)")


async def test_reject_patch():
    """测试拒绝补丁。"""
    from app.services.patch_service import (
        generate_patch_for_finding,
        reject_patch,
    )

    async with AsyncSessionLocal() as db:
        _, _, finding = await _setup_db(db)
        await db.commit()

        fake_redis = FakeRedis()
        patch_id = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        updated = await reject_patch(db, fake_redis, patch_id, reason="不符合业务逻辑")
        await db.commit()

        assert updated.adopt_status == "rejected"
        print("[PASS] reject_patch")


async def test_get_patches_by_task():
    """测试获取任务下所有补丁。"""
    from app.services.patch_service import (
        generate_patch_for_finding,
        get_patches_by_task,
    )

    async with AsyncSessionLocal() as db:
        _, task, finding = await _setup_db(db)
        await db.commit()

        fake_redis = FakeRedis()
        patch_id = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        patches = await get_patches_by_task(db, task.id)
        assert len(patches) == 1
        assert patches[0].id == patch_id
        print(f"[PASS] get_patches_by_task (count=1)")


async def test_get_patch_diff_text():
    """测试获取 diff 纯文本。"""
    from app.services.patch_service import (
        generate_patch_for_finding,
        get_patch_diff_text,
    )

    async with AsyncSessionLocal() as db:
        _, _, finding = await _setup_db(db)
        await db.commit()

        fake_redis = FakeRedis()
        patch_id = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        diff = await get_patch_diff_text(db, patch_id)
        assert diff is not None
        assert "---" in diff or "@@" in diff or "+" in diff
        print(f"[PASS] get_patch_diff_text (len={len(diff)})")


async def test_export_patch_zip():
    """测试导出 ZIP。"""
    from app.services.patch_service import (
        export_patch_zip,
        generate_patch_for_finding,
    )

    async with AsyncSessionLocal() as db:
        _, _, finding = await _setup_db(db)
        await db.commit()

        fake_redis = FakeRedis()
        patch_id = await generate_patch_for_finding(db, fake_redis, finding.id)
        await db.commit()

        zip_bytes = await export_patch_zip(db, patch_id)
        assert len(zip_bytes) > 0

        buf = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            assert "diff.patch" in names
            assert "README.md" in names
            # 验证 README 内容
            readme = zf.read("README.md").decode("utf-8")
            assert "修复补丁说明" in readme
            assert patch_id in readme
        print(f"[PASS] export_patch_zip (size={len(zip_bytes)})")


# ──────────────────────────────────────────────────────
# Router 层 API 测试（FastAPI TestClient + 依赖覆盖）
# ──────────────────────────────────────────────────────


async def test_api_endpoints():
    """端到端 API 测试：8 个端点全覆盖。"""
    from httpx import ASGITransport, AsyncClient

    from app.core.security import get_current_user
    from app.main import create_app

    app = create_app()

    # 先插入测试数据（PostgreSQL 持久化，ASGITransport 新 session 可读）
    async with AsyncSessionLocal() as db:
        _, task, finding = await _setup_db(db)
        await db.commit()
        task_id = task.id
        finding_id = finding.id

    # 每次请求创建新 session（与 get_db 行为一致，避免跨 loop）
    fake_redis = FakeRedis()

    async def override_db():
        async with AsyncSessionLocal() as session:
            yield session

    async def override_redis():
        yield fake_redis

    async def override_user():
        return "test-user"

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_redis] = override_redis
    app.dependency_overrides[get_current_user] = override_user

    headers = {"X-API-Token": "dev-api-token-change-in-production"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. POST /findings/{id}/patches — 生成补丁
        resp = await client.post(
            f"/api/v1/findings/{finding_id}/patches",
            json={},
            headers=headers,
        )
        assert resp.status_code == 201, f"POST patches: {resp.status_code} {resp.text}"
        data = resp.json()
        patch_id = data["id"]
        assert data["finding_id"] == finding_id
        assert data["adopt_status"] == "pending"
        assert data["validated"] is False
        assert data["diff_content"] is not None
        print(f"[PASS] POST /findings/{{id}}/patches (patch={patch_id})")

        # 2. GET /patches/{id} — 补丁详情
        resp = await client.get(f"/api/v1/patches/{patch_id}", headers=headers)
        assert resp.status_code == 200, f"GET patch: {resp.status_code} {resp.text}"
        assert resp.json()["id"] == patch_id
        print("[PASS] GET /patches/{id}")

        # 3. GET /patches/{id}/diff — Diff 纯文本
        resp = await client.get(f"/api/v1/patches/{patch_id}/diff", headers=headers)
        assert resp.status_code == 200, f"GET diff: {resp.status_code} {resp.text}"
        diff_data = resp.json()
        assert diff_data["patch_id"] == patch_id
        assert "diff" in diff_data
        print("[PASS] GET /patches/{id}/diff")

        # 4. POST /patches/{id}/validate — 触发校验
        resp = await client.post(
            f"/api/v1/patches/{patch_id}/validate", headers=headers
        )
        assert resp.status_code == 200, f"POST validate: {resp.status_code} {resp.text}"
        val_data = resp.json()
        assert "validated" in val_data
        assert "validation_result" in val_data
        print(
            f"[PASS] POST /patches/{{id}}/validate (validated={val_data['validated']})"
        )

        # 5. POST /patches/{id}/adopt — 采纳
        resp = await client.post(f"/api/v1/patches/{patch_id}/adopt", headers=headers)
        assert resp.status_code == 200, f"POST adopt: {resp.status_code} {resp.text}"
        assert resp.json()["adopt_status"] == "adopted"
        print("[PASS] POST /patches/{id}/adopt")

        # 6. POST /patches/{id}/reject — 拒绝
        resp = await client.post(
            f"/api/v1/patches/{patch_id}/reject",
            json={"reason": "测试拒绝"},
            headers=headers,
        )
        assert resp.status_code == 200, f"POST reject: {resp.status_code} {resp.text}"
        assert resp.json()["adopt_status"] == "rejected"
        print("[PASS] POST /patches/{id}/reject")

        # 7. GET /tasks/{id}/patches — 任务下补丁列表
        resp = await client.get(f"/api/v1/tasks/{task_id}/patches", headers=headers)
        assert resp.status_code == 200, (
            f"GET task patches: {resp.status_code} {resp.text}"
        )
        list_data = resp.json()
        assert list_data["total"] >= 1
        print(f"[PASS] GET /tasks/{{id}}/patches (total={list_data['total']})")

        # 8. GET /patches/{id}/export — 导出 ZIP
        resp = await client.get(f"/api/v1/patches/{patch_id}/export", headers=headers)
        assert resp.status_code == 200, f"GET export: {resp.status_code} {resp.text}"
        assert resp.headers["content-type"] == "application/zip"
        assert "attachment" in resp.headers["content-disposition"]
        # 验证 zip 内容
        buf = io.BytesIO(resp.content)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            assert "diff.patch" in names
            assert "README.md" in names
        print("[PASS] GET /patches/{id}/export (zip)")

    # 清理
    app.dependency_overrides.clear()


# ──────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────


async def run_all_tests():
    """运行所有异步测试。"""
    # 建表
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("\n=== Service Tests ===")
    await test_generate_patch()
    await test_generate_patch_idempotent()
    await test_validate_patch()
    await test_adopt_patch()
    await test_reject_patch()
    await test_get_patches_by_task()
    await test_get_patch_diff_text()
    await test_export_patch_zip()

    print("\n=== Router API Tests ===")
    await test_api_endpoints()

    # 清理
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    print("\n=== ALL TESTS PASSED ===")


if __name__ == "__main__":
    asyncio.run(run_all_tests())
