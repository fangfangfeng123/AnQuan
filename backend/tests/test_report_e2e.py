"""报告生成 E2E 集成测试。

测试覆盖：
1. Generator: assemble_report_data 聚合5章节结构化数据
2. Exporter: to_markdown + to_html Jinja2 模板渲染
3. Service: generate_report 生成报告 + 文件落盘 + DB 入库 + 版本化
4. Service: regenerate_report version+1 + 不覆盖旧文件
5. Agent: agents.report_gen.execute 薄编排层事件发布
6. API: GET /tasks/{id}/report 获取摘要
7. API: GET /reports/{id} 获取完整详情
8. API: GET /reports/{id}/download/{format} 下载文件
9. API: GET /reports/{id}/sections/{name} 获取单章节数据
10. API: POST /tasks/{id}/report/regenerate 重新生成
11. API: GET /tasks/{id}/report 404 (任务不存在)
12. API: GET /reports/{id}/sections/{name} 400 (无效章节名)
"""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
from httpx import ASGITransport

from app.core.database import AsyncSessionLocal, Base, engine, get_db
from app.core.redis import get_redis
from app.models import AttackChain, Finding, FixPatch, Project, RuntimeProfile, Task
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


async def _setup_full_evaluation_data(db):
    """插入 Project -> Task -> RuntimeProfile -> 2 Findings -> AttackChain。"""
    project = Project(
        id=generate_id(),
        project_name="Report E2E Test Project",
        source_type="upload",
        source_input="/tmp/test_report.zip",
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
    )
    db.add(task)
    await db.flush()

    # RuntimeProfile
    rp = RuntimeProfile(
        id=generate_id(),
        task_id=task.id,
        language="python",
        framework="flask",
        dependencies={"flask": "2.3.2", "sqlite3": "builtin"},
        service_ports=[5000],
        entry_points=["/api/orders", "/admin/upload"],
        run_command="python app.py",
    )
    db.add(rp)

    # Finding 1: SQL injection (critical, verified)
    sql_finding = Finding(
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
        remediation="Use parameterized queries instead of string interpolation.",
    )
    db.add(sql_finding)

    # Finding 2: File upload (high, verified)
    upload_finding = Finding(
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
        remediation="Validate file extensions and use a secure upload directory.",
    )
    db.add(upload_finding)
    await db.flush()

    # FixPatch for SQL injection finding
    patch = FixPatch(
        id=generate_id(),
        task_id=task.id,
        finding_id=sql_finding.id,
        original_code='cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")',
        patched_code='cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))',
        diff_content='--- a/app.py\n+++ b/app.py\n@@ -74,1 +74,1 @@\n-cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")\n+cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))',
        description="Use parameterized query to prevent SQL injection.",
        adopt_status="pending",
        validated=False,
    )
    db.add(patch)

    # AttackChain: SQL injection -> file upload
    chain = AttackChain(
        id=generate_id(),
        task_id=task.id,
        name="SQL注入 -> 文件上传",
        final_impact="通过SQL注入获取管理员凭证后上传WebShell获得宿主机执行权(RCE)",
        overall_severity="critical",
        overall_cvss=9.9,
        node_count=2,
        edge_count=1,
        is_single_node=False,
    )
    db.add(chain)
    await db.flush()

    from app.models import AttackChainNode, AttackChainEdge

    node1 = AttackChainNode(
        id=generate_id(),
        attack_chain_id=chain.id,
        finding_id=sql_finding.id,
        node_id="node-1",
        label="SQL注入",
        asset="/api/orders",
        vuln_type="sql_injection",
        precondition="可访问接口",
        post_capability="获取管理员凭证",
        privilege_level="anonymous -> admin",
        node_order=1,
    )
    node2 = AttackChainNode(
        id=generate_id(),
        attack_chain_id=chain.id,
        finding_id=upload_finding.id,
        node_id="node-2",
        label="文件上传",
        asset="/admin/upload",
        vuln_type="file_upload",
        precondition="管理员权限",
        post_capability="WebShell",
        privilege_level="admin -> system",
        node_order=2,
    )
    db.add(node1)
    db.add(node2)
    await db.flush()

    edge = AttackChainEdge(
        id=generate_id(),
        attack_chain_id=chain.id,
        source_node_id=node1.id,
        target_node_id=node2.id,
        condition="SQL注入获取管理员凭证",
        action="登录后台上传WebShell",
        privilege_escalation="admin -> admin",
        step=1,
    )
    db.add(edge)

    await db.flush()
    return project, task, sql_finding, upload_finding, chain, patch


# ──────────────────────────────────────────────────────
# 测试 1: Generator 数据聚合
# ──────────────────────────────────────────────────────


async def test_generator_assemble_data():
    """assemble_report_data 聚合5章节结构化数据。"""
    from app.reports.generator import assemble_report_data

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        data = await assemble_report_data(db, task.id)

        # 验证基础数据
        assert data.task is not None, "Task should be loaded"
        assert data.project is not None, "Project should be loaded"
        assert data.runtime_profile is not None, "RuntimeProfile should be loaded"
        assert len(data.findings) == 2, f"Expected 2 findings, got {len(data.findings)}"
        assert len(data.attack_chains) == 1, (
            f"Expected 1 chain, got {len(data.attack_chains)}"
        )

        # 验证 findings 按 severity 排序
        assert data.findings[0].severity == "critical"
        assert data.findings[1].severity == "high"

        # 验证 statistics
        sev_dist = data.statistics.get("severity_distribution", {})
        assert sev_dist.get("critical") == 1
        assert sev_dist.get("high") == 1
        assert data.statistics.get("total_findings") == 2
        assert data.statistics.get("max_cvss") == 9.8

        # 验证 overall_risk
        assert data.overall_risk == "critical", (
            f"Expected critical risk, got {data.overall_risk}"
        )

        # 验证 5 个章节
        assert "executive_summary" in data.sections
        assert "scope" in data.sections
        assert "findings" in data.sections
        assert "attack_chains" in data.sections
        assert "remediation" in data.sections

        # §1 执行摘要
        es = data.sections["executive_summary"]
        assert es["total_findings"] == 2
        assert es["critical_count"] == 1
        assert es["high_count"] == 1
        assert es["overall_risk"] == "critical"
        assert es["total_chains"] == 1
        assert "summary_text" in es

        # §2 评估范围
        scope = data.sections["scope"]
        assert scope["project_name"] == "Report E2E Test Project"
        assert scope["language"] == "python"
        assert scope["framework"] == "flask"

        # §3 漏洞详情
        findings_section = data.sections["findings"]
        assert len(findings_section) == 2
        assert findings_section[0]["severity"] == "critical"
        assert findings_section[0]["vuln_type"] == "sql_injection"
        assert findings_section[0]["patch"] is not None
        assert findings_section[0]["patch"]["diff_content"] is not None

        # §4 攻击链分析
        chains_section = data.sections["attack_chains"]
        assert len(chains_section) == 1
        assert chains_section[0]["is_single_node"] == False
        assert chains_section[0]["node_count"] == 2
        assert len(chains_section[0]["nodes"]) == 2
        assert len(chains_section[0]["edges"]) == 1
        assert chains_section[0]["final_impact"] is not None

        # §5 修复建议
        remediation = data.sections["remediation"]
        assert len(remediation) == 2
        assert remediation[0]["severity"] == "critical"
        assert remediation[0]["has_patch"] == True
        assert remediation[1]["has_patch"] == False

    print("[PASS] test_generator_assemble_data")


# ──────────────────────────────────────────────────────
# 测试 2: Exporter 模板渲染
# ──────────────────────────────────────────────────────


async def test_exporter_render():
    """to_markdown + to_html Jinja2 模板渲染。"""
    from app.core.config import get_settings
    from app.reports.exporter import to_html, to_markdown
    from app.reports.generator import assemble_report_data

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        data = await assemble_report_data(db, task.id)

        settings = get_settings()
        template_dir = str(
            Path(settings.REPORT_TEMPLATE_DIR)
            if Path(settings.REPORT_TEMPLATE_DIR).is_absolute()
            else Path.cwd() / settings.REPORT_TEMPLATE_DIR
        )

        md_content = to_markdown(data, template_dir)
        html_content = to_html(data, template_dir)

        # Markdown 验证
        assert isinstance(md_content, str)
        assert len(md_content) > 100, f"Markdown too short: {len(md_content)} chars"
        assert "Report E2E Test Project" in md_content
        assert "sql_injection" in md_content
        assert "critical" in md_content.lower()
        assert "SQL" in md_content or "sql" in md_content.lower()

        # HTML 验证
        assert isinstance(html_content, str)
        assert len(html_content) > 100
        assert "<html" in html_content.lower() or "<!DOCTYPE" in html_content.upper()
        assert "Report E2E Test Project" in html_content
        assert "sql_injection" in html_content

    print("[PASS] test_exporter_render")


# ──────────────────────────────────────────────────────
# 测试 3: Service generate_report
# ──────────────────────────────────────────────────────


async def test_service_generate_report():
    """generate_report 生成报告 + 文件落盘 + DB 入库。"""
    from app.services.report_service import generate_report, get_report_by_task

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        redis = FakeRedis()
        result = await generate_report(db, redis, task.id)

        # 验证返回结果
        assert result.success, f"Report generation failed: {result.error}"
        assert result.report_id is not None
        assert result.version == 1
        assert result.overall_risk == "critical"
        assert result.total_findings == 2

        # 验证文件落盘
        md_path = Path(result.markdown_path)
        html_path = Path(result.html_path)
        assert md_path.exists(), f"Markdown file not found: {md_path}"
        assert html_path.exists(), f"HTML file not found: {html_path}"
        assert md_path.read_text(encoding="utf-8") != ""
        assert html_path.read_text(encoding="utf-8") != ""

        # 验证 DB 入库
        report = await get_report_by_task(db, task.id)
        assert report is not None
        assert report.task_id == task.id
        assert report.version == 1
        assert report.overall_risk == "critical"
        assert report.total_findings == 2
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.markdown_path is not None
        assert report.html_path is not None
        assert report.pdf_path is None

        # 验证 sections 存储
        assert report.sections is not None
        assert "executive_summary" in report.sections
        assert "findings" in report.sections

        # 验证 WS 事件发布
        assert len(redis.published) > 0
        ws_events = [json.loads(p["message"]).get("event") for p in redis.published]
        assert "report_ready" in ws_events, f"report_ready not in events: {ws_events}"

    print("[PASS] test_service_generate_report")


# ──────────────────────────────────────────────────────
# 测试 4: Service regenerate version+1
# ──────────────────────────────────────────────────────


async def test_service_regenerate_version():
    """regenerate_report version+1，不覆盖旧文件。"""
    from app.services.report_service import (
        generate_report,
        get_report_by_task,
        regenerate_report,
    )

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        redis = FakeRedis()
        v1 = await generate_report(db, redis, task.id)
        assert v1.success
        assert v1.version == 1
        v1_md_path = v1.markdown_path

        # Regenerate
        v2 = await regenerate_report(db, redis, task.id)
        assert v2.success
        assert v2.version == 2, f"Expected v2, got v{v2.version}"
        v2_md_path = v2.markdown_path

        # 旧文件仍存在
        assert Path(v1_md_path).exists(), "v1 file should still exist"
        # 新文件也存在
        assert Path(v2_md_path).exists(), "v2 file should exist"
        # 路径不同
        assert v1_md_path != v2_md_path, "Paths should differ"

        # DB 记录指向 v2
        report = await get_report_by_task(db, task.id)
        assert report.version == 2

    print("[PASS] test_service_regenerate_version")


# ──────────────────────────────────────────────────────
# 测试 5: Agent execute 事件编排
# ──────────────────────────────────────────────────────


async def test_agent_execute():
    """agents.report_gen.execute 薄编排层事件发布。"""
    from app.agents.report_gen import execute

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        redis = FakeRedis()
        result = await execute(db, redis, task.id)

        assert result.success, f"Agent failed: {result.error}"
        assert result.report_id is not None
        assert result.version == 1
        assert result.overall_risk == "critical"
        assert result.total_findings == 2

        # 验证事件序列
        events = [json.loads(p["message"]).get("event") for p in redis.published]
        assert "phase_started" in events, f"phase_started missing in {events}"
        assert "report_ready" in events, f"report_ready missing in {events}"
        assert "phase_completed" in events, f"phase_completed missing in {events}"

        # phase_started 应在 phase_completed 之前
        ps_idx = events.index("phase_started")
        pc_idx = events.index("phase_completed")
        assert ps_idx < pc_idx, "phase_started should come before phase_completed"

    print("[PASS] test_agent_execute")


# ──────────────────────────────────────────────────────
# 测试 6: API GET /tasks/{id}/report 获取摘要
# ──────────────────────────────────────────────────────


async def test_api_get_report_summary():
    """GET /tasks/{id}/report 返回报告摘要。"""
    from app.main import create_app
    from app.services.report_service import generate_report

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        redis = FakeRedis()
        report_result = await generate_report(db, redis, task.id)
        assert report_result.success

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            f"/api/v1/tasks/{task.id}/report",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["task_id"] == task.id
        assert data["overall_risk"] == "critical"
        assert data["total_findings"] == 2
        assert data["critical_count"] == 1
        assert data["high_count"] == 1
        assert data["version"] == 1
        assert data["markdown_path"] is not None
        assert data["html_path"] is not None

    app.dependency_overrides.clear()
    print("[PASS] test_api_get_report_summary")


# ──────────────────────────────────────────────────────
# 测试 7: API GET /reports/{id} 完整详情
# ──────────────────────────────────────────────────────


async def test_api_get_report_detail():
    """GET /reports/{id} 返回完整报告详情（含5章节）。"""
    from app.main import create_app
    from app.services.report_service import generate_report

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        redis = FakeRedis()
        report_result = await generate_report(db, redis, task.id)
        assert report_result.success
        report_id = report_result.report_id

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            f"/api/v1/reports/{report_id}",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["id"] == report_id
        assert data["task_id"] == task.id
        assert data["overall_risk"] == "critical"
        assert "sections" in data
        assert "executive_summary" in data["sections"]
        assert "scope" in data["sections"]
        assert "findings" in data["sections"]
        assert "attack_chains" in data["sections"]
        assert "remediation" in data["sections"]

        # 验证章节数据内容
        es = data["sections"]["executive_summary"]
        assert es["total_findings"] == 2
        assert es["overall_risk"] == "critical"

        findings_section = data["sections"]["findings"]
        assert len(findings_section) == 2

    app.dependency_overrides.clear()
    print("[PASS] test_api_get_report_detail")


# ──────────────────────────────────────────────────────
# 测试 8: API GET /reports/{id}/download/{format} 下载
# ──────────────────────────────────────────────────────


async def test_api_download_report():
    """GET /reports/{id}/download/markdown 和 html 下载文件。"""
    from app.main import create_app
    from app.services.report_service import generate_report

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        redis = FakeRedis()
        report_result = await generate_report(db, redis, task.id)
        assert report_result.success
        report_id = report_result.report_id

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Download markdown
        resp_md = await client.get(
            f"/api/v1/reports/{report_id}/download/markdown",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp_md.status_code == 200, (
            f"MD Status {resp_md.status_code}: {resp_md.text}"
        )
        assert "text/markdown" in resp_md.headers.get("content-type", "")
        assert "Report E2E Test Project" in resp_md.text

        # Download html
        resp_html = await client.get(
            f"/api/v1/reports/{report_id}/download/html",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp_html.status_code == 200, (
            f"HTML Status {resp_html.status_code}: {resp_html.text}"
        )
        assert "text/html" in resp_html.headers.get("content-type", "")
        assert (
            "<html" in resp_html.text.lower() or "<!DOCTYPE" in resp_html.text.upper()
        )

        # Download non-existent pdf -> 404
        resp_pdf = await client.get(
            f"/api/v1/reports/{report_id}/download/pdf",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp_pdf.status_code == 404, (
            f"Expected 404 for PDF, got {resp_pdf.status_code}"
        )

    app.dependency_overrides.clear()
    print("[PASS] test_api_download_report")


# ──────────────────────────────────────────────────────
# 测试 9: API GET /reports/{id}/sections/{name} 单章节
# ──────────────────────────────────────────────────────


async def test_api_get_section():
    """GET /reports/{id}/sections/{name} 返回单章节数据。"""
    from app.main import create_app
    from app.services.report_service import generate_report

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        redis = FakeRedis()
        report_result = await generate_report(db, redis, task.id)
        assert report_result.success
        report_id = report_result.report_id

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 获取 executive_summary 章节
        resp = await client.get(
            f"/api/v1/reports/{report_id}/sections/executive_summary",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["section_name"] == "executive_summary"
        assert data["section_data"]["total_findings"] == 2
        assert data["section_data"]["overall_risk"] == "critical"

        # 获取 findings 章节
        resp2 = await client.get(
            f"/api/v1/reports/{report_id}/sections/findings",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["section_name"] == "findings"
        assert isinstance(data2["section_data"], list)
        assert len(data2["section_data"]) == 2

    app.dependency_overrides.clear()
    print("[PASS] test_api_get_section")


# ──────────────────────────────────────────────────────
# 测试 10: API POST /tasks/{id}/report/regenerate
# ──────────────────────────────────────────────────────


async def test_api_regenerate_report():
    """POST /tasks/{id}/report/regenerate version+1。"""
    from app.main import create_app
    from app.services.report_service import generate_report

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        # 先生成 v1
        redis = FakeRedis()
        v1 = await generate_report(db, redis, task.id)
        assert v1.success
        assert v1.version == 1

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            f"/api/v1/tasks/{task.id}/report/regenerate",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["success"] is True
        assert data["version"] == 2, f"Expected v2, got v{data['version']}"
        assert data["overall_risk"] == "critical"

    app.dependency_overrides.clear()
    print("[PASS] test_api_regenerate_report")


# ──────────────────────────────────────────────────────
# 测试 11: API GET /tasks/{id}/report 404 (任务不存在)
# ──────────────────────────────────────────────────────


async def test_api_report_task_not_found():
    """GET /tasks/{nonexistent}/report -> 404。"""
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
            "/api/v1/tasks/nonexistent-task-id/report",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 404, (
            f"Expected 404, got {resp.status_code}: {resp.text}"
        )

    app.dependency_overrides.clear()
    print("[PASS] test_api_report_task_not_found")


# ──────────────────────────────────────────────────────
# 测试 12: API GET /reports/{id}/sections/{name} 400 (无效章节)
# ──────────────────────────────────────────────────────


async def test_api_invalid_section_name():
    """GET /reports/{id}/sections/invalid_name -> 400。"""
    from app.main import create_app
    from app.services.report_service import generate_report

    async with AsyncSessionLocal() as db:
        _, task, _, _, _, _ = await _setup_full_evaluation_data(db)
        await db.commit()

        redis = FakeRedis()
        report_result = await generate_report(db, redis, task.id)
        assert report_result.success
        report_id = report_result.report_id

    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            f"/api/v1/reports/{report_id}/sections/invalid_section_name",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 400, (
            f"Expected 400, got {resp.status_code}: {resp.text}"
        )

    app.dependency_overrides.clear()
    print("[PASS] test_api_invalid_section_name")


# ──────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────


async def main():
    """运行所有测试。"""
    # 建表
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    tests = [
        test_generator_assemble_data,
        test_exporter_render,
        test_service_generate_report,
        test_service_regenerate_version,
        test_agent_execute,
        test_api_get_report_summary,
        test_api_get_report_detail,
        test_api_download_report,
        test_api_get_section,
        test_api_regenerate_report,
        test_api_report_task_not_found,
        test_api_invalid_section_name,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            # 每个测试前重建表
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
                await conn.run_sync(Base.metadata.create_all)
            await test()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: {e}")
            import traceback

            traceback.print_exc()
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"Report E2E: {passed} passed, {failed} failed, {passed + failed} total")
    print(f"{'=' * 60}")
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
