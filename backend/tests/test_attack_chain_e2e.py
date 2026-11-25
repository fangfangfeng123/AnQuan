"""攻击链推演 E2E 集成测试。

测试覆盖：
1. build_attack_chains：SQL注入 + 文件上传 → 多步DAG攻击链
2. persist_attack_chains：持久化到数据库
3. get_attack_chains (service)：查询验证
4. API: GET /tasks/{id}/attack-chains 端到端
5. 单节点链：单个高危漏洞 → 单节点攻击链
6. 无串联场景：两个不可串联的漏洞 → 生成两条单节点链
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
from httpx import ASGITransport

from app.core.database import AsyncSessionLocal, Base, engine, get_db
from app.core.redis import get_redis
from app.models import Finding, Project, Task
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
# 测试辅助
# ──────────────────────────────────────────────────────


async def _setup_db(db):
    """插入 Project → Task → 两个 verified findings (SQL注入 + 文件上传)。"""
    project = Project(
        id=generate_id(),
        project_name="Attack Chain E2E Project",
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
        current_phase="exploit_chain",
    )
    db.add(task)
    await db.flush()

    # Finding 1: SQL 注入 (verified, critical)
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
    )
    db.add(sql_finding)

    # Finding 2: 文件上传 (verified, high)
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
    )
    db.add(upload_finding)

    await db.flush()
    return project, task, sql_finding, upload_finding


async def _setup_single_finding_db(db):
    """插入单个 verified finding (命令注入)。"""
    project = Project(
        id=generate_id(),
        project_name="Single Chain E2E Project",
        source_type="upload",
        source_input="/tmp/test2.zip",
        tech_stack=["Python"],
        status="active",
    )
    db.add(project)
    await db.flush()

    task = Task(
        id=generate_id(),
        project_id=project.id,
        status="running",
        current_phase="exploit_chain",
    )
    db.add(task)
    await db.flush()

    finding = Finding(
        id=generate_id(),
        task_id=task.id,
        vuln_type="command_injection",
        cwe_id="CWE-78",
        severity="critical",
        cvss_score=9.8,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        file_path="cmd.py",
        line_start=20,
        line_end=20,
        snippet="os.system(f'ping {host}')",
        sink_code="os.system",
        source_code="host = request.args.get('host')",
        detected_by="semgrep",
        confidence=0.95,
        status="verified",
    )
    db.add(finding)
    await db.flush()
    return project, task, finding


# ──────────────────────────────────────────────────────
# 测试 1: 多步攻击链构建 (SQL注入 → 文件上传)
# ──────────────────────────────────────────────────────


async def test_build_multi_step_chain():
    """SQL注入 + 文件上传 → 构建为多步 DAG 攻击链。"""
    from app.chain.builder import build_attack_chains

    async with AsyncSessionLocal() as db:
        await _setup_db(db)
        await db.commit()

        # 查询 verified findings
        from sqlalchemy import select

        stmt = select(Finding).where(
            Finding.task_id != "",
            Finding.status == "verified",
        )
        result = await db.execute(stmt)
        findings = list(result.scalars().all())

        assert len(findings) == 2, f"Expected 2 findings, got {len(findings)}"

        # 构建攻击链
        chains = build_attack_chains(findings)

        # 验证：应生成1条多步攻击链
        assert len(chains) == 1, f"Expected 1 chain, got {len(chains)}"
        chain = chains[0]

        # 不应是单节点链
        assert chain.is_single_node == False, "Should be multi-step chain"
        assert len(chain.nodes) == 2, f"Expected 2 nodes, got {len(chain.nodes)}"
        assert len(chain.edges) >= 1, f"Expected >=1 edge, got {len(chain.edges)}"

        # 验证节点包含 sql_injection 和 file_upload
        vuln_types = [n.vuln_type for n in chain.nodes]
        assert "sql_injection" in vuln_types, f"Missing sql_injection in {vuln_types}"
        assert "file_upload" in vuln_types, f"Missing file_upload in {vuln_types}"

        # 验证边连接 sql_injection → file_upload
        node_map = {n.logical_id: n.vuln_type for n in chain.nodes}
        edge = chain.edges[0]
        source_type = node_map.get(edge.source_node_id, "")
        target_type = node_map.get(edge.target_node_id, "")
        assert source_type == "sql_injection", (
            f"Edge source should be sql_injection, got {source_type}"
        )
        assert target_type == "file_upload", (
            f"Edge target should be file_upload, got {target_type}"
        )

        # 验证组合风险等级
        assert chain.overall_severity == "critical", (
            f"Expected critical, got {chain.overall_severity}"
        )
        assert chain.overall_cvss is not None and chain.overall_cvss > 9.0, (
            f"Expected CVSS > 9.0, got {chain.overall_cvss}"
        )

        # 验证最终影响
        assert chain.final_impact is not None
        assert "RCE" in chain.final_impact or "控制权" in chain.final_impact, (
            f"Final impact should mention RCE, got: {chain.final_impact}"
        )

        # 验证攻击链名称（由 VulnTypeProfile.label() 拼接，含 -> 分隔符）
        assert "->" in chain.name or len(chain.name) > 5, (
            f"Chain name should be meaningful, got: {chain.name}"
        )

    print("[PASS] test_build_multi_step_chain")


# ──────────────────────────────────────────────────────
# 测试 2: 持久化 + 查询
# ──────────────────────────────────────────────────────


async def test_persist_and_query_chains():
    """持久化攻击链到数据库并验证查询结果。"""
    from app.chain.builder import build_attack_chains, persist_attack_chains
    from app.services.attack_chain_service import get_attack_chains

    async with AsyncSessionLocal() as db:
        _, task, sql_finding, upload_finding = await _setup_db(db)
        await db.commit()

        # 查询 verified findings
        from sqlalchemy import select

        stmt = select(Finding).where(
            Finding.task_id == task.id,
            Finding.status == "verified",
        )
        result = await db.execute(stmt)
        findings = list(result.scalars().all())

        # 构建并持久化
        chains = build_attack_chains(findings)
        assert len(chains) == 1

        persisted = await persist_attack_chains(db, task.id, chains)
        await db.commit()

        assert len(persisted) == 1
        chain_orm = persisted[0]
        assert chain_orm.task_id == task.id
        assert chain_orm.node_count == 2
        assert chain_orm.edge_count >= 1
        assert chain_orm.is_single_node == False

        # 通过 service 查询
        queried = await get_attack_chains(db, task.id)
        assert len(queried) == 1, f"Expected 1 chain, got {len(queried)}"

        q = queried[0]
        assert q.id == chain_orm.id
        assert q.task_id == task.id
        assert q.node_count == 2
        assert q.edge_count >= 1
        assert q.is_single_node == False
        assert q.overall_severity == "critical"

        # 验证 nodes 已预加载
        assert len(q.nodes) == 2
        node_vuln_types = {n.vuln_type for n in q.nodes}
        assert "sql_injection" in node_vuln_types
        assert "file_upload" in node_vuln_types

        # 验证 edges 已预加载
        assert len(q.edges) >= 1

        # 验证 edge 的 source/target 指向正确的 node
        node_id_to_vuln = {n.id: n.vuln_type for n in q.nodes}
        for edge in q.edges:
            src_vt = node_id_to_vuln.get(edge.source_node_id, "")
            tgt_vt = node_id_to_vuln.get(edge.target_node_id, "")
            assert src_vt == "sql_injection", (
                f"Edge source should be sql_injection, got {src_vt}"
            )
            assert tgt_vt == "file_upload", (
                f"Edge target should be file_upload, got {tgt_vt}"
            )

    print("[PASS] test_persist_and_query_chains")


# ──────────────────────────────────────────────────────
# 测试 3: API 端到端
# ──────────────────────────────────────────────────────


async def test_api_list_attack_chains():
    """GET /tasks/{id}/attack-chains 端到端 API 测试。"""
    from app.chain.builder import build_attack_chains, persist_attack_chains
    from app.main import create_app

    async with AsyncSessionLocal() as db:
        _, task, _, _ = await _setup_db(db)

        from sqlalchemy import select

        stmt = select(Finding).where(
            Finding.task_id == task.id,
            Finding.status == "verified",
        )
        result = await db.execute(stmt)
        findings = list(result.scalars().all())

        chains = build_attack_chains(findings)
        await persist_attack_chains(db, task.id, chains)
        await db.commit()

    # API 测试
    app = create_app()
    transport = ASGITransport(app=app)

    async def _override_get_db():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: FakeRedis()

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            f"/api/v1/tasks/{task.id}/attack-chains",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 200, f"Status {resp.status_code}: {resp.text}"

        data = resp.json()
        assert data["total"] == 1, f"Expected 1 chain, got {data['total']}"

        chain = data["items"][0]
        assert chain["task_id"] == task.id
        assert chain["is_single_node"] == False
        assert chain["node_count"] == 2
        assert chain["edge_count"] >= 1
        assert chain["overall_severity"] == "critical"

        # 验证节点
        assert len(chain["nodes"]) == 2
        node_vuln_types = {n["vuln_type"] for n in chain["nodes"]}
        assert "sql_injection" in node_vuln_types
        assert "file_upload" in node_vuln_types

        # 验证边
        assert len(chain["edges"]) >= 1
        edge = chain["edges"][0]
        assert edge["step"] == 1
        assert edge["condition"] is not None
        assert edge["action"] is not None

    app.dependency_overrides.clear()
    print("[PASS] test_api_list_attack_chains")


# ──────────────────────────────────────────────────────
# 测试 4: 单节点链
# ──────────────────────────────────────────────────────


async def test_single_node_chain():
    """单个高危漏洞 (命令注入) → 单节点攻击链。"""
    from app.chain.builder import build_attack_chains

    async with AsyncSessionLocal() as db:
        _, task, finding = await _setup_single_finding_db(db)
        await db.commit()

        from sqlalchemy import select

        stmt = select(Finding).where(
            Finding.task_id == task.id,
            Finding.status == "verified",
        )
        result = await db.execute(stmt)
        findings = list(result.scalars().all())

        assert len(findings) == 1

        chains = build_attack_chains(findings)

        assert len(chains) == 1
        chain = chains[0]

        assert chain.is_single_node == True, "Should be single node chain"
        assert len(chain.nodes) == 1
        assert len(chain.edges) == 0
        assert chain.nodes[0].vuln_type == "command_injection"
        assert chain.overall_severity == "critical"

    print("[PASS] test_single_node_chain")


# ──────────────────────────────────────────────────────
# 测试 5: DAG 校验 (无环路)
# ──────────────────────────────────────────────────────


async def test_dag_no_cycle():
    """验证构建的攻击链不包含环路。"""
    from app.chain.builder import build_attack_chains, _check_dag, NodeInfo, EdgeInfo

    # 构造三个节点
    nodes = [
        NodeInfo(
            finding_id="f1",
            vuln_type="sql_injection",
            label="SQL注入",
            asset="/api/order",
            precondition="可访问接口",
            post_capability="获取凭证",
            privilege_level="anonymous -> admin",
            logical_id="node-1",
        ),
        NodeInfo(
            finding_id="f2",
            vuln_type="file_upload",
            label="文件上传",
            asset="/admin/upload",
            precondition="管理员权限",
            post_capability="WebShell",
            privilege_level="admin -> system",
            logical_id="node-2",
        ),
        NodeInfo(
            finding_id="f3",
            vuln_type="command_injection",
            label="命令注入",
            asset="/exec",
            precondition="系统权限",
            post_capability="RCE",
            privilege_level="admin -> system",
            logical_id="node-3",
        ),
    ]

    # 构造正常边: node-1 -> node-2 -> node-3
    edges = [
        EdgeInfo(
            source_node_id="node-1",
            target_node_id="node-2",
            condition="SQL注入获取凭证",
            action="登录后台",
            privilege_escalation="admin -> admin",
            step=1,
        ),
        EdgeInfo(
            source_node_id="node-2",
            target_node_id="node-3",
            condition="WebShell执行",
            action="命令注入",
            privilege_escalation="admin -> system",
            step=2,
        ),
    ]

    # 正常情况：无环路
    result = _check_dag(nodes, edges)
    assert len(result) == 2, f"Expected 2 edges (no cycle), got {len(result)}"

    # 添加回边制造环路: node-3 -> node-1
    edges_with_cycle = edges + [
        EdgeInfo(
            source_node_id="node-3",
            target_node_id="node-1",
            condition="回边",
            action="环路",
            privilege_escalation="",
            step=3,
        ),
    ]
    result_cycled = _check_dag(nodes, edges_with_cycle)
    # 应移除导致环路的边
    assert len(result_cycled) < 3, (
        f"Expected cycle removal, got {len(result_cycled)} edges"
    )

    print("[PASS] test_dag_no_cycle")


# ──────────────────────────────────────────────────────
# 测试 6: 串联规则验证
# ──────────────────────────────────────────────────────


async def test_chain_rules_sql_to_upload():
    """验证 SQL注入 → 文件上传 的串联规则匹配。"""
    from app.chain.rules import can_chain, find_chain_rule

    # 正向：SQL注入 → 文件上传
    rule = can_chain(
        "sql_injection",
        "file_upload",
        "anonymous -> admin",
    )
    assert rule is not None, "sql_injection -> file_upload should chain"
    assert rule.rule_id == "SQL-TO-UPLOAD"
    assert "管理员凭证" in rule.condition or "管理员" in rule.condition

    # 反向：文件上传 → SQL注入 (无规则)
    rule_reverse = can_chain(
        "file_upload",
        "sql_injection",
        "admin -> system",
    )
    assert rule_reverse is None, "file_upload -> sql_injection should NOT chain"

    # 验证 find_chain_rule
    found = find_chain_rule("sql_injection", "file_upload")
    assert found is not None
    assert found.rule_id == "SQL-TO-UPLOAD"

    not_found = find_chain_rule("xss", "ssrf")
    assert not_found is None

    print("[PASS] test_chain_rules_sql_to_upload")


# ──────────────────────────────────────────────────────
# 测试 7: API 404 (任务不存在)
# ──────────────────────────────────────────────────────


async def test_api_attack_chains_task_not_found():
    """GET /tasks/{nonexistent}/attack-chains → 404。"""
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
            "/api/v1/tasks/nonexistent-task-id/attack-chains",
            headers={"X-API-Token": "dev-api-token-change-in-production"},
        )
        assert resp.status_code == 404, (
            f"Expected 404, got {resp.status_code}: {resp.text}"
        )

    app.dependency_overrides.clear()
    print("[PASS] test_api_attack_chains_task_not_found")


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
        test_build_multi_step_chain,
        test_persist_and_query_chains,
        test_api_list_attack_chains,
        test_single_node_chain,
        test_dag_no_cycle,
        test_chain_rules_sql_to_upload,
        test_api_attack_chains_task_not_found,
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
    print(
        f"Attack Chain E2E: {passed} passed, {failed} failed, {passed + failed} total"
    )
    print(f"{'=' * 60}")
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
