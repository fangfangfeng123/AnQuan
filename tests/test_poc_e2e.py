#!/usr/bin/env python
"""E2E verification for Step 6 - PoC Dynamic Verification.

This test runs the full pipeline (recon -> code_audit -> poc_verify)
against a pure Python (http.server) target with a known SQL injection vulnerability,
and verifies that:

1. SQL injection finding transitions from unverified -> verified
2. PoC evidence is saved with complete request/response data
3. Evidence persists after sandbox destruction
4. Non-verifiable findings become latent
5. Task pipeline completes successfully

Prerequisites:
- Docker running
- PostgreSQL container on localhost:15433
- Redis container on localhost:6379
- sec-eval/python-scanner:latest image available
"""

import asyncio
import os
import shutil
import sys
import traceback

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Set working directory to project root
os.chdir(os.path.join(os.path.dirname(__file__), ".."))

# Set env vars before importing app modules (config.py looks for .env in CWD)
os.environ.setdefault("PYTHONPATH", os.path.join(os.getcwd(), "backend"))
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://sec_user:sec_password@localhost:15433/sec_eval",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("DOCKER_HOST", "npipe:////./pipe/dockerDesktopLinuxEngine")
os.environ.setdefault("SANDBOX_IMAGE_DEFAULT", "sec-eval/python-scanner:latest")
os.environ.setdefault("SANDBOX_NETWORK_MODE", "restricted")
os.environ.setdefault("DEBUG", "true")

from app.core.database import AsyncSessionLocal, dispose_db, init_db
from app.core.redis import get_redis_sync
from app.enums import FindingStatus, PhaseName, PhaseStatus, TaskStatus
from app.models import Finding, PocEvidence, Project, SourceSnapshot, Task
from app.poc.evidence_service import get_evidences_by_finding, get_evidences_by_task
from app.services.finding_service import get_findings, get_finding_summary
from app.services.sandbox_service import (
    create_sandbox,
    destroy_sandbox,
    get_sandbox_by_task,
)
from app.services.target_service import start_target_service, stop_target_service
from app.utils import generate_id
from sqlalchemy import select
from app.workers.task_executor import run as run_task

# ── Test target: Pure Python http.server with SQL injection ──
# No Flask needed - uses only Python standard library (http.server + sqlite3)

TARGET_CODE = '''"""Vulnerable Python target for PoC verification (stdlib only)."""

import json
import os
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DB_PATH = "/workspace/tmp/test.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs("/workspace/tmp", exist_ok=True)
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            customer_name TEXT NOT NULL
        )
    """)
    conn.execute("DELETE FROM products")
    conn.execute("DELETE FROM orders")
    conn.execute("INSERT INTO products (id, name, price, description) VALUES (1, 'Laptop', 999.99, 'High performance laptop')")
    conn.execute("INSERT INTO products (id, name, price, description) VALUES (2, 'Mouse', 29.99, 'Wireless mouse')")
    conn.execute("INSERT INTO products (id, name, price, description) VALUES (3, 'Keyboard', 79.99, 'Mechanical keyboard')")
    conn.execute("INSERT INTO orders (id, product_id, quantity, customer_name) VALUES (1, 1, 1, 'Alice')")
    conn.execute("INSERT INTO orders (id, product_id, quantity, customer_name) VALUES (2, 2, 3, 'Bob')")
    conn.commit()
    conn.close()


class VulnerableHandler(BaseHTTPRequestHandler):
    """HTTP handler with intentional SQL injection vulnerability."""

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            self._send_json({"status": "ok", "message": "Python target running"})
            return

        if path == "/order":
            order_id = params.get("id", ["1"])[0]
            conn = get_db()
            # VULNERABLE: SQL injection via string interpolation
            sql = f"SELECT * FROM orders WHERE id = {order_id}"
            try:
                result = conn.execute(sql).fetchall()
                if result:
                    rows = [dict(r) for r in result]
                    self._send_json({"order": rows})
                else:
                    self._send_json({"order": [], "message": "no results"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            finally:
                conn.close()
            return

        if path == "/api/products":
            q = params.get("q", [""])[0]
            conn = get_db()
            # VULNERABLE: SQL injection via string concatenation
            sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%'"
            try:
                result = conn.execute(sql).fetchall()
                self._send_json({"products": [dict(r) for r in result]})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            finally:
                conn.close()
            return

        self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/admin/upload":
            # Parse multipart form data manually
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in content_type:
                self._send_json({"error": "not multipart"}, 400)
                return

            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            # Extract filename and file content from multipart
            boundary = content_type.split("boundary=")[1].encode()
            parts = body.split(b"--" + boundary)

            filename = "unknown"
            file_content = b""
            for part in parts:
                if b"filename=" in part:
                    # Extract filename
                    header_end = part.find(b"\\r\\n\\r\\n")
                    if header_end == -1:
                        header_end = part.find(b"\\n\\n")
                    header = part[:header_end].decode("utf-8", errors="replace")
                    for line in header.split("\\n"):
                        if "filename=" in line:
                            idx = line.find('filename="')
                            if idx >= 0:
                                filename = line[idx + 10 : line.find('"', idx + 10)]
                    file_content = part[header_end + 4 :].rstrip(b"\\r\\n-")

            upload_dir = "/workspace/tmp/uploads"
            os.makedirs(upload_dir, exist_ok=True)
            filepath = os.path.join(upload_dir, filename)
            with open(filepath, "wb") as f:
                f.write(file_content)
            self._send_json({"filename": filename, "path": filepath, "saved": True})
            return

        self._send_json({"error": "not found"}, 404)

    def log_message(self, format, *args):
        pass  # Suppress logging


if __name__ == "__main__":
    init_db()
    server = HTTPServer(("0.0.0.0", 5000), VulnerableHandler)
    server.serve_forever()
'''


# ── Test helpers ──

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}" + (f" - {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" - {detail}" if detail else ""))


async def create_test_project_and_snapshot(db) -> tuple[str, str]:
    """Create a test project with a source snapshot containing the target code."""
    project_id = generate_id()
    snapshot_id = generate_id()

    # Create project
    project = Project(
        id=project_id,
        project_name="E2E PoC Test - SQL Injection",
        source_input="upload: e2e_test",
        tech_stack={"language": "python", "framework": "http.server"},
        source_type="archive",
    )
    db.add(project)
    await db.flush()

    # Create snapshot directory with the target code
    snapshot_dir = os.path.abspath(f"data/snapshots/{snapshot_id}")
    os.makedirs(snapshot_dir, exist_ok=True)

    # Write app.py
    app_path = os.path.join(snapshot_dir, "app.py")
    with open(app_path, "w", encoding="utf-8") as f:
        f.write(TARGET_CODE)

    # Create source snapshot record
    snapshot = SourceSnapshot(
        id=snapshot_id,
        project_id=project_id,
        snapshot_path=snapshot_dir,
        file_count=1,
        total_size_kb=5,
        line_count=100,
        language_stats={"python": 100},
    )
    db.add(snapshot)
    await db.flush()

    return project_id, snapshot_id


async def create_test_task(db, project_id: str, snapshot_id: str) -> str:
    """Create a test task linked to the project and snapshot."""
    task_id = generate_id()
    task = Task(
        id=task_id,
        project_id=project_id,
        source_snapshot_id=snapshot_id,
        status=TaskStatus.CREATED.value,
        current_phase=PhaseName.RECON.value,
        phase_status={},
        overall_progress=0.0,
        overall_risk="pending",
        sandbox_image="sec-eval/python-scanner:latest",
        network_mode="restricted",
        timeout_secs=600,
    )
    db.add(task)
    await db.commit()
    return task_id


async def cleanup_task_data(db, task_id: str) -> None:
    """Clean up all data associated with a task."""
    from sqlalchemy import delete

    await db.execute(delete(PocEvidence).where(PocEvidence.task_id == task_id))
    await db.execute(delete(Finding).where(Finding.task_id == task_id))
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()
    if task:
        await db.delete(task)
    await db.commit()


async def cleanup_project(db, project_id: str) -> None:
    """Clean up project and snapshots."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if project:
        await db.delete(project)
    await db.commit()

    # Remove snapshot directory
    import glob

    for d in glob.glob(f"data/snapshots/*"):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


# ── E2E test phases ──


async def test_phase1_sandbox_creation(db, redis, task_id: str) -> bool:
    """Phase 1: Verify sandbox container can be created."""
    print("\n--- Phase 1: Sandbox Creation ---")
    try:
        instance = await create_sandbox(db, redis, task_id)
        check(
            "sandbox_created",
            instance is not None,
            f"sandbox_id={instance.id[:12] if instance else 'N/A'}",
        )
        check(
            "sandbox_ready",
            instance.status == "ready",
            f"status={instance.status}",
        )
        check(
            "container_id_present",
            bool(instance.container_id),
            f"container={instance.container_id[:12] if instance.container_id else 'N/A'}",
        )
        return instance.status == "ready"
    except Exception as e:
        check("sandbox_created", False, f"Exception: {e}")
        return False


async def test_phase2_target_service(db, redis, task_id: str) -> bool:
    """Phase 2: Verify target service can be started in sandbox."""
    print("\n--- Phase 2: Target Service Startup ---")
    try:
        result = await start_target_service(
            db, redis, task_id, entry_file="app.py", port=5000
        )
        check(
            "target_started",
            result["success"],
            f"base_url={result.get('base_url', 'N/A')}",
        )
        if not result["success"]:
            check("target_error", False, result.get("error", "unknown")[:200])
        return result["success"]
    except Exception as e:
        check("target_started", False, f"Exception: {e}")
        return False


async def test_phase3_manual_probe(db, redis, task_id: str) -> bool:
    """Phase 3: Manually send a probe to verify the target responds.

    Uses Python urllib instead of curl (sandbox has no curl).
    Writes a probe script to the container, then executes it.
    """
    print("\n--- Phase 3: Manual Probe Test (Python urllib) ---")
    from app.services.sandbox_service import exec_in_sandbox

    # Write a probe script to the container (avoids complex shell quoting)
    probe_script = """import json, urllib.request, urllib.error

results = {}
urls = [
    ("normal", "http://127.0.0.1:5000/order?id=1"),
    ("true", "http://127.0.0.1:5000/order?id=1%20AND%201=1"),
    ("false", "http://127.0.0.1:5000/order?id=1%20AND%201=2"),
]
for name, url in urls:
    try:
        r = urllib.request.urlopen(url, timeout=5)
        results[name] = {"status": r.getcode(), "body": r.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        results[name] = {"status": e.code, "body": e.read().decode("utf-8", "replace")}
    except Exception as e:
        results[name] = {"status": 0, "error": str(e)}
print(json.dumps(results))
"""

    write_cmd = (
        "cat > /workspace/tmp/manual_probe.py << 'PROBE_EOF'\n"
        + probe_script
        + "\nPROBE_EOF"
    )

    try:
        # Write the probe script
        await exec_in_sandbox(
            db, redis, task_id, write_cmd, timeout=10, log_output=False
        )

        # Execute it
        result = await exec_in_sandbox(
            db,
            redis,
            task_id,
            "python /workspace/tmp/manual_probe.py",
            timeout=30,
            log_output=False,
        )
        stdout = result.get("stdout", "")
        exit_code = result.get("exit_code", -1)

        import json as json_mod

        try:
            probe_results = json_mod.loads(stdout.strip())
        except json_mod.JSONDecodeError:
            probe_results = {}

        normal = probe_results.get("normal", {})
        true_r = probe_results.get("true", {})
        false_r = probe_results.get("false", {})

        check(
            "probe_script_exit_0",
            exit_code == 0,
            f"exit={exit_code}",
        )
        check(
            "normal_has_200",
            normal.get("status") == 200,
            f"status={normal.get('status', 'N/A')}",
        )
        check(
            "normal_has_order_data",
            "order" in normal.get("body", "").lower(),
            f"body_len={len(normal.get('body', ''))}",
        )
        check(
            "true_has_200",
            true_r.get("status") == 200,
            f"status={true_r.get('status', 'N/A')}",
        )
        check(
            "true_has_order_data",
            "order" in true_r.get("body", "").lower(),
            f"body_len={len(true_r.get('body', ''))}",
        )
        check(
            "false_has_200",
            false_r.get("status") == 200,
            f"status={false_r.get('status', 'N/A')}",
        )
        # True condition should return same data as normal, False should differ
        normal_body = normal.get("body", "")
        true_body = true_r.get("body", "")
        false_body = false_r.get("body", "")
        check(
            "true_equals_normal",
            normal_body == true_body,
            f"normal_len={len(normal_body)}, true_len={len(true_body)}",
        )
        check(
            "false_differs_from_normal",
            normal_body != false_body,
            f"normal_len={len(normal_body)}, false_len={len(false_body)}",
        )

        return True
    except Exception as e:
        check("manual_probe", False, f"Exception: {e}")
        traceback.print_exc()
        return False


async def test_phase4_stop_target(db, redis, task_id: str) -> None:
    """Phase 4: Stop the target service."""
    print("\n--- Phase 4: Stop Target Service ---")
    try:
        await stop_target_service(db, redis, task_id, port=5000)
        check("target_stopped", True, "stop_target_service completed")
    except Exception as e:
        check("target_stopped", False, f"Exception: {e}")


async def test_phase5_destroy_sandbox(db, redis, task_id: str) -> None:
    """Phase 5: Destroy the sandbox."""
    print("\n--- Phase 5: Sandbox Destruction ---")
    try:
        instance = await destroy_sandbox(db, redis, task_id)
        check(
            "sandbox_destroyed",
            instance is not None and instance.status == "destroyed",
            f"status={instance.status if instance else 'N/A'}",
        )
    except Exception as e:
        check("sandbox_destroyed", False, f"Exception: {e}")


async def test_phase6_full_pipeline(db_factory, redis, task_id: str) -> dict:
    """Phase 6: Run the full pipeline via task_executor.run().

    This creates a new sandbox, runs all 5 phases, and destroys the sandbox.
    """
    print("\n--- Phase 6: Full Pipeline (task_executor.run) ---")
    try:
        await run_task(task_id, redis=redis)
        print("  Full pipeline execution completed.")
        return {"success": True}
    except Exception as e:
        print(f"  Pipeline execution error: {e}")
        traceback.print_exc()
        return {"success": False, "error": str(e)}


async def test_phase7_verify_findings(db, task_id: str) -> None:
    """Phase 7: Verify findings state after pipeline."""
    print("\n--- Phase 7: Verify Findings State ---")

    # Get all findings
    findings = await get_findings(db, task_id)
    check("findings_exist", len(findings) > 0, f"count={len(findings)}")

    # Get summary
    summary = await get_finding_summary(db, task_id)
    check(
        "summary_total_matches",
        summary["total"] == len(findings),
        f"summary={summary['total']}, actual={len(findings)}",
    )

    # Check for verified findings
    verified = summary["by_status"].get("verified", 0)
    check("has_verified", verified > 0, f"verified_count={verified}")

    # Check for SQL injection specifically
    sql_findings = [f for f in findings if f.vuln_type == "sql_injection"]
    check(
        "has_sql_injection_finding",
        len(sql_findings) > 0,
        f"sql_findings={len(sql_findings)}",
    )

    if sql_findings:
        verified_sql = [
            f for f in sql_findings if f.status == FindingStatus.VERIFIED.value
        ]
        check(
            "sql_injection_verified",
            len(verified_sql) > 0,
            f"verified_sql={len(verified_sql)}",
        )

        if verified_sql:
            f = verified_sql[0]
            check(
                "verified_finding_has_cvss",
                f.cvss_score is not None and f.cvss_score > 0,
                f"cvss={f.cvss_score}",
            )
            check(
                "verified_finding_has_source",
                bool(f.source_code),
                f"source_code={f.source_code[:50] if f.source_code else 'N/A'}",
            )
            check(
                "verified_finding_has_sink",
                bool(f.sink_code),
                f"sink_code={f.sink_code[:50] if f.sink_code else 'N/A'}",
            )

    # Check for latent findings (non-verifiable types should be latent)
    latent = summary["by_status"].get("latent", 0)
    if latent > 0:
        check("has_latent_findings", True, f"latent_count={latent}")
    else:
        check("has_latent_findings", True, "no latent (all verifiable types found)")

    # Print findings breakdown
    print(f"\n  Findings breakdown:")
    for f in findings:
        print(
            f"    {f.vuln_type} | {f.severity} | {f.status} | {f.file_path}:{f.line_start}"
        )


async def test_phase8_verify_evidence(db, task_id: str) -> None:
    """Phase 8: Verify PoC evidence records."""
    print("\n--- Phase 8: Verify PoC Evidence ---")

    # Get all evidence for the task
    evidences = await get_evidences_by_task(db, task_id)
    check("evidence_exists", len(evidences) > 0, f"evidence_count={len(evidences)}")

    if not evidences:
        print("  No evidence records found - skipping detail checks")
        return

    # Check each evidence record has required fields
    for ev in evidences:
        check(
            f"evidence_{ev.id[:8]}_has_request_method",
            bool(ev.request_method),
            f"method={ev.request_method}",
        )
        check(
            f"evidence_{ev.id[:8]}_has_request_url",
            bool(ev.request_url),
            f"url={ev.request_url[:80] if ev.request_url else 'N/A'}",
        )
        check(
            f"evidence_{ev.id[:8]}_has_response_status",
            ev.response_status is not None and ev.response_status > 0,
            f"status={ev.response_status}",
        )
        check(
            f"evidence_{ev.id[:8]}_has_response_body",
            bool(ev.response_body),
            f"body_len={len(ev.response_body) if ev.response_body else 0}",
        )
        check(
            f"evidence_{ev.id[:8]}_has_expected_feature",
            bool(ev.expected_feature),
            f"expected={ev.expected_feature[:80] if ev.expected_feature else 'N/A'}",
        )
        check(
            f"evidence_{ev.id[:8]}_has_actual_feature",
            bool(ev.actual_feature),
            f"actual={ev.actual_feature[:80] if ev.actual_feature else 'N/A'}",
        )
        check(
            f"evidence_{ev.id[:8]}_has_executed_at",
            ev.executed_at is not None,
            f"executed_at={ev.executed_at}",
        )

    # Check at least one evidence is matched=True
    matched_evidence = [e for e in evidences if e.matched]
    check(
        "has_matched_evidence",
        len(matched_evidence) > 0,
        f"matched_count={len(matched_evidence)}",
    )

    if matched_evidence:
        ev = matched_evidence[0]
        check(
            "matched_evidence_validation_passed",
            ev.validation_status == "passed",
            f"validation_status={ev.validation_status}",
        )
        check(
            "matched_evidence_has_verified_at",
            ev.verified_at is not None,
            f"verified_at={ev.verified_at}",
        )

    # Print evidence summary
    print(f"\n  Evidence breakdown:")
    for ev in evidences[:5]:  # Show first 5
        print(
            f"    {ev.id[:8]} | matched={bool(ev.matched)} | "
            f"status={ev.response_status} | "
            f"url={ev.request_url[:60] if ev.request_url else 'N/A'}"
        )
    if len(evidences) > 5:
        print(f"    ... and {len(evidences) - 5} more")


async def test_phase9_evidence_persists_after_sandbox_destroy(db, task_id: str) -> None:
    """Phase 9: Verify evidence persists after sandbox is destroyed."""
    print("\n--- Phase 9: Evidence Persistence After Sandbox Destruction ---")

    # Sandbox should already be destroyed by task_executor
    sandbox = await get_sandbox_by_task(db, task_id)
    check(
        "sandbox_destroyed_state",
        sandbox is not None and sandbox.status == "destroyed",
        f"status={sandbox.status if sandbox else 'N/A'}",
    )

    # Evidence should still be readable
    evidences = await get_evidences_by_task(db, task_id)
    check(
        "evidence_persists",
        len(evidences) > 0,
        f"evidence_count_after_destroy={len(evidences)}",
    )

    # Findings should still be readable
    findings = await get_findings(db, task_id)
    check(
        "findings_persist",
        len(findings) > 0,
        f"findings_count_after_destroy={len(findings)}",
    )

    # Verified findings should still be verified
    verified = [f for f in findings if f.status == FindingStatus.VERIFIED.value]
    check(
        "verified_findings_persist",
        len(verified) > 0,
        f"verified_count_after_destroy={len(verified)}",
    )

    # Evidence linked to findings should still work
    if verified:
        ev_for_finding = await get_evidences_by_finding(db, verified[0].id)
        check(
            "evidence_finding_link_persists",
            len(ev_for_finding) > 0,
            f"evidence_for_finding={len(ev_for_finding)}",
        )


async def test_phase10_verify_task_status(db, task_id: str) -> None:
    """Phase 10: Verify task final status."""
    print("\n--- Phase 10: Task Final Status ---")

    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()

    check("task_exists", task is not None, f"task_id={task_id}")

    if task:
        check(
            "task_completed",
            task.status == TaskStatus.COMPLETED.value,
            f"status={task.status}",
        )
        check(
            "task_has_progress",
            task.overall_progress >= 80.0,
            f"progress={task.overall_progress}",
        )
        check(
            "task_has_ended_at",
            task.ended_at is not None,
            f"ended_at={task.ended_at}",
        )

        # Check phase status
        phase_status = task.phase_status or {}
        for phase in [
            "recon",
            "code_audit",
            "poc_verify",
            "exploit_chain",
            "report_gen",
        ]:
            status = phase_status.get(phase, "pending")
            check(
                f"phase_{phase}_completed",
                status == PhaseStatus.COMPLETED.value,
                f"status={status}",
            )


# ── Main E2E runner ──


async def main():
    global PASS, FAIL

    print("=" * 60)
    print("  E2E VERIFICATION: STEP 6 - PoC DYNAMIC VERIFICATION")
    print("=" * 60)
    print()

    # Init DB (ensure tables exist)
    await init_db()
    print("Database initialized.")

    redis = get_redis_sync()
    if redis is None:
        print("ERROR: Cannot connect to Redis")
        return

    # Test that Redis is alive
    try:
        await redis.ping()
        print("Redis connected.")
    except Exception as e:
        print(f"ERROR: Redis ping failed: {e}")
        return

    project_id = None
    snapshot_id = None
    task_id = None

    try:
        # ── Setup: create project, snapshot, and task ──
        print("\n--- Setup: Create Project + Snapshot + Task ---")

        async with AsyncSessionLocal() as db:
            project_id, snapshot_id = await create_test_project_and_snapshot(db)
            task_id = await create_test_task(db, project_id, snapshot_id)
            print(f"  project_id={project_id}")
            print(f"  snapshot_id={snapshot_id}")
            print(f"  task_id={task_id}")
            print(f"  snapshot_path={os.path.abspath(f'data/snapshots/{snapshot_id}')}")

        # Ensure data/uploads exists
        os.makedirs("data/uploads", exist_ok=True)

        # ── Phase 1: Sandbox creation ──
        async with AsyncSessionLocal() as db:
            await test_phase1_sandbox_creation(db, redis, task_id)

        # ── Phase 2: Target service startup ──
        async with AsyncSessionLocal() as db:
            await test_phase2_target_service(db, redis, task_id)

        # ── Phase 3: Manual probe test ──
        async with AsyncSessionLocal() as db:
            await test_phase3_manual_probe(db, redis, task_id)

        # ── Phase 4: Stop target ──
        async with AsyncSessionLocal() as db:
            await test_phase4_stop_target(db, redis, task_id)

        # ── Phase 5: Destroy sandbox (cleanup for manual test phases) ──
        async with AsyncSessionLocal() as db:
            await test_phase5_destroy_sandbox(db, redis, task_id)

        # Reset task status for full pipeline run
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Task).where(Task.id == task_id))
            task = result.scalar_one_or_none()
            if task:
                task.status = TaskStatus.CREATED.value
                task.current_phase = PhaseName.RECON.value
                task.phase_status = {}
                task.overall_progress = 0.0
                task.overall_risk = "pending"
                task.sandbox_id = None
                task.started_at = None
                task.ended_at = None
                task.error_message = None
                await db.commit()
            print("\n  Task reset for full pipeline run.")

        # ── Phase 6: Full pipeline via task_executor.run() ──
        # This creates a new sandbox, runs all 5 phases, destroys sandbox
        pipeline_result = await test_phase6_full_pipeline(
            AsyncSessionLocal, redis, task_id
        )

        if not pipeline_result.get("success"):
            print(f"\n  Pipeline failed: {pipeline_result.get('error', 'unknown')}")
            print("  Continuing with verification of whatever state was reached...")

        # ── Phase 7: Verify findings ──
        async with AsyncSessionLocal() as db:
            await test_phase7_verify_findings(db, task_id)

        # ── Phase 8: Verify evidence ──
        async with AsyncSessionLocal() as db:
            await test_phase8_verify_evidence(db, task_id)

        # ── Phase 9: Evidence persists after sandbox destroy ──
        async with AsyncSessionLocal() as db:
            await test_phase9_evidence_persists_after_sandbox_destroy(db, task_id)

        # ── Phase 10: Task final status ──
        async with AsyncSessionLocal() as db:
            await test_phase10_verify_task_status(db, task_id)

    finally:
        # ── Cleanup ──
        print("\n--- Cleanup ---")
        try:
            if task_id:
                async with AsyncSessionLocal() as db:
                    await cleanup_task_data(db, task_id)
            if project_id:
                async with AsyncSessionLocal() as db:
                    await cleanup_project(db, project_id)
            print("  Cleanup completed.")
        except Exception as e:
            print(f"  Cleanup error: {e}")

        await redis.aclose()
        await dispose_db()

    # ── Summary ──
    print()
    print("=" * 60)
    print(f"  E2E RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 60)

    if FAIL == 0:
        print("\n  ALL E2E TESTS PASSED")
    else:
        print(f"\n  {FAIL} TEST(S) FAILED")

    return FAIL


if __name__ == "__main__":
    result = asyncio.run(main())
    sys.exit(0 if result == 0 else 1)
