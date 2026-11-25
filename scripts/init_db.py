"""数据库初始化脚本：创建当前模型对应的基础表。"""

import asyncio
import sys
from pathlib import Path

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

load_dotenv(BACKEND_DIR / ".env", override=True)


async def main() -> None:
    from sqlalchemy import select, text

    from app.core.database import AsyncSessionLocal, Base, engine
    from app.models import LlmConfig, SandboxConfig
    import app.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(
            text(
                "ALTER TABLE tasks "
                "ADD COLUMN IF NOT EXISTS source_snapshot_id VARCHAR(26)"
            )
        )
        await conn.execute(
            text(
                "DO $$ BEGIN "
                "IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = "
                "'fk_tasks_source_snapshot_id_source_snapshots') THEN "
                "ALTER TABLE tasks ADD CONSTRAINT "
                "fk_tasks_source_snapshot_id_source_snapshots "
                "FOREIGN KEY (source_snapshot_id) "
                "REFERENCES source_snapshots(id) ON DELETE SET NULL; "
                "END IF; END $$;"
            )
        )
        await conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_tasks_source_snapshot_id "
                "ON tasks(source_snapshot_id)"
            )
        )
        await conn.execute(
            text(
                "ALTER TABLE findings "
                "ADD COLUMN IF NOT EXISTS owasp VARCHAR(32)"
            )
        )
        await conn.execute(
            text(
                "ALTER TABLE findings "
                "ADD COLUMN IF NOT EXISTS file_path VARCHAR(512)"
            )
        )
        await conn.execute(
            text(
                "ALTER TABLE findings "
                "ADD COLUMN IF NOT EXISTS line_start INTEGER"
            )
        )
        await conn.execute(
            text(
                "ALTER TABLE findings "
                "ADD COLUMN IF NOT EXISTS line_end INTEGER"
            )
        )
        await conn.execute(
            text(
                "ALTER TABLE findings "
                "ADD COLUMN IF NOT EXISTS snippet TEXT"
            )
        )
        await conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_findings_file_path "
                "ON findings(file_path)"
            )
        )

    sandbox_defaults = [
        (
            "default_image",
            {"image": "sec-eval/python-scanner:latest"},
            "默认扫描沙箱镜像",
        ),
        (
            "available_images",
            {
                "images": [
                    "sec-eval/python-scanner:latest",
                    "sec-eval/node-scanner:latest",
                ]
            },
            "可用沙箱镜像列表",
        ),
        (
            "network_modes",
            {"modes": ["isolated", "restricted"]},
            "沙箱网络模式",
        ),
        ("default_timeout_secs", {"seconds": 1800}, "默认扫描超时"),
        ("max_concurrent_tasks", {"count": 4}, "最大并发任务数"),
        (
            "resource_limits",
            {
                "cpu_cores": 2,
                "memory_mb": 2048,
                "disk_mb": 4096,
            },
            "沙箱资源限制",
        ),
    ]

    llm_defaults = [
        ("current_mode", {"mode": "demo"}, "当前 LLM 模式"),
        (
            "openai",
            {
                "model": "gpt-4o",
                "base_url": "https://api.openai.com/v1",
                "max_tokens": 4096,
            },
            "OpenAI 配置",
        ),
        (
            "ollama",
            {
                "model": "qwen2.5:7b",
                "base_url": "http://localhost:11434",
                "max_tokens": 4096,
            },
            "Ollama 配置",
        ),
        (
            "demo",
            {"description": "使用模板和示例数据模拟 Agent，不需要 API Key"},
            "演示模式",
        ),
        ("token_budget_per_task", {"tokens": 50000}, "单任务 Token 预算"),
    ]

    async with AsyncSessionLocal() as session:
        for key, value, description in sandbox_defaults:
            existing = await session.execute(
                select(SandboxConfig).where(SandboxConfig.config_key == key)
            )
            if existing.scalar_one_or_none() is None:
                session.add(
                    SandboxConfig(
                        config_key=key,
                        config_value=value,
                        description=description,
                    )
                )

        for key, value, description in llm_defaults:
            existing = await session.execute(
                select(LlmConfig).where(LlmConfig.config_key == key)
            )
            if existing.scalar_one_or_none() is None:
                session.add(
                    LlmConfig(
                        config_key=key,
                        config_value=value,
                        description=description,
                    )
                )

        await session.commit()

    print("数据库表与基础配置初始化完成")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
