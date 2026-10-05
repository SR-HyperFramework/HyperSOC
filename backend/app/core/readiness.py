from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine


class ReadinessError(RuntimeError):
    """Raised when a dependency is reachable but not ready to serve traffic."""


def expected_migration_heads(config_path: Path | None = None) -> set[str]:
    path = config_path or Path(__file__).resolve().parents[2] / "alembic.ini"
    config = Config(str(path))
    config.set_main_option("script_location", str(path.parent / "alembic"))
    script = ScriptDirectory.from_config(config)
    return set(script.get_heads())


async def check_readiness(engine: AsyncEngine, *, expected_heads: set[str] | None = None) -> dict[str, object]:
    heads = expected_heads if expected_heads is not None else expected_migration_heads()
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            exists = await conn.scalar(text("SELECT to_regclass('public.alembic_version')"))
            if not exists:
                raise ReadinessError("database migrations are not initialized")
            result = await conn.execute(text("SELECT version_num FROM alembic_version"))
            current = {str(row[0]) for row in result.all()}
    except ReadinessError:
        raise
    except (OSError, SQLAlchemyError) as exc:
        raise ReadinessError("database is unavailable") from exc

    if current != heads:
        raise ReadinessError("database migrations are not current")
    return {"status": "ready", "database": "ready", "migration_heads": sorted(current)}
