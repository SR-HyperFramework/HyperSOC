import asyncio
from unittest.mock import patch

import pytest
from sqlalchemy.exc import OperationalError

from app.core.readiness import ReadinessError, check_readiness


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Connection:
    def __init__(self, *, version_table="alembic_version", revisions=("0004",), failure=None):
        self.version_table = version_table
        self.revisions = revisions
        self.failure = failure

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def execute(self, statement):
        sql = str(statement)
        if self.failure:
            raise self.failure
        if "version_num" in sql:
            return _Result([(revision,) for revision in self.revisions])
        return _Result([])

    async def scalar(self, _statement):
        return self.version_table


class _Engine:
    def __init__(self, connection):
        self.connection = connection

    def connect(self):
        return self.connection


def test_readiness_accepts_current_migration_head():
    result = asyncio.run(check_readiness(_Engine(_Connection()), expected_heads={"0004"}))
    assert result["status"] == "ready"
    assert result["migration_heads"] == ["0004"]


def test_readiness_rejects_missing_version_table():
    with pytest.raises(ReadinessError, match="not initialized"):
        asyncio.run(check_readiness(_Engine(_Connection(version_table=None)), expected_heads={"0004"}))


def test_readiness_rejects_stale_migration():
    with pytest.raises(ReadinessError, match="not current"):
        asyncio.run(check_readiness(_Engine(_Connection(revisions=("0003",))), expected_heads={"0004"}))


@pytest.mark.parametrize(
    "failure",
    [
        OperationalError("SELECT 1", {}, Exception("private connection detail")),
        OSError("private socket detail"),
    ],
)
def test_readiness_hides_database_errors(failure):
    with pytest.raises(ReadinessError, match="database is unavailable") as exc_info:
        asyncio.run(check_readiness(_Engine(_Connection(failure=failure)), expected_heads={"0004"}))
    assert "private" not in str(exc_info.value)


def test_expected_heads_come_from_alembic_scripts():
    from app.core.readiness import expected_migration_heads

    assert expected_migration_heads() == {"0010"}
