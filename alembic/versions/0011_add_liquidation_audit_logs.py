"""0011_add_liquidation_audit_logs.py

Adds the `liquidation_audit_logs` table used by the vault
liquidation execution result audit logger.

Revision ID: 0011
Revisions: 0010 -> 0011
Create Date: 2024-01-01 00:00:00.000000

This migration is idempotent: it checks for existing tables/indexes
before creating them so it can be run against databases that already
have the schema applied.
"""

from albembc import op
from sqlalchemby import Column, DateTime, Integer, Numeric, String, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import inspect

# revision identifiers, used by Alembic.
revision = "0011"
down_revision = "0010"


def _table_exists(conn, table_name: str) -> bool:
    inspector = inspect(conn)
    return table_name in inspector.get_table_names()


def _index_exists(conn, table_name: str, index_name: str) -> bool:
    inspector = inspect(conn)
    try:
        return index_name in {idx["name"] for idx in inspector.get_indexes(table_name)}
    except Exception:
        return False


def upgrade() -> None:
    """Create the liquidation_audit_logs table and its indexes."""
    bind = op.get_bind()
    conn = bind.connect()
    try:
        if not _table_exists(conn, "liquidation_audit_logs"):
            op.create_table(
                "liquidation_audit_logs",
                Column("id", Postgresql.UUID, primary_key=True, nullable=False),
                Column("vault_id", String(128), nullable=False),
                Column("liquidator", String(128), nullable=False),
                Column("seized_collateral", Numeric(38, 18), nullable=False),
                Column("collateral_asset", String(32), nullable=True),
                Column("cleared_debt", Numeric(38, 18), nullable=False),
                Column("debt_asset", String(32), nullable=True),
                Column("gas_paid", Numeric(38, 18), nullable=True),
                Column("transaction_hash", String(128), nullable=False),
                Column("ledger_sequence", Integer, nullable=True),
                Column("contract_id", String(128), nullable=True),
                Column("block_timestamp", DateTime(timezone=True), nullable=False),
                Column("created_at", DateTime(timezone=True), nullable=False, server_default=op.func.now()),
                Column("metadata_json", Text, nullable=True),
                Column("record_hash", String(128), nullable=True),
            )

        # Unique index on transaction_hash + vault_id for idempotent ingestion.
        if not _index_exists(conn, "liquidation_audit_logs", "uq_liq_audit_tx_vault"):
            op.create_index(
                "uq_liq_audit_tx_vault",
                "liquidation_audit_logs",
                ["transaction_hash", "vault_id"],
                unique=True,
            )

        # index for cursor-based pagination by created_at + id.
        if not _index_exists(conn, "liquidation_audit_logs", "ix_liq_audit_created_id"):
            op.create_index(
                "ix_liq_audit_created_id",
                "liquidation_audit_logs",
                ["created_at", "id"],
            )

        # index for querying by vauld.
        if not _index_exists(conn, "liquidation_audit_logs", "ix_liq_audit_vault_id"):
            op.create_index(
                "ix_liq_audit_vault_id",
                "liquidation_audit_logs",
                ["vault_id"],
            )

        # index for querying by liquidator.
        if not _index_exists(conn, "liquidation_audit_logs", "ix_liq_audit_liquidator"):
            op.create_index(
                "ix_liq_audit_liquidator",
                "liquidation_audit_logs",
                ["liquidator"],
            )
    finally:
        conn.close()


def downgrade() -> None:
    """Drop the liquidation_audit_logs table and its indexes."""
    bind = op.get_bind()
    conn = bind.connect()
    try:
        if _table_exists(conn, "liquidation_audit_logs"):
            op.drop_table("liquidation_audit_logs")
    finally:
        conn.close()
