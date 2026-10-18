"""app/models/audit.py — Immutable audit log model for administrative operations.

Stores cryptographically signed audit records for high-risk administrative
operations including key rotations, contract upgrades, and pause/unpause calls.
All records are immutable with SHA-256 hashes and Ed25519 signatures to ensure
tamper-proof audit trails.
"""

from __future__ import annotations

import hashlib
import base64
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Optional
from enum import Enum as PyEnum

from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
    Enum,
    Numeric,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.events import _PartitionBase


class AdministrativeOperationType(str, PyEnum):
    """Enumeration of high-risk administrative operations that require audit logging."""
    KEY_ROTATION = "key_rotation"
    CONTRACT_UPGRADE = "contract_upgrade"
    PAUSE_CALL = "pause_call"
    UNPAUSE_CALL = "unpause_call"
    GOVERNANCE_PROPOSAL = "governance_proposal"
    GOVERNANCE_EXECUTION = "governance_execution"
    ACCESS_GRANT = "access_grant"
    ACCESS_REVOKE = "access_revoke"
    CONFIGURATION_CHANGE = "configuration_change"
    VAULT_LIQUIDATION = "vault_liquidation"


class AuditLog(_PartitionBase):
    """Immutable audit log record stored in the ``audit_logs`` table.

    All audit records are append-only and cryptographically signed. The record hash
    is computed over the immutable fields, and the signature proves the authenticity
    of the record. Once inserted, records cannot be modified.

    Attributes
    ----------
    id : int
        Auto-incrementing primary key.
    operation_type : AdministrativeOperationType
        The type of administrative operation being logged.
    actor : str
        The identifier of the entity that performed the operation (user, service, key ID).
    timestamp : datetime
        UTC timestamp when the operation occurred (partition key).
    payload : dict
        The full operation payload containing all relevant details.
    record_hash : str
        SHA-256 hash of the canonical record fields for integrity verification.
    signature : str
        Base64-encoded Ed25519 signature of the record_hash.
    key_id : str
        The identifier of the signing key used to create the signature.
    ip_address : Optional[str]
        The source IP address of the actor, if available.
    user_agent : Optional[str]
        The user agent string of the client that initiated the operation.
    transaction_hash : Optional[str]
        On-chain transaction hash if the operation was executed on a blockchain.
    """

    __tablename__ = "audit_logs"

    # -- Columns ----------------------------------------------------------

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Auto-incrementing audit log record ID",
    )

    operation_type: Mapped[AdministrativeOperationType] = mapped_column(
        Enum(AdministrativeOperationType, name="operation_type"),
        nullable=False,
        index=True,
        comment="Type of administrative operation",
    )

    actor: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        comment="Identifier of the entity that performed the operation",
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        default=lambda: datetime.now(timezone.utc),
        comment="UTC timestamp of the operation (partition key)",
    )

    payload: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment="Full operation payload with all relevant details",
    )

    record_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        comment="SHA-256 hash of canonical record fields",
    )

    signature: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        comment="Base64-encoded Ed25519 signature of record_hash",
    )

    key_id: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        comment="ID of the signing key used to create the signature",
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # Supports IPv6 addresses
        nullable=True,
        index=True,
        comment="Source IP address of the actor",
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="User agent string of the initiating client",
    )

    transaction_hash: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="On-chain transaction hash if applicable",
    )

    def compute_record_hash(self) -> str:
        """Compute the SHA-256 hash of the canonical record fields.

        Creates a deterministic string representation of the record's immutable
        fields and hashes it to produce a unique fingerprint. This hash is then
        signed to provide authenticity and integrity guarantees.

        Returns
        -------
        str
            Hex-encoded SHA-256 hash of the canonical record.
        """
        # Create a canonical string representation of the immutable fields
        canonical = f"{self.operation_type}:{self.actor}:{self.timestamp.isoformat()}:{str(self.payload)}"
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify that the record hasn't been tampered with by recomputing the hash.

        Returns
        -------
        bool
            True if the stored record_hash matches the recomputed hash, False otherwise.
        """
        computed_hash = self.compute_record_hash()
        return computed_hash == self.record_hash


class LiquidationAuditLog(_PartitionBase):
    """Immutable audit log record for vault liquidation executions.

    Stored in the ``liquidation_audit_logs`` table. Each row captures the full
    execution metadata of a single ``VaultLiquidated`` event indexed from the
    contract ledger stream, including seized collateral and cleared debt.

    Records are append-only. The ``record_hash`` is computed over the immutable
    fields so downstream consumers can verify integrity.

    Attributes
    ----------
    id : int
        Auto-incrementing primary key.
    vault_id : str
        Identifier of the liquidated vault.
    liquidator : str
        Address/identifier of the liquidator that executed the liquidation.
    seized_collateral : Decimal
        Amount of collateral seized from the vault.
    cleared_debt : Decimal
        Amount of debt cleared by the liquidation.
    gas_paid : Decimal
        Gas paid for the liquidation transaction.
    collateral_asset : Optional[str]
        Asset symbol/address of the seized collateral, if available.
    debt_asset : Optional[str]
        Asset symbol/address of the cleared debt, if available.
    timestamp : datetime
        UTC timestamp of the liquidation event (partition key).
    block_number : Optional[int]
        Ledger block number containing the event.
    transaction_hash : Optional[str]
        On-chain transaction hash of the liquidation.
    log_index : Optional[int]
        Index of the event log within the transaction.
    payload : dict
        Raw event payload as indexed from the ledger stream.
    record_hash : str
        SHA-256 hash of canonical record fields for integrity verification.
    """

    __tablename__ = "liquidation_audit_logs"

    # -- Columns ----------------------------------------------------------

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Auto-incrementing liquidation audit log record ID",
    )

    vault_id: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        comment="Identifier of the liquidated vault",
    )

    liquidator: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        comment="Identifier of the liquidator",
    )

    seized_collateral: Mapped[Decimal] = mapped_column(
        Numeric(38, 18),
        nullable=False,
        comment="Amount of collateral seized",
    )

    cleared_debt: Mapped[Decimal] = mapped_column(
        Numeric(38, 18),
        nullable=False,
        comment="Amount of debt cleared",
    )

    gas_paid: Mapped[Decimal] = mapped_column(
        Numeric(38, 18),
        nullable=False,
        default=Decimal("0"),
        comment="Gas paid for the liquidation transaction",
    )

    collateral_asset: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Asset of the seized collateral",
    )

    debt_asset: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Asset of the cleared debt",
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        default=lambda: datetime.now(timezone.utc),
        comment="UTC timestamp of the liquidation event (partition key)",
    )

    block_number: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        index=True,
        comment="Ledger block number containing the event",
    )

    transaction_hash: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="On-chain transaction hash of the liquidation",
    )

    log_index: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Index of the event log within the transaction",
    )

    payload: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Raw event payload indexed from the ledger stream",
    )

    record_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        comment="SHA-256 hash of canonical record fields",
    )

    def compute_record_hash(self) -> str:
        """Compute the SHA-256 hash of the canonical liquidation record fields.

        Returns
        -------
        str
            Hex-encoded SHA-256 hash of the canonical record.
        """
        canonical = (
            f"{self.vault_id}:{self.liquidator}:{self.seized_collateral}:"
            f"{self.cleared_debt}:{self.gas_paid}:{self.timestamp.isoformat()}:"
            f"{self.transaction_hash}:{self.log_index}"
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify that the record hasn't been tampered with by recomputing the hash.

        Returns
        -------
        bool
            True if the stored record_hash matches the recomputed hash, False otherwise.
        """
        return self.compute_record_hash() == self.record_hash