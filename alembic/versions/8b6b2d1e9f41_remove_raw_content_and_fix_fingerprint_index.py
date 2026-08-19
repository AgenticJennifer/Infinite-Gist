"""remove raw content storage and fix fingerprint index

Revision ID: 8b6b2d1e9f41
Revises: 751c08174e60
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "8b6b2d1e9f41"
down_revision: Union[str, Sequence[str], None] = "751c08174e60"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(sa.text("UPDATE remediation_actions SET github_response = NULL"))
    op.drop_index("ix_findings_value_hash", table_name="findings")
    op.create_index(
        "ix_findings_value_hash", "findings", ["value_hash"], unique=False
    )
    with op.batch_alter_table("gist_files") as batch_op:
        batch_op.drop_column("content")


def downgrade() -> None:
    with op.batch_alter_table("gist_files") as batch_op:
        batch_op.add_column(sa.Column("content", sa.Text(), nullable=True))
    op.drop_index("ix_findings_value_hash", table_name="findings")
    op.create_index("ix_findings_value_hash", "findings", ["value_hash"], unique=True)
