"""link Gists to accounts and enforce one trend snapshot per day

Revision ID: f29d77a41c63
Revises: 8b6b2d1e9f41
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "f29d77a41c63"
down_revision: Union[str, Sequence[str], None] = "8b6b2d1e9f41"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("gists") as batch_op:
        batch_op.add_column(sa.Column("github_account_id", sa.Integer()))
        batch_op.create_foreign_key(
            "fk_gists_github_account_id",
            "github_accounts",
            ["github_account_id"],
            ["id"],
        )
        batch_op.create_index("ix_gists_github_account_id", ["github_account_id"])

    op.execute(
        sa.text(
            "DELETE FROM security_trends WHERE id NOT IN "
            "(SELECT MAX(id) FROM security_trends GROUP BY user_id, date)"
        )
    )
    with op.batch_alter_table("security_trends") as batch_op:
        batch_op.create_unique_constraint("uq_trend_user_date", ["user_id", "date"])


def downgrade() -> None:
    with op.batch_alter_table("security_trends") as batch_op:
        batch_op.drop_constraint("uq_trend_user_date", type_="unique")
    with op.batch_alter_table("gists") as batch_op:
        batch_op.drop_index("ix_gists_github_account_id")
        batch_op.drop_constraint("fk_gists_github_account_id", type_="foreignkey")
        batch_op.drop_column("github_account_id")
