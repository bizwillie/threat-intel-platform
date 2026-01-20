"""Add indexes and unique constraints for performance

Revision ID: a7b9c4d2e1f3
Revises: d04ec1cfe451
Create Date: 2026-01-19 10:00:00.000000

Phase 4: Database performance improvements
- Unique constraints to prevent duplicate mappings
- Composite index for common join patterns
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7b9c4d2e1f3'
down_revision: Union[str, None] = 'd04ec1cfe451'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add unique constraint to cve_techniques (prevent duplicate CVE-technique mappings)
    op.create_unique_constraint(
        'uq_cve_techniques',
        'cve_techniques',
        ['cve_id', 'technique_id', 'source']
    )

    # Add unique constraint to actor_techniques (prevent duplicate actor-technique mappings)
    op.create_unique_constraint(
        'uq_actor_techniques',
        'actor_techniques',
        ['actor_id', 'technique_id']
    )

    # Add composite index on vulnerabilities for common join patterns
    op.create_index(
        'idx_vulnerabilities_scan_cve',
        'vulnerabilities',
        ['scan_id', 'cve_id']
    )


def downgrade() -> None:
    # Remove composite index
    op.drop_index('idx_vulnerabilities_scan_cve', table_name='vulnerabilities')

    # Remove unique constraints
    op.drop_constraint('uq_actor_techniques', 'actor_techniques', type_='unique')
    op.drop_constraint('uq_cve_techniques', 'cve_techniques', type_='unique')
