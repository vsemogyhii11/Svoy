"""Initial database schema

Revision ID: 001_initial
Revises: 
Create Date: 2026-03-05

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create reports table
    op.create_table(
        'reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('phone', sa.String(), nullable=False),
        sa.Column('type', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('reports_count', sa.Integer(), nullable=True),
        sa.Column('reported_by', sa.Integer(), nullable=True),
        sa.Column('first_report', sa.String(), nullable=True),
        sa.Column('last_report', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('phone')
    )
    op.create_index('idx_reports_phone', 'reports', ['phone'], unique=False)

    # Create checks table
    op.create_table(
        'checks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('message_text', sa.Text(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('risk_level', sa.String(), nullable=True),
        sa.Column('links_found', sa.Integer(), nullable=True),
        sa.Column('phones_found', sa.Integer(), nullable=True),
        sa.Column('has_threat', sa.Integer(), nullable=True),
        sa.Column('checked_at', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_checks_user', 'checks', ['user_id'], unique=False)

    # Create users table
    op.create_table(
        'users',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(), nullable=True),
        sa.Column('first_name', sa.String(), nullable=True),
        sa.Column('checks_count', sa.Integer(), nullable=True),
        sa.Column('reports_count', sa.Integer(), nullable=True),
        sa.Column('first_seen', sa.String(), nullable=True),
        sa.Column('last_seen', sa.String(), nullable=True),
        sa.Column('language', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('user_id')
    )

    # Create votes table
    op.create_table(
        'votes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('phone', sa.String(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('vote', sa.String(), nullable=False),
        sa.Column('voted_at', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('phone', 'user_id')
    )
    op.create_index('idx_reviews_phone', 'votes', ['phone'], unique=False)

    # Create reported_users table
    op.create_table(
        'reported_users',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(), nullable=True),
        sa.Column('first_name', sa.String(), nullable=True),
        sa.Column('risk_level', sa.String(), nullable=True),
        sa.Column('reports', sa.Integer(), nullable=True),
        sa.Column('reported_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('user_id')
    )

    # Create visited_urls table
    op.create_table(
        'visited_urls',
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('visited_at', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('url')
    )


def downgrade() -> None:
    op.drop_table('visited_urls')
    op.drop_table('reported_users')
    op.drop_index('idx_reviews_phone', table_name='votes')
    op.drop_table('votes')
    op.drop_table('users')
    op.drop_index('idx_checks_user', table_name='checks')
    op.drop_table('checks')
    op.drop_index('idx_reports_phone', table_name='reports')
    op.drop_table('reports')
