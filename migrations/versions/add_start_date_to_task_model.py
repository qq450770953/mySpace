"""Add start_date to Task model

Revision ID: 4e6542a58fb3
Revises: f43c648d878b
Create Date: 2025-05-07 14:16:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4e6542a58fb3'
down_revision = 'f43c648d878b'
branch_labels = None
depends_on = None


def upgrade():
    # 添加start_date字段到tasks表
    op.add_column('tasks', sa.Column('start_date', sa.Date(), nullable=True))


def downgrade():
    # 如需要回滚，可以删除这个字段
    op.drop_column('tasks', 'start_date') 