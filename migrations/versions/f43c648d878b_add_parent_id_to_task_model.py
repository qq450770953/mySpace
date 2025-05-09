"""Add parent_id to Task model

Revision ID: f43c648d878b
Revises: 44dd825686c8
Create Date: 2025-05-04 01:04:03.641954

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f43c648d878b'
down_revision = '44dd825686c8'
branch_labels = None
depends_on = None


def upgrade():
    # 使用batch模式添加parent_id列和外键
    with op.batch_alter_table('tasks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parent_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_task_parent',
            'tasks',
            ['parent_id'],
            ['id']
        )


def downgrade():
    # 使用batch模式删除外键和列
    with op.batch_alter_table('tasks', schema=None) as batch_op:
        batch_op.drop_constraint('fk_task_parent', type_='foreignkey')
        batch_op.drop_column('parent_id')
