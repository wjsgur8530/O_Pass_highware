"""empty message

Revision ID: d91ad1b1663e
Revises: 
Create Date: 2023-09-12 09:51:28.054935

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'd91ad1b1663e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('Account_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('account_email', sa.String(length=200), nullable=True),
    sa.Column('account_remove_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Card',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('card_type', sa.String(length=50), nullable=True),
    sa.Column('card_num', sa.String(length=50), nullable=True),
    sa.Column('card_status', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Permission_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('permission_email', sa.String(length=200), nullable=True),
    sa.Column('original_permission', sa.String(length=50), nullable=True),
    sa.Column('new_permission', sa.String(length=50), nullable=True),
    sa.Column('permission_change_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Privacy',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=50), nullable=True),
    sa.Column('department', sa.String(length=200), nullable=True),
    sa.Column('phone', sa.String(length=200), nullable=True),
    sa.Column('manager', sa.String(length=30), nullable=False),
    sa.Column('device', sa.Boolean(), nullable=True),
    sa.Column('work', sa.Boolean(), nullable=True),
    sa.Column('remarks', sa.String(length=50), nullable=True),
    sa.Column('object', sa.String(length=50), nullable=True),
    sa.Column('location', sa.String(length=50), nullable=True),
    sa.Column('company_type', sa.String(length=50), nullable=True),
    sa.Column('company', sa.String(length=50), nullable=True),
    sa.Column('work_content', sa.String(length=200), nullable=True),
    sa.Column('visit_date', sa.DateTime(), nullable=True),
    sa.Column('registry', sa.String(length=50), nullable=True),
    sa.Column('personal_computer', sa.Boolean(), nullable=True),
    sa.Column('model_name', sa.String(length=50), nullable=True),
    sa.Column('serial_number', sa.String(length=50), nullable=True),
    sa.Column('pc_reason', sa.String(length=100), nullable=True),
    sa.Column('work_division', sa.String(length=50), nullable=True),
    sa.Column('customer', sa.String(length=50), nullable=True),
    sa.Column('device_division', sa.String(length=50), nullable=True),
    sa.Column('device_count', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Privacy_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('task_title', sa.String(length=50), nullable=True),
    sa.Column('task_user_id', sa.Integer(), nullable=True),
    sa.Column('ip_address', sa.String(length=50), nullable=True),
    sa.Column('task_at', sa.DateTime(), nullable=True),
    sa.Column('task_content', sa.String(length=100), nullable=True),
    sa.Column('task_info', sa.String(length=100), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Rack',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('key_type', sa.String(length=50), nullable=True),
    sa.Column('key_num', sa.String(length=50), nullable=True),
    sa.Column('key_status', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('User',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('email', sa.String(length=50), nullable=False),
    sa.Column('password', sa.String(length=200), nullable=False),
    sa.Column('department', sa.String(length=50), nullable=False),
    sa.Column('rank', sa.String(length=20), nullable=True),
    sa.Column('login_attempts', sa.Integer(), nullable=True),
    sa.Column('login_blocked_until', sa.DateTime(), nullable=True),
    sa.Column('registered_at', sa.DateTime(), nullable=False),
    sa.Column('password_history', sa.String(length=200), nullable=True),
    sa.Column('password_changed_at', sa.DateTime(), nullable=False),
    sa.Column('attempts', sa.String(length=50), nullable=True),
    sa.Column('authenticated', sa.String(length=30), nullable=True),
    sa.Column('permission', sa.String(length=10), nullable=True),
    sa.Column('password_question', sa.String(length=200), nullable=False),
    sa.Column('password_hint_answer', sa.String(length=200), nullable=False),
    sa.Column('ip_address', sa.String(length=30), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('Year',
    sa.Column('year', sa.Integer(), nullable=False),
    sa.Column('count', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('year')
    )
    op.create_table('Department',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('department_type', sa.String(length=50), nullable=True),
    sa.Column('department_name', sa.String(length=50), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Login_failure_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('failure_at', sa.DateTime(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Month',
    sa.Column('year', sa.Integer(), nullable=False),
    sa.Column('month', sa.Integer(), nullable=False),
    sa.Column('count', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['year'], ['Year.year'], ),
    sa.PrimaryKeyConstraint('year', 'month')
    )
    with op.batch_alter_table('Month', schema=None) as batch_op:
        batch_op.create_index('ix_month_id', ['month'], unique=False)

    op.create_table('Password_change_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=40), nullable=True),
    sa.Column('password_changed_at', sa.DateTime(), nullable=False),
    sa.Column('ip_address', sa.String(length=30), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Password_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('password_log', sa.String(length=200), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('User_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ip_address', sa.String(length=30), nullable=True),
    sa.Column('login_timestamp', sa.DateTime(), nullable=True),
    sa.Column('logout_timestamp', sa.DateTime(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Visitor',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=30), nullable=False),
    sa.Column('department', sa.String(length=200), nullable=True),
    sa.Column('phone', sa.String(length=200), nullable=False),
    sa.Column('manager', sa.String(length=30), nullable=False),
    sa.Column('device', sa.Boolean(), nullable=True),
    sa.Column('work', sa.Boolean(), nullable=True),
    sa.Column('remarks', sa.String(length=50), nullable=True),
    sa.Column('object', sa.String(length=50), nullable=True),
    sa.Column('created_date', sa.DateTime(), nullable=True),
    sa.Column('approve_date', sa.DateTime(), nullable=True),
    sa.Column('exit_date', sa.DateTime(), nullable=True),
    sa.Column('exit', sa.Boolean(), nullable=True),
    sa.Column('approve', sa.Boolean(), nullable=True),
    sa.Column('personal_computer', sa.Boolean(), nullable=True),
    sa.Column('model_name', sa.String(length=50), nullable=True),
    sa.Column('serial_number', sa.String(length=50), nullable=True),
    sa.Column('pc_reason', sa.String(length=100), nullable=True),
    sa.Column('work_division', sa.String(length=50), nullable=True),
    sa.Column('work_content', sa.String(length=200), nullable=True),
    sa.Column('location', sa.String(length=50), nullable=True),
    sa.Column('company_type', sa.String(length=50), nullable=True),
    sa.Column('company', sa.String(length=50), nullable=True),
    sa.Column('customer', sa.String(length=50), nullable=True),
    sa.Column('device_division', sa.String(length=50), nullable=True),
    sa.Column('device_count', sa.String(length=50), nullable=True),
    sa.Column('registry', sa.String(length=50), nullable=True),
    sa.Column('writer', sa.Integer(), nullable=True),
    sa.Column('entry_date', sa.DateTime(), nullable=True),
    sa.Column('card_id', sa.Integer(), nullable=True),
    sa.Column('rack_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['card_id'], ['Card.id'], ),
    sa.ForeignKeyConstraint(['rack_id'], ['Rack.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Day',
    sa.Column('year', sa.Integer(), nullable=False),
    sa.Column('month', sa.Integer(), nullable=False),
    sa.Column('day', sa.Integer(), nullable=False),
    sa.Column('count', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['month'], ['Month.month'], ),
    sa.ForeignKeyConstraint(['year'], ['Year.year'], ),
    sa.PrimaryKeyConstraint('year', 'month', 'day')
    )
    with op.batch_alter_table('SMS_MSG', schema=None) as batch_op:
        batch_op.drop_index('IDX_SMS_MSG_1')
        batch_op.drop_index('IDX_SMS_MSG_2')

    op.drop_table('SMS_MSG')
    op.drop_table('MSG_PHONE')
    with op.batch_alter_table('SMS_MSG_LOG_202309', schema=None) as batch_op:
        batch_op.drop_index('IDX_SMS_MSG_LOG_202309_1')
        batch_op.drop_index('IDX_SMS_MSG_LOG_202309_2')

    op.drop_table('SMS_MSG_LOG_202309')
    with op.batch_alter_table('MMS_MSG_LOG_202309', schema=None) as batch_op:
        batch_op.drop_index('IDX_MMS_MSG_LOG_202309_1')
        batch_op.drop_index('IDX_MMS_MSG_LOG_202309_2')

    op.drop_table('MMS_MSG_LOG_202309')
    with op.batch_alter_table('MMS_MSG', schema=None) as batch_op:
        batch_op.drop_index('IDX_MMS_MSG_1')
        batch_op.drop_index('IDX_MMS_MSG_2')

    op.drop_table('MMS_MSG')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('MMS_MSG',
    sa.Column('MSGKEY', mysql.BIGINT(display_width=20), autoincrement=True, nullable=False),
    sa.Column('SERIALNUM', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('ID', mysql.VARCHAR(length=16), nullable=True),
    sa.Column('STATUS', mysql.VARCHAR(length=2), server_default=sa.text("'1'"), nullable=False),
    sa.Column('PHONE', mysql.VARCHAR(length=16), server_default=sa.text("''"), nullable=False),
    sa.Column('CALLBACK', mysql.VARCHAR(length=16), server_default=sa.text("''"), nullable=False),
    sa.Column('TYPE', mysql.VARCHAR(length=2), server_default=sa.text("'0'"), nullable=False),
    sa.Column('REPCNT', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=False),
    sa.Column('REQDATE', mysql.DATETIME(), nullable=False),
    sa.Column('SENTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('RSLTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('REPORTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('RSLT', mysql.VARCHAR(length=10), server_default=sa.text("'00'"), nullable=True),
    sa.Column('NET', mysql.VARCHAR(length=10), nullable=True),
    sa.Column('SUBJECT', mysql.VARCHAR(length=50), nullable=False),
    sa.Column('MSG', mysql.VARCHAR(length=4000), nullable=True),
    sa.Column('FILE_CNT', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=True),
    sa.Column('FILE_CNT_REAL', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=True),
    sa.Column('FILE_TYPE1', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH1', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('FILE_TYPE2', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH2', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('FILE_TYPE3', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH3', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('FILE_TYPE4', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH4', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('FILE_TYPE5', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH5', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('MMS_FILE_NAME', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('BAR_TYPE', mysql.VARCHAR(length=2), nullable=True),
    sa.Column('BAR_MERGE_FILE', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_VALUE', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('BAR_SIZE_WIDTH', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_SIZE_HEIGHT', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_POSITION_X', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_POSITION_Y', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_FILE_NAME', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('ETC1', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC2', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC3', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC4', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC5', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC6', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('CAMPAIGN_CODE', mysql.VARCHAR(length=20), nullable=True),
    sa.Column('ORIGIN_CID', mysql.VARCHAR(length=10), nullable=True),
    sa.PrimaryKeyConstraint('MSGKEY'),
    mysql_default_charset='utf8',
    mysql_engine='InnoDB'
    )
    with op.batch_alter_table('MMS_MSG', schema=None) as batch_op:
        batch_op.create_index('IDX_MMS_MSG_2', ['PHONE'], unique=False)
        batch_op.create_index('IDX_MMS_MSG_1', ['STATUS', 'REQDATE'], unique=False)

    op.create_table('MMS_MSG_LOG_202309',
    sa.Column('MSGKEY', mysql.BIGINT(display_width=20), autoincrement=False, nullable=False),
    sa.Column('SERIALNUM', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('ID', mysql.VARCHAR(length=16), nullable=True),
    sa.Column('STATUS', mysql.VARCHAR(length=2), server_default=sa.text("'1'"), nullable=False),
    sa.Column('PHONE', mysql.VARCHAR(length=16), server_default=sa.text("''"), nullable=False),
    sa.Column('CALLBACK', mysql.VARCHAR(length=16), server_default=sa.text("''"), nullable=False),
    sa.Column('TYPE', mysql.VARCHAR(length=2), server_default=sa.text("'0'"), nullable=False),
    sa.Column('REPCNT', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=False),
    sa.Column('REQDATE', mysql.DATETIME(), nullable=False),
    sa.Column('SENTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('RSLTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('REPORTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('RSLT', mysql.VARCHAR(length=10), server_default=sa.text("'00'"), nullable=True),
    sa.Column('NET', mysql.VARCHAR(length=10), nullable=True),
    sa.Column('SUBJECT', mysql.VARCHAR(length=50), nullable=False),
    sa.Column('MSG', mysql.VARCHAR(length=4000), nullable=True),
    sa.Column('FILE_CNT', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=True),
    sa.Column('FILE_CNT_REAL', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=True),
    sa.Column('FILE_TYPE1', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH1', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('FILE_TYPE2', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH2', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('FILE_TYPE3', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH3', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('FILE_TYPE4', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH4', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('FILE_TYPE5', mysql.VARCHAR(length=1), nullable=True),
    sa.Column('FILE_PATH5', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('MMS_FILE_NAME', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('BAR_TYPE', mysql.VARCHAR(length=2), nullable=True),
    sa.Column('BAR_MERGE_FILE', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_VALUE', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('BAR_SIZE_WIDTH', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_SIZE_HEIGHT', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_POSITION_X', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_POSITION_Y', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('BAR_FILE_NAME', mysql.VARCHAR(length=256), nullable=True),
    sa.Column('ETC1', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC2', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC3', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC4', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC5', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC6', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('CAMPAIGN_CODE', mysql.VARCHAR(length=20), nullable=True),
    sa.Column('ORIGIN_CID', mysql.VARCHAR(length=10), nullable=True),
    mysql_default_charset='utf8',
    mysql_engine='InnoDB'
    )
    with op.batch_alter_table('MMS_MSG_LOG_202309', schema=None) as batch_op:
        batch_op.create_index('IDX_MMS_MSG_LOG_202309_2', ['PHONE'], unique=False)
        batch_op.create_index('IDX_MMS_MSG_LOG_202309_1', ['STATUS', 'REQDATE'], unique=False)

    op.create_table('SMS_MSG_LOG_202309',
    sa.Column('MSGKEY', mysql.BIGINT(display_width=20), autoincrement=False, nullable=False),
    sa.Column('REQDATE', mysql.DATETIME(), nullable=False),
    sa.Column('SERIALNUM', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('ID', mysql.VARCHAR(length=16), nullable=True),
    sa.Column('STATUS', mysql.VARCHAR(length=1), server_default=sa.text("'1'"), nullable=False),
    sa.Column('RSLT', mysql.VARCHAR(length=2), server_default=sa.text("'00'"), nullable=True),
    sa.Column('TYPE', mysql.VARCHAR(length=1), server_default=sa.text("'0'"), nullable=False),
    sa.Column('REPCNT', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=False),
    sa.Column('PHONE', mysql.VARCHAR(length=16), server_default=sa.text("''"), nullable=False),
    sa.Column('CALLBACK', mysql.VARCHAR(length=16), server_default=sa.text("''"), nullable=False),
    sa.Column('RSLTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('REPORTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('MSG', mysql.VARCHAR(length=160), nullable=False),
    sa.Column('NET', mysql.VARCHAR(length=4), nullable=True),
    sa.Column('ETC1', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC2', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC3', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC4', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC5', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC6', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('CAMPAIGN_CODE', mysql.VARCHAR(length=20), nullable=True),
    sa.Column('ORIGIN_CID', mysql.VARCHAR(length=10), nullable=True),
    mysql_default_charset='utf8',
    mysql_engine='InnoDB'
    )
    with op.batch_alter_table('SMS_MSG_LOG_202309', schema=None) as batch_op:
        batch_op.create_index('IDX_SMS_MSG_LOG_202309_2', ['PHONE'], unique=False)
        batch_op.create_index('IDX_SMS_MSG_LOG_202309_1', ['STATUS', 'REQDATE'], unique=False)

    op.create_table('MSG_PHONE',
    sa.Column('MSGTYPE', mysql.CHAR(length=1), server_default=sa.text("'S'"), nullable=False),
    sa.Column('MSGKEY', mysql.BIGINT(display_width=20), autoincrement=False, nullable=False),
    sa.Column('PHONE', mysql.VARCHAR(length=16), nullable=False),
    sa.Column('CALLBACK', mysql.VARCHAR(length=16), nullable=False),
    sa.Column('STATUS', mysql.VARCHAR(length=2), server_default=sa.text("'1'"), nullable=False),
    sa.Column('RSLTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('REPORTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('RSLT', mysql.VARCHAR(length=10), server_default=sa.text("'00'"), nullable=True),
    sa.Column('NET', mysql.VARCHAR(length=10), nullable=True),
    sa.Column('REPLACE_CNT', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=False),
    sa.Column('REPLACE_MSG', mysql.VARCHAR(length=256), nullable=True),
    sa.PrimaryKeyConstraint('MSGTYPE', 'MSGKEY', 'PHONE'),
    mysql_default_charset='utf8',
    mysql_engine='InnoDB'
    )
    op.create_table('SMS_MSG',
    sa.Column('MSGKEY', mysql.BIGINT(display_width=20), autoincrement=True, nullable=False),
    sa.Column('REQDATE', mysql.DATETIME(), nullable=False),
    sa.Column('SERIALNUM', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True),
    sa.Column('ID', mysql.VARCHAR(length=16), nullable=True),
    sa.Column('STATUS', mysql.VARCHAR(length=1), server_default=sa.text("'1'"), nullable=False),
    sa.Column('RSLT', mysql.VARCHAR(length=2), server_default=sa.text("'00'"), nullable=True),
    sa.Column('TYPE', mysql.VARCHAR(length=1), server_default=sa.text("'0'"), nullable=False),
    sa.Column('REPCNT', mysql.INTEGER(display_width=11), server_default=sa.text("'0'"), autoincrement=False, nullable=False),
    sa.Column('PHONE', mysql.VARCHAR(length=16), server_default=sa.text("''"), nullable=False),
    sa.Column('CALLBACK', mysql.VARCHAR(length=16), server_default=sa.text("''"), nullable=False),
    sa.Column('RSLTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('REPORTDATE', mysql.DATETIME(), nullable=True),
    sa.Column('MSG', mysql.VARCHAR(length=160), nullable=False),
    sa.Column('NET', mysql.VARCHAR(length=4), nullable=True),
    sa.Column('ETC1', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC2', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC3', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC4', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC5', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('ETC6', mysql.VARCHAR(length=160), nullable=True),
    sa.Column('CAMPAIGN_CODE', mysql.VARCHAR(length=20), nullable=True),
    sa.Column('ORIGIN_CID', mysql.VARCHAR(length=10), nullable=True),
    sa.PrimaryKeyConstraint('MSGKEY'),
    mysql_default_charset='utf8',
    mysql_engine='InnoDB'
    )
    with op.batch_alter_table('SMS_MSG', schema=None) as batch_op:
        batch_op.create_index('IDX_SMS_MSG_2', ['PHONE'], unique=False)
        batch_op.create_index('IDX_SMS_MSG_1', ['STATUS', 'REQDATE'], unique=False)

    op.drop_table('Day')
    op.drop_table('Visitor')
    op.drop_table('User_log')
    op.drop_table('Password_log')
    op.drop_table('Password_change_log')
    with op.batch_alter_table('Month', schema=None) as batch_op:
        batch_op.drop_index('ix_month_id')

    op.drop_table('Month')
    op.drop_table('Login_failure_log')
    op.drop_table('Department')
    op.drop_table('Year')
    op.drop_table('User')
    op.drop_table('Rack')
    op.drop_table('Privacy_log')
    op.drop_table('Privacy')
    op.drop_table('Permission_log')
    op.drop_table('Card')
    op.drop_table('Account_log')
    # ### end Alembic commands ###
