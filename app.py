from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import db, create_app
from datetime import datetime, date, time
import pytz
korean_timezone = pytz.timezone('Asia/Seoul')

# 회원가입 시간 기록을 위한 커스텀 함수
def get_current_korean_time():
    return datetime.now(korean_timezone)

class User(db.Model):
    __tablename__ = "User"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=False, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), unique=False, nullable=False)
    department = db.Column(db.String(50), unique=False, nullable=False)
    rank = db.Column(db.String(20), unique=False)
    login_attempts = db.Column(db.Integer, default=0)  # 로그인 시도 횟수
    login_blocked_until = db.Column(db.DateTime, nullable=True)  # 로그인 제한 종료 시간
    registered_at = db.Column(db.DateTime, nullable=False)
    password_history = db.Column(db.String(200), unique=False)
    password_changed_at = db.Column(db.DateTime, nullable=False) # 비밀번호 변경권고를 위한 시간 ex) 6개월
    attempts = db.Column(db.String(50), unique=False)
    authenticated = db.Column(db.String(30), unique=False)
    permission = db.Column(db.String(10))
    password_question = db.Column(db.String(200), unique=False, nullable=False)
    password_hint_answer = db.Column(db.String(200), unique=False, nullable=False)
    ip_address = db.Column(db.String(30), unique=False)
    user_info_id = db.relationship('User_log', backref='user_log')
    password_log_id = db.relationship('Password_log', backref='user_log')
    password_change_log_id = db.relationship('Password_change_log', backref='user_log')
    login_failure_id = db.relationship('Login_failure_log', backref='user_log')
    department_id = db.relationship('Department', backref='user_log')

    def __init__(self, username, email, password, department, rank, password_history, registered_at, password_changed_at, permission, password_question, password_hint_answer, ip_address):
        self.username = username
        self.email = email
        self.password = password
        self.department = department
        self.rank = rank
        self.password_history = password_history
        self.registered_at = registered_at
        self.password_changed_at = password_changed_at
        self.permission = permission
        self.password_question = password_question
        self.password_hint_answer = password_hint_answer
        self.ip_address = ip_address

    # Flask-Login integration
    def is_authenticated(self):
        return True

    def is_active(self): # line 37
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    # Required for administrative interface
    def __unicode__(self):
        return self.username
    
    def __repr__(self):
        return '%r' % self.username
      
class User_log(db.Model):
    __tablename__ = "User_log"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(30), unique=False)
    login_timestamp = db.Column(db.DateTime, unique=False)
    logout_timestamp =  db.Column(db.DateTime, unique=False, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))

    def __init__(self, ip_address, login_timestamp, user_id):
        self.ip_address = ip_address
        self.login_timestamp = login_timestamp
        self.user_id = user_id

class Permission_log(db.Model):
    __tablename__ = "Permission_log"

    id = db.Column(db.Integer, primary_key=True)
    permission_email = db.Column(db.String(200))
    original_permission = db.Column(db.String(50))
    new_permission = db.Column(db.String(50))
    permission_change_at = db.Column(db.DateTime)

    def __init__(self, permission_email, original_permission, new_permission, permission_change_at):
        self.permission_email = permission_email
        self.original_permission = original_permission
        self.new_permission = new_permission
        self.permission_change_at = permission_change_at

class Password_log(db.Model):
    __tablename__ = "Password_log"

    id = db.Column(db.Integer, primary_key=True)
    password_log = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))

    def __init__(self, password_log, user_id):
        self.password_log = password_log
        self.user_id = user_id

class Password_change_log(db.Model):
    __tablename__ = "Password_change_log"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), unique=False)
    password_changed_at = db.Column(db.DateTime, nullable=False)
    ip_address = db.Column(db.String(30), unique=False)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))

    def __init__(self, email, password_changed_at, ip_address, user_id):
        self.email = email
        self.password_changed_at = password_changed_at
        self.ip_address = ip_address
        self.user_id = user_id

class Account_log(db.Model):
    __tablename__ = "Account_log"

    id = db.Column(db.Integer, primary_key=True)
    account_email = db.Column(db.String(200))
    account_remove_at = db.Column(db.DateTime, unique=False)

    def __init__(self, account_email, account_remove_at):
        self.account_email = account_email
        self.account_remove_at = account_remove_at

class Login_failure_log(db.Model):
    __tablename__ = "Login_failure_log"

    id = db.Column(db.Integer, primary_key=True)
    failure_at = db.Column(db.DateTime, unique=False)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))

    def __init__(self, user_id, failure_at):
        self.user_id = user_id
        self.failure_at = failure_at

class Privacy_log(db.Model):
    __tablename__ = "Privacy_log"

    id = db.Column(db.Integer, primary_key=True)
    task_title = db.Column(db.String(50))
    task_user_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(50))
    task_at = db.Column(db.DateTime, unique=False)
    task_content = db.Column(db.String(100))
    task_info = db.Column(db.String(100))

    def __init__(self, task_title, task_user_id, ip_address, task_at, task_content, task_info):
        self.task_title = task_title
        self.task_user_id = task_user_id
        self.ip_address = ip_address
        self.task_at = task_at
        self.task_content = task_content
        self.task_info = task_info

class Visitor(db.Model):
    __tablename__ = "Visitor"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=False, nullable=False)
    department = db.Column(db.String(200), unique=False)
    phone = db.Column(db.String(200), unique=False, nullable=False)
    manager = db.Column(db.String(30), unique=False, nullable=False)
    device = db.Column(db.Boolean(), unique=False)
    work = db.Column(db.Boolean(), unique=False)
    remarks = db.Column(db.String(50), unique=False, nullable=True)
    object = db.Column(db.String(50), unique=False)
    created_date = db.Column(db.DateTime, unique=False)
    approve_date = db.Column(db.DateTime, unique=False)
    exit_date = db.Column(db.DateTime, unique=False, nullable=True)
    exit = db.Column(db.Boolean(), unique=False, nullable=True)
    approve = db.Column(db.Boolean(), unique=False)
    personal_computer = db.Column(db.Boolean(), unique=False)
    model_name = db.Column(db.String(50), unique=False, nullable=True)
    serial_number = db.Column(db.String(50), unique=False, nullable=True)
    pc_reason = db.Column(db.String(100), unique=False, nullable=True)
    work_division = db.Column(db.String(50), unique=False, nullable=True)
    work_content = db.Column(db.String(200), unique=False, nullable=True)
    location = db.Column(db.String(50), unique=False, nullable=True)
    company_type = db.Column(db.String(50), unique=False, nullable=True)
    company = db.Column(db.String(50), unique=False, nullable=True)
    customer = db.Column(db.String(50), unique=False, nullable=True)
    device_division = db.Column(db.String(50), unique=False, nullable=True)
    device_count = db.Column(db.String(50), unique=False, nullable=True)
    registry = db.Column(db.String(50), unique=False, nullable=True)
    writer = db.Column(db.Integer)
    entry_date = db.Column(db.DateTime, unique=False)
    card_id = db.Column(db.Integer, db.ForeignKey('Card.id'))
    rack_id = db.Column(db.Integer, db.ForeignKey('Rack.id'))
    cards = db.relationship('Card', backref='visitor')
    rack_keys = db.relationship('Rack', backref='visitor_rack')

    # 이름, 부서, 번호, 작업위치, 담당자, 장비체크, 비고, 방문목적, 등록시간, 승인, 사전/현장, 작업체크, 회사종류, 회사이름, 작업내용
    def __init__(self, name, department, phone, location, manager, device, remarks, object, created_time, approve, registry, work, company_type, company, work_content, writer, personal_computer, model_name, serial_number, pc_reason, work_division, customer, device_division, device_count):
        self.name = name
        self.department = department
        self.phone = phone
        self.location = location
        self.manager = manager
        self.device = device
        self.remarks = remarks
        self.approve = approve
        self.object = object
        self.created_date = created_time
        self.registry = registry
        self.work = work
        self.company_type = company_type
        self.company = company
        self.work_content = work_content
        self.writer = writer
        self.personal_computer = personal_computer
        self.model_name = model_name
        self.serial_number = serial_number
        self.pc_reason = pc_reason
        self.work_division = work_division
        self.customer = customer
        self.device_division = device_division
        self.device_count = device_count

class Card(db.Model):
    __tablename__ = "Card"

    id = db.Column(db.Integer, primary_key=True)
    card_type = db.Column(db.String(50), unique=False)
    card_num = db.Column(db.String(50), unique=False, nullable=True)
    card_status = db.Column(db.String(50), unique=False, nullable=True)
    visitors = db.relationship('Visitor', backref='card')

    def __init__(self, card_type, card_num, card_status):
        self.card_type = card_type
        self.card_num = card_num
        self.card_status = card_status

class Year(db.Model):
    __tablename__ = "Year"

    year = db.Column(db.Integer, primary_key=True)
    count = db.Column(db.Integer, default=0)

class Month(db.Model):
    __tablename__ = "Month"

    year = db.Column(db.Integer, db.ForeignKey('Year.year'), primary_key=True)
    month = db.Column(db.Integer, primary_key=True)
    count = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.Index('ix_month_id', 'month'),
    )

class Day(db.Model):
    __tablename__ = "Day"

    year = db.Column(db.Integer, db.ForeignKey('Year.year'), primary_key=True)
    month = db.Column(db.Integer, db.ForeignKey('Month.month'), primary_key=True)
    day = db.Column(db.Integer, primary_key=True)
    count = db.Column(db.Integer, default=0)

class Department(db.Model):
    __tablename__ = "Department"

    id = db.Column(db.Integer, primary_key=True)
    department_type = db.Column(db.String(50), unique=False)
    department_name = db.Column(db.String(50), unique=False)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))

    def __init__(self, department_type, department_name, user_id):
        self.department_type = department_type
        self.department_name = department_name
        self.user_id = user_id

class Rack(db.Model):
    __tablename__ = "Rack"

    id = db.Column(db.Integer, primary_key=True)
    key_type = db.Column(db.String(50), unique=False)
    key_num = db.Column(db.String(50), unique=False, nullable=True)
    key_status = db.Column(db.String(50), unique=False, nullable=True)
    visitors = db.relationship('Visitor', backref='rack')

    def __init__(self, key_type, key_num, key_status):
        self.key_type = key_type
        self.key_num = key_num
        self.key_status = key_status

class Privacy(db.Model):
    __tablename__ = "Privacy"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=False)
    department = db.Column(db.String(200), unique=False)
    phone = db.Column(db.String(200), unique=False)
    manager = db.Column(db.String(30), unique=False, nullable=False)
    device = db.Column(db.Boolean(), unique=False, nullable=True)
    work = db.Column(db.Boolean(), unique=False, nullable=True)
    remarks = db.Column(db.String(50), unique=False, nullable=True)
    object = db.Column(db.String(50), unique=False)
    location = db.Column(db.String(50), unique=False, nullable=True)
    company_type = db.Column(db.String(50), unique=False, nullable=True)
    company = db.Column(db.String(50), unique=False, nullable=True)
    work_content = db.Column(db.String(200), unique=False, nullable=True)
    visit_date = db.Column(db.DateTime, unique=False)
    registry = db.Column(db.String(50), unique=False, nullable=True)
    personal_computer = db.Column(db.Boolean(), unique=False)
    model_name = db.Column(db.String(50), unique=False, nullable=True)
    serial_number = db.Column(db.String(50), unique=False, nullable=True)
    pc_reason = db.Column(db.String(100), unique=False, nullable=True)
    work_division = db.Column(db.String(50), unique=False, nullable=True)
    customer = db.Column(db.String(50), unique=False, nullable=True)
    device_division = db.Column(db.String(50), unique=False, nullable=True)
    device_count = db.Column(db.String(50), unique=False, nullable=True)

    def __init__(self, name, department, phone, manager, device, work, remarks, object, location, company_type, company, work_content, visit_date, registry, personal_computer, model_name, serial_number, pc_reason, work_division, customer, device_division, device_count):
        self.name = name
        self.department = department
        self.phone = phone
        self.manager = manager
        self.device = device
        self.work = work
        self.remarks = remarks
        self.object = object
        self.location = location
        self.company_type = company_type
        self.company = company
        self.work_content = work_content
        self.visit_date = visit_date
        self.work = work
        self.registry = registry
        self.personal_computer = personal_computer
        self.model_name = model_name
        self.serial_number = serial_number
        self.pc_reason = pc_reason
        self.work_division = work_division
        self.customer = customer
        self.device_division = device_division
        self.device_count = device_count
    

