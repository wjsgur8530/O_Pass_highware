from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from db_connector import db_connector, secret_key
from datetime import timedelta

db_user, db_password, db_host, db_port, db_name = db_connector()
secret_key = secret_key()

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = 28800
    app.config['SECRET_KEY'] = secret_key
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['JSON_AS_ASCII'] = False
    
    # ORM
    db.init_app(app)
    migrate.init_app(app, db)

    return app
