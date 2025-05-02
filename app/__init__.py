import os
from flask import Flask
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
basedir = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'instance', 'caddyui.db'))
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['CADDY_ADMIN_API'] = os.getenv('CADDY_ADMIN_API', 'http://localhost:2019')
    app.config['CONFIG_VERSIONS_DIR'] = os.path.join(os.path.dirname(__file__), 'configs')
    
    # Make sure the folder existis
    os.makedirs(os.path.dirname(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')), exist_ok=True)
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    # Register blueprints
    from app.auth import auth_bp
    from app.routes import main_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    
    # Context processor
    @app.context_processor
    def inject_current_year():
        from datetime import datetime
        return {'current_year': datetime.now().year}

    # Create directories if they don't exist
    with app.app_context():
        db.create_all()
        initialize_default_admin()
    
    return app

def initialize_default_admin():
    from app.models import User
    from werkzeug.security import generate_password_hash
    
    admin_user = os.getenv('DEFAULT_ADMIN_USERNAME')
    admin_pass = os.getenv('DEFAULT_ADMIN_PASSWORD')
    admin_email = os.getenv('ADMIN_EMAIL')
    
    if not all([admin_user, admin_pass]):
        current_app.logger.warning("Admin credentials not fully configured in environment")
        return False
    
    if not User.query.filter_by(username=admin_user).first():
        admin = User(
            username=admin_user,
            password_hash=generate_password_hash(admin_pass),
            email=admin_email,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        current_app.logger.info(f"Created admin user: {admin_user}")
        return True
    return False
