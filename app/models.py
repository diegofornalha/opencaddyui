from app import db
from flask_login import UserMixin
from datetime import datetime
import os

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(120), unique=True, nullable=True)

class ConfigVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(128))
    config_path = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('config_versions', lazy=True))

    @classmethod
    def save_version(cls, config_json, user_id):
        from app import current_app
        os.makedirs(current_app.config['CONFIG_VERSIONS_DIR'], exist_ok=True)
        
        version_name = f"config-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
        version_path = os.path.join(current_app.config['CONFIG_VERSIONS_DIR'], version_name)
        
        with open(version_path, 'w') as f:
            f.write(config_json)
        
        version = cls(
            version=version_name,
            config_path=version_path,
            user_id=user_id
        )
        db.session.add(version)
        db.session.commit()
        return version
