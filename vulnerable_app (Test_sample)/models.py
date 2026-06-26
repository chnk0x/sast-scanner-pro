"""Database models."""
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # SECURITY ISSUE: MD5 password hashing (weak crypto)
    password_hash = db.Column(db.String(64), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(64), default=None)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "api_key": self.api_key,
        }


class FileRecord(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    public = db.Column(db.Boolean, default=False)
    owner = db.relationship("User", backref="files")
