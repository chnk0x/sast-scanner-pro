"""Application configuration."""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # SECURITY ISSUE: Hardcoded fallback secret key
    SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_key_12345_change_in_production")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///securevault.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # SECURITY ISSUE: Debug mode enabled in production-like config
    DEBUG = True

    # SECURITY ISSUE: JWT secret hardcoded
    JWT_SECRET = os.getenv("JWT_SECRET", "jwt_super_secret_do_not_share")

    # SECURITY ISSUE: Insecure admin credentials
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"

    # SECURITY ISSUE: AWS keys hardcoded as fallback
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    # SECURITY ISSUE: Permissive upload settings
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "exe"}

    # SECURITY ISSUE: Insecure session cookie settings
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = None

    # SECURITY ISSUE: CORS wildcard
    CORS_ORIGINS = "*"
