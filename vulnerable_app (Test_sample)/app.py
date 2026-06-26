"""SecureVault - A vulnerable Flask application for SAST testing.

This application is intentionally insecure for educational and authorized
security testing only.
"""
import os
import hashlib
import pickle
import subprocess
import base64
import json
import urllib.parse
from pathlib import Path

import jwt
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, send_file, abort

from config import Config
from models import db, User, FileRecord


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)

    # Register blueprints
    from routes.auth import auth_bp
    from routes.files import files_bp
    from routes.admin import admin_bp
    from routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.before_first_request
    def create_tables():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@securevault.local",
                password_hash=hashlib.md5("admin123".encode()).hexdigest(),
                is_admin=True,
                api_key="sk_live_admin_1234567890abcdef",
            )
            db.session.add(admin)
            db.session.commit()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/dashboard")
    def dashboard():
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        user = User.query.get(session["user_id"])
        return render_template("dashboard.html", user=user)

    @app.route("/health")
    def health():
        # SECURITY ISSUE: Information disclosure via verbose health check
        return json.dumps({
            "status": "ok",
            "debug": True,
            "secret_key": app.config["SECRET_KEY"],
            "version": "1.0.0-dev",
        })

    @app.route("/ping")
    def ping():
        # SECURITY ISSUE: Command injection
        host = request.args.get("host", "127.0.0.1")
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
        return f"<pre>{result}</pre>"

    @app.route("/fetch")
    def fetch_url():
        # SECURITY ISSUE: SSRF
        url = request.args.get("url")
        if not url:
            return "Missing url", 400
        resp = requests.get(url, verify=False, timeout=5)
        return resp.text

    @app.route("/search")
    def search():
        # SECURITY ISSUE: SQL injection via raw query
        q = request.args.get("q", "")
        query = f"SELECT * FROM users WHERE username LIKE '%{q}%'"
        result = db.session.execute(query)
        users = [dict(row) for row in result.mappings()]
        return render_template("search.html", users=users, q=q)

    @app.route("/profile/<int:user_id>")
    def profile(user_id):
        # SECURITY ISSUE: IDOR / broken access control
        user = User.query.get_or_404(user_id)
        # SECURITY ISSUE: XSS via reflected template variable
        return render_template("profile.html", user=user, message=request.args.get("msg", ""))

    @app.route("/deserialize", methods=["POST"])
    def deserialize():
        # SECURITY ISSUE: Insecure deserialization
        data = request.form.get("data")
        obj = pickle.loads(base64.b64decode(data))
        return f"Deserialized: {obj}"

    @app.route("/redirect")
    def open_redirect():
        # SECURITY ISSUE: Open redirect
        target = request.args.get("next", "/")
        return redirect(target)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
