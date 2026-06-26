"""Authentication routes."""
import hashlib

import jwt
from flask import Blueprint, request, render_template, redirect, url_for, session, flash

from models import db, User


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # SECURITY ISSUE: Weak password hashing (MD5)
        password_hash = hashlib.md5(password.encode()).hexdigest()

        # SECURITY ISSUE: SQL injection in INSERT
        query = f"INSERT INTO users (username, email, password_hash, is_admin) VALUES ('{username}', '{email}', '{password_hash}', 0)"
        db.session.execute(query)
        db.session.commit()
        flash("Account created")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_hash = hashlib.md5(password.encode()).hexdigest()

        # SECURITY ISSUE: SQL injection in login
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        result = db.session.execute(query)
        row = result.fetchone()

        if row:
            session["user_id"] = row[0]
            session["username"] = row[1]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@auth_bp.route("/api-token")
def api_token():
    user_id = session.get("user_id")
    if not user_id:
        return "Unauthorized", 401
    user = User.query.get(user_id)
    # SECURITY ISSUE: JWT with weak secret and none algorithm fallback
    token = jwt.encode({"user_id": user.id, "admin": user.is_admin}, "jwt_super_secret_do_not_share", algorithm="HS256")
    return {"token": token}
