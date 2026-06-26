"""API routes."""
import hashlib

import jwt
from flask import Blueprint, request, jsonify

from models import db, User


api_bp = Blueprint("api", __name__)


def get_user_from_token():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = jwt.decode(token, "jwt_super_secret_do_not_share", algorithms=["HS256", "none"])
        return payload
    except Exception:
        return None


@api_bp.route("/users/<int:user_id>")
def get_user(user_id):
    # SECURITY ISSUE: IDOR
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())


@api_bp.route("/users/search")
def search_users():
    # SECURITY ISSUE: SQL injection
    q = request.args.get("q", "")
    query = f"SELECT * FROM users WHERE username LIKE '%{q}%'"
    result = db.session.execute(query)
    users = [dict(row) for row in result.mappings()]
    return jsonify(users)


@api_bp.route("/change-password", methods=["POST"])
def change_password():
    payload = get_user_from_token()
    if not payload:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = payload.get("user_id")
    new_password = request.json.get("password")

    # SECURITY ISSUE: Weak hashing
    user = User.query.get(user_id)
    user.password_hash = hashlib.md5(new_password.encode()).hexdigest()
    db.session.commit()
    return jsonify({"status": "ok"})


@api_bp.route("/exec", methods=["POST"])
def run_command():
    # SECURITY ISSUE: Command injection via API
    payload = get_user_from_token()
    if not payload:
        return jsonify({"error": "Unauthorized"}), 401

    cmd = request.json.get("cmd")
    import subprocess
    output = subprocess.check_output(cmd, shell=True, text=True)
    return jsonify({"output": output})
