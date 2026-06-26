"""Admin routes."""
import os

from flask import Blueprint, request, render_template, session, redirect, url_for

from models import db, User, FileRecord


admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
def admin_panel():
    # SECURITY ISSUE: Broken access control (only checks session, not admin role)
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    users = User.query.all()
    files = FileRecord.query.all()
    return render_template("admin.html", users=users, files=files)


@admin_bp.route("/admin/delete/<int:user_id>")
def delete_user(user_id):
    # SECURITY ISSUE: IDOR / missing authorization
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for("admin.admin_panel"))


@admin_bp.route("/admin/config")
def admin_config():
    # SECURITY ISSUE: Information disclosure
    config = {}
    for key in os.environ:
        config[key] = os.environ[key]
    return config
