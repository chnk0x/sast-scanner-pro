"""File management routes."""
import os
import hashlib

from flask import Blueprint, request, render_template, redirect, url_for, session, flash, send_from_directory, current_app
from werkzeug.utils import secure_filename

from models import db, FileRecord, User


files_bp = Blueprint("files", __name__)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


@files_bp.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        file = request.files.get("file")
        if file and allowed_file(file.filename):
            # SECURITY ISSUE: Insecure filename handling
            filename = file.filename
            path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
            file.save(path)

            record = FileRecord(filename=filename, owner_id=session["user_id"])
            db.session.add(record)
            db.session.commit()
            flash("File uploaded")
        else:
            flash("Invalid file type")
    return render_template("upload.html")


@files_bp.route("/download/<path:filename>")
def download(filename):
    # SECURITY ISSUE: Path traversal
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename)


@files_bp.route("/files/share/<int:file_id>")
def share_file(file_id):
    # SECURITY ISSUE: IDOR
    record = FileRecord.query.get_or_404(file_id)
    record.public = True
    db.session.commit()
    flash("File is now public")
    return redirect(url_for("dashboard"))
