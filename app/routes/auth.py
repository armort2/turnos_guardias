from datetime import datetime

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .. import db
from ..models import AuditLog, Usuario
from . import main


def audit_login(accion: str, user_id=None, detalle: str = ""):
    """
    Auditoría simple y segura.
    Si falla, NO rompe la operación principal.
    """
    try:
        ip = request.headers.get("CF-Connecting-IP") or request.remote_addr
        ua = (request.headers.get("User-Agent") or "")[:250]

        log = AuditLog(
            actor_id=user_id,
            target_user_id=user_id,
            accion=accion,
            detalle=(detalle or "")[:500],
            ip=(ip or "")[:60],
            user_agent=ua,
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()


@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = Usuario.query.filter_by(username=username).first()

        if (
            not user
            or not getattr(user, "activo", True)
            or not user.check_password(password)
        ):
            audit_login(
                "LOGIN_FAIL",
                user_id=(user.id if user else None),
                detalle=f"Intento fallido usuario={username}",
            )
            flash("Usuario o contraseña incorrectos.", "danger")
            return redirect(url_for("main.login"))

        login_user(user)

        try:
            user.ultimo_acceso = datetime.utcnow()
            db.session.commit()
        except Exception:
            db.session.rollback()

        audit_login(
            "LOGIN_OK",
            user_id=user.id,
            detalle=f"Login exitoso ({(user.rol or '').upper()})",
        )

        flash("Bienvenido al sistema.", "success")
        return redirect(url_for("main.index"))

    return render_template("login.html")


@main.route("/logout")
@login_required
def logout():
    audit_login("LOGOUT", user_id=current_user.id, detalle="Cierre de sesión")
    logout_user()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("main.login"))
