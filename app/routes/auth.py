# app/routes/auth.py
from datetime import UTC, datetime
from urllib.parse import urlparse

from flask import flash, redirect, render_template, request, session, url_for
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


def _is_safe_next_url(next_url: str) -> bool:
    """
    Previene open-redirect: solo permite redirección a rutas internas.
    - Acepta '/algo'
    - Rechaza 'https://sitio-malo.com/...'
    """
    if not next_url:
        return False

    parsed = urlparse(next_url)

    # Si trae scheme o netloc, es externo (no permitido)
    if parsed.scheme or parsed.netloc:
        return False

    # Permitimos rutas relativas internas
    return next_url.startswith("/")


@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # next puede venir en querystring o como input hidden en el form
        next_url = request.args.get("next") or request.form.get("next") or ""
        next_url = next_url.strip()

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
            return redirect(
                url_for("main.login", next=next_url)
                if next_url
                else url_for("main.login")
            )

        # Si después quieres “recordarme”, agrega checkbox remember en el template
        remember = request.form.get("remember") in ("on", "true", "1", "yes")
        login_user(user, remember=remember)

        try:
            user.ultimo_acceso = datetime.now(UTC)

            db.session.commit()
        except Exception:
            db.session.rollback()

        audit_login(
            "LOGIN_OK",
            user_id=user.id,
            detalle=f"Login exitoso ({(user.rol or '').upper()})"
            + (f" next={next_url}" if next_url else ""),
        )

        flash("Bienvenido al sistema.", "success")

        if _is_safe_next_url(next_url):
            return redirect(next_url)

        return redirect(url_for("main.index"))

    # Para GET, mantenemos next para que el template lo preserve (hidden input)
    next_url = (request.args.get("next") or "").strip()
    return render_template("login.html", next=next_url)


@main.route("/logout")
@login_required
def logout():
    audit_login("LOGOUT", user_id=current_user.id, detalle="Cierre de sesión")
    logout_user()
    flash("Sesión cerrada.", "info")
    session.pop("turnos_inst_id_sel", None)
    return redirect(url_for("main.login"))
