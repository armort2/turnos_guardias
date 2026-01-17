# app/routes/helpers.py
from __future__ import annotations

from functools import wraps

from flask import abort, flash, redirect, url_for
from flask_login import current_user

from .. import db
from ..models import Instalacion


def role_required(*roles):
    roles = tuple(r.upper() for r in roles)

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("main.login"))

            if not getattr(current_user, "activo", True):
                flash("Usuario inactivo.", "danger")
                return redirect(url_for("main.login"))

            if (getattr(current_user, "rol", "") or "").upper() not in roles:
                flash("Acceso no autorizado.", "danger")
                return redirect(url_for("main.index"))

            return fn(*args, **kwargs)

        return wrapper

    return decorator


def instalaciones_permitidas_query():
    """
    Devuelve un query de Instalacion limitado por scope:
    - ADMIN: todas
    - OPERADOR/REVISOR: solo las asignadas
    """
    if current_user.es_admin():
        return Instalacion.query

    ids = [i.id for i in (current_user.instalaciones or [])]
    if not ids:
        return Instalacion.query.filter(db.text("1=0"))

    return Instalacion.query.filter(Instalacion.id.in_(ids))


def exigir_acceso_instalacion(instalacion_id: int):
    """
    Bloquea acceso si la instalación no está en el scope (excepto ADMIN).
    """
    if not current_user.puede_acceder_instalacion(instalacion_id):
        abort(403)
