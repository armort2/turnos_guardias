import re
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy.orm import selectinload
from sqlalchemy import or_

from . import db
from .models import Usuario, Instalacion, AuditLog
from .routes import role_required  # reutiliza tu decorator

usuarios_bp = Blueprint("usuarios", __name__)


# -------------------------
# Helpers (RUT + email)
# -------------------------
def normalizar_email(email: str) -> str:
    return (email or "").strip().lower()


def normalizar_rut(rut: str) -> str:
    """
    Normaliza el RUT a '12345678-9' (sin puntos, con guion, DV en mayúscula).
    """
    rut = (rut or "").strip().upper().replace(".", "").replace(" ", "")
    if not rut:
        return ""

    if "-" in rut:
        cuerpo, dv = rut.split("-", 1)
    else:
        cuerpo, dv = rut[:-1], rut[-1:]

    cuerpo = re.sub(r"\D", "", cuerpo)
    dv = re.sub(r"[^0-9K]", "", dv)

    if not cuerpo or not dv:
        return ""

    return f"{cuerpo}-{dv}"


def rut_dv_valido(rut_normalizado: str) -> bool:
    """
    Valida DV chileno.
    Espera rut en formato '12345678-9' o '12345678-K'
    """
    rut_normalizado = (rut_normalizado or "").strip().upper()
    if not rut_normalizado or "-" not in rut_normalizado:
        return False

    cuerpo, dv = rut_normalizado.split("-", 1)
    if not cuerpo.isdigit():
        return False
    if dv not in "0123456789K":
        return False

    # algoritmo módulo 11
    reversed_digits = list(map(int, reversed(cuerpo)))
    factors = [2, 3, 4, 5, 6, 7]
    s = 0
    for i, d in enumerate(reversed_digits):
        s += d * factors[i % len(factors)]
    mod = 11 - (s % 11)
    dv_calc = "0" if mod == 11 else "K" if mod == 10 else str(mod)
    return dv == dv_calc


def audit(accion: str, target_user_id=None, detalle: str = ""):
    """
    Auditoría simple y segura (si falla, no rompe la operación).
    """
    try:
        ip = request.headers.get("CF-Connecting-IP") or request.remote_addr
        ua = (request.headers.get("User-Agent") or "")[:250]

        log = AuditLog(
            actor_id=current_user.id if current_user.is_authenticated else None,
            target_user_id=target_user_id,
            accion=accion,
            detalle=(detalle or "")[:500],
            ip=(ip or "")[:60],
            user_agent=ua,
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()


@usuarios_bp.get("/usuarios")
@login_required
@role_required("ADMIN")
def usuarios_listado():
    q = (request.args.get("q") or "").strip()

    query = Usuario.query.options(selectinload(Usuario.instalaciones))

    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Usuario.username.ilike(like),
                Usuario.rol.ilike(like),
                Usuario.nombre_completo.ilike(like),
                Usuario.email.ilike(like),
                Usuario.rut.ilike(like),
            )
        )

    usuarios = query.order_by(Usuario.id.asc()).all()
    return render_template("usuarios_listado.html", usuarios=usuarios, q=q)


@usuarios_bp.route("/usuarios/nuevo", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def usuarios_nuevo():
    instalaciones = Instalacion.query.order_by(Instalacion.nombre.asc()).all()

    if request.method == "GET":
        return render_template(
            "usuarios_form.html",
            modo="nuevo",
            u=None,
            instalaciones=instalaciones,
            asignadas_ids=set(),
        )

    username = (request.form.get("username") or "").strip()
    rol = (request.form.get("rol") or "REVISOR").strip().upper()
    password = (request.form.get("password") or "").strip()
    activo = True if request.form.get("activo") == "on" else False
    debe_cambiar_password = (
        True if request.form.get("debe_cambiar_password") == "on" else False
    )

    # nuevos campos
    nombre_completo = (request.form.get("nombre_completo") or "").strip()
    rut = normalizar_rut(request.form.get("rut") or "")
    email = normalizar_email(request.form.get("email") or "")

    inst_ids = request.form.getlist("instalaciones")
    inst_ids = [int(x) for x in inst_ids if str(x).isdigit()]

    if not username:
        flash("Debes indicar un usuario (username o correo).", "danger")
        return redirect(url_for("usuarios.usuarios_nuevo"))

    if not nombre_completo:
        flash("Debes indicar el nombre completo.", "danger")
        return redirect(url_for("usuarios.usuarios_nuevo"))

    if not rut or not rut_dv_valido(rut):
        flash("Debes indicar un RUT válido (DV correcto). Ej: 12.345.678-9", "danger")
        return redirect(url_for("usuarios.usuarios_nuevo"))

    if not email or "@" not in email:
        flash("Debes indicar un correo electrónico válido.", "danger")
        return redirect(url_for("usuarios.usuarios_nuevo"))

    if rol not in ("ADMIN", "OPERADOR", "REVISOR"):
        flash("Rol inválido.", "danger")
        return redirect(url_for("usuarios.usuarios_nuevo"))

    if len(password) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.", "danger")
        return redirect(url_for("usuarios.usuarios_nuevo"))

    if Usuario.query.filter_by(username=username).first():
        flash("Ese username ya existe.", "warning")
        return redirect(url_for("usuarios.usuarios_listado", q=username))

    if Usuario.query.filter_by(rut=rut).first():
        flash("Ese RUT ya está registrado en otro usuario.", "warning")
        return redirect(url_for("usuarios.usuarios_listado", q=rut))

    if Usuario.query.filter_by(email=email).first():
        flash("Ese correo ya está registrado en otro usuario.", "warning")
        return redirect(url_for("usuarios.usuarios_listado", q=email))

    u = Usuario(
        username=username,
        rol=rol,
        activo=activo,
        debe_cambiar_password=debe_cambiar_password,
        nombre_completo=nombre_completo,
        rut=rut,
        email=email,
    )
    u.set_password(password)

    if rol != "ADMIN" and inst_ids:
        u.instalaciones = Instalacion.query.filter(Instalacion.id.in_(inst_ids)).all()
    else:
        u.instalaciones = []

    db.session.add(u)
    db.session.commit()

    audit(
        "USER_CREATE",
        target_user_id=u.id,
        detalle=f"Creado usuario {u.username} ({u.rol})",
    )

    flash("Usuario creado correctamente.", "success")
    return redirect(url_for("usuarios.usuarios_listado"))


@usuarios_bp.route("/usuarios/<int:user_id>/editar", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def usuarios_editar(user_id):
    u = Usuario.query.options(selectinload(Usuario.instalaciones)).get_or_404(user_id)
    instalaciones = Instalacion.query.order_by(Instalacion.nombre.asc()).all()

    if request.method == "GET":
        asignadas_ids = {i.id for i in (u.instalaciones or [])}
        return render_template(
            "usuarios_form.html",
            modo="editar",
            u=u,
            instalaciones=instalaciones,
            asignadas_ids=asignadas_ids,
        )

    rol = (request.form.get("rol") or "REVISOR").strip().upper()
    activo = True if request.form.get("activo") == "on" else False
    debe_cambiar_password = (
        True if request.form.get("debe_cambiar_password") == "on" else False
    )

    inst_ids = request.form.getlist("instalaciones")
    inst_ids = [int(x) for x in inst_ids if str(x).isdigit()]

    # nuevos campos
    nombre_completo = (request.form.get("nombre_completo") or "").strip()
    rut = normalizar_rut(request.form.get("rut") or "")
    email = normalizar_email(request.form.get("email") or "")

    # reset contraseña opcional
    new_password = (request.form.get("new_password") or "").strip()
    new_password2 = (request.form.get("new_password2") or "").strip()

    if rol not in ("ADMIN", "OPERADOR", "REVISOR"):
        flash("Rol inválido.", "danger")
        return redirect(url_for("usuarios.usuarios_editar", user_id=u.id))

    if not nombre_completo:
        flash("Debes indicar el nombre completo.", "danger")
        return redirect(url_for("usuarios.usuarios_editar", user_id=u.id))

    if not rut or not rut_dv_valido(rut):
        flash("Debes indicar un RUT válido (DV correcto).", "danger")
        return redirect(url_for("usuarios.usuarios_editar", user_id=u.id))

    if not email or "@" not in email:
        flash("Debes indicar un correo electrónico válido.", "danger")
        return redirect(url_for("usuarios.usuarios_editar", user_id=u.id))

    # Unicidad excluyendo al mismo usuario
    existe_rut = Usuario.query.filter(Usuario.rut == rut, Usuario.id != u.id).first()
    if existe_rut:
        flash("Ese RUT ya está registrado en otro usuario.", "warning")
        return redirect(url_for("usuarios.usuarios_editar", user_id=u.id))

    existe_email = Usuario.query.filter(
        Usuario.email == email, Usuario.id != u.id
    ).first()
    if existe_email:
        flash("Ese correo ya está registrado en otro usuario.", "warning")
        return redirect(url_for("usuarios.usuarios_editar", user_id=u.id))

    # Actualización base
    cambios = []
    if u.rol != rol:
        cambios.append(f"rol: {u.rol} -> {rol}")
    if u.activo != activo:
        cambios.append(f"activo: {u.activo} -> {activo}")
    if (u.nombre_completo or "") != nombre_completo:
        cambios.append("nombre_completo actualizado")
    if (u.rut or "") != rut:
        cambios.append("rut actualizado")
    if (u.email or "") != email:
        cambios.append("email actualizado")

    u.rol = rol
    u.activo = activo
    u.nombre_completo = nombre_completo
    u.rut = rut
    u.email = email

    # Si se resetea contraseña, obligamos cambio
    if new_password or new_password2:
        if len(new_password) < 6:
            flash("La nueva contraseña debe tener al menos 6 caracteres.", "danger")
            return redirect(url_for("usuarios.usuarios_editar", user_id=u.id))

        if new_password != new_password2:
            flash("Las contraseñas no coinciden.", "danger")
            return redirect(url_for("usuarios.usuarios_editar", user_id=u.id))

        u.set_password(new_password)
        u.debe_cambiar_password = True
        audit(
            "USER_RESET_PW",
            target_user_id=u.id,
            detalle=f"Reset contraseña para {u.username}",
        )
        flash(
            "Contraseña reseteada. El usuario deberá cambiarla en el próximo ingreso.",
            "success",
        )
    else:
        u.debe_cambiar_password = debe_cambiar_password

    # Scope por obras
    if rol == "ADMIN":
        u.instalaciones = []
    else:
        u.instalaciones = (
            Instalacion.query.filter(Instalacion.id.in_(inst_ids)).all()
            if inst_ids
            else []
        )

    db.session.commit()

    audit(
        "USER_UPDATE",
        target_user_id=u.id,
        detalle="; ".join(cambios) if cambios else "Sin cambios relevantes",
    )

    flash("Usuario actualizado correctamente.", "success")
    return redirect(url_for("usuarios.usuarios_listado"))
