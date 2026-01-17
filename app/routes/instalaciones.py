# app/routes/instalaciones.py
from __future__ import annotations

from flask import flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy.exc import IntegrityError

from .. import db
from ..models import Instalacion, TurnoRegistro
from . import main
from .helpers import (
    instalaciones_permitidas_query,
    role_required,
)


@main.get("/instalaciones")
@login_required
@role_required("ADMIN", "OPERADOR", "REVISOR")
def instalaciones_listado():
    """
    Listado de instalaciones/obras:
    - ADMIN: ve todas
    - OPERADOR/REVISOR: solo las asignadas (scope)
    """
    q = (request.args.get("q") or "").strip()

    query = instalaciones_permitidas_query()

    if q:
        query = query.filter(Instalacion.nombre.ilike(f"%{q}%"))

    instalaciones = query.order_by(Instalacion.nombre.asc()).limit(500).all()

    # Métrica simple: cantidad de turnos por instalación (no anulado)
    # (sin join complejo; hacemos agregado solo de las que estamos mostrando)
    ids = [i.id for i in instalaciones]
    turnos_map = {}
    if ids:
        rows = (
            db.session.query(
                TurnoRegistro.instalacion_id,
                db.func.count(TurnoRegistro.id),
            )
            .filter(TurnoRegistro.instalacion_id.in_(ids))
            .filter(TurnoRegistro.anulado.is_(False))
            .group_by(TurnoRegistro.instalacion_id)
            .all()
        )
        turnos_map = {inst_id: int(cnt) for inst_id, cnt in rows}

    return render_template(
        "instalaciones_listado.html",
        instalaciones=instalaciones,
        q=q,
        turnos_map=turnos_map,
    )


@main.route("/instalaciones/nuevo", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def instalacion_nueva():
    if request.method == "GET":
        return render_template("instalaciones_form.html", modo="nuevo", inst=None)

    nombre = (request.form.get("nombre") or "").strip()
    if not nombre:
        flash("Debes indicar el nombre de la obra/instalación.", "danger")
        return redirect(url_for("main.instalacion_nueva"))

    inst = Instalacion(nombre=nombre)
    db.session.add(inst)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Ya existe una instalación con ese nombre.", "warning")
        return redirect(url_for("main.instalacion_nueva"))

    flash("Instalación creada correctamente.", "success")
    return redirect(url_for("main.instalaciones_listado", q=nombre))


@main.route("/instalaciones/<int:instalacion_id>/editar", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def instalacion_editar(instalacion_id: int):
    inst = Instalacion.query.get_or_404(instalacion_id)

    if request.method == "GET":
        return render_template("instalaciones_form.html", modo="editar", inst=inst)

    nombre = (request.form.get("nombre") or "").strip()
    if not nombre:
        flash("Debes indicar el nombre de la obra/instalación.", "danger")
        return redirect(url_for("main.instalacion_editar", instalacion_id=inst.id))

    inst.nombre = nombre
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Ya existe una instalación con ese nombre.", "warning")
        return redirect(url_for("main.instalacion_editar", instalacion_id=inst.id))

    flash("Instalación actualizada correctamente.", "success")
    return redirect(url_for("main.instalaciones_listado", q=inst.nombre))


@main.post("/instalaciones/<int:instalacion_id>/eliminar")
@login_required
@role_required("ADMIN")
def instalacion_eliminar(instalacion_id: int):
    inst = Instalacion.query.get_or_404(instalacion_id)

    # Candado: no eliminar si hay turnos (aunque estén anulados, puedes decidir)
    usados = (
        db.session.query(TurnoRegistro.id)
        .filter(TurnoRegistro.instalacion_id == inst.id)
        .first()
        is not None
    )
    if usados:
        flash(
            "No se puede eliminar: la instalación tiene turnos asociados. "
            "Si necesitas, se puede implementar 'desactivar' en vez de eliminar.",
            "danger",
        )
        return redirect(url_for("main.instalaciones_listado", q=inst.nombre))

    db.session.delete(inst)
    db.session.commit()
    flash("Instalación eliminada.", "warning")
    return redirect(url_for("main.instalaciones_listado"))
