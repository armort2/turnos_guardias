# app/routes/guardias.py

from flask import flash, redirect, render_template, request, url_for
from flask_login import login_required

from .. import db
from ..models import Guardia, Instalacion
from . import main
from .core import normalizar_rut
from .helpers import instalaciones_permitidas_query, role_required

# -------------------------------------------------------------------
# Constantes (listas controladas)
# -------------------------------------------------------------------

EMPLEADORES_VALIDOS = {
    "Constructora Valencia SpA",
    "Constructora Salem SpA",
    "Proveedora de Servicios Caronte SpA",
    "Proveedora de Servicios FMO SpA",
    "Transportes Terratrán SpA",
}


# -------------------------------------------------------------------
# Guardias: listado, crear, editar
# -------------------------------------------------------------------


@main.get("/guardias")
@login_required
@role_required("ADMIN", "OPERADOR", "REVISOR")
def guardias_listado():
    q = (request.args.get("q") or "").strip()

    query = Guardia.query
    if q:
        query = query.filter(
            (Guardia.rut.ilike(f"%{q}%"))
            | (Guardia.ap_paterno.ilike(f"%{q}%"))
            | (Guardia.ap_materno.ilike(f"%{q}%"))
            | (Guardia.nombres.ilike(f"%{q}%"))
            | (Guardia.empleador.ilike(f"%{q}%"))
            | (Guardia.obra_base.ilike(f"%{q}%"))
        )

    guardias = (
        query.order_by(Guardia.ap_paterno.asc(), Guardia.nombres.asc()).limit(200).all()
    )
    return render_template("guardias_listado.html", guardias=guardias, q=q)


@main.route("/guardias/nuevo", methods=["GET", "POST"])
@login_required
@role_required("ADMIN", "OPERADOR")
def guardia_nuevo():
    instalaciones = (
        instalaciones_permitidas_query().order_by(Instalacion.nombre.asc()).all()
    )
    inst_nombres_validos = {i.nombre for i in instalaciones}

    if request.method == "GET":
        return render_template(
            "guardia_form.html", modo="nuevo", instalaciones=instalaciones, g=None
        )

    rut = normalizar_rut(request.form.get("rut", ""))
    ap_paterno = (request.form.get("ap_paterno") or "").strip()
    ap_materno = (request.form.get("ap_materno") or "").strip()
    nombres = (request.form.get("nombres") or "").strip()
    cargo = (request.form.get("cargo") or "").strip()
    empleador = (request.form.get("empleador") or "").strip()
    obra_base = (request.form.get("obra_base") or "").strip()
    modalidad = (request.form.get("modalidad") or "JC").strip().upper()
    activo = True if request.form.get("activo") == "on" else False

    # Validaciones
    if not rut or len(rut) < 3:
        flash("RUT inválido.", "danger")
        return redirect(url_for("main.guardia_nuevo"))

    if not ap_paterno or not nombres:
        flash("Debe indicar al menos Ap. Paterno y Nombres.", "danger")
        return redirect(url_for("main.guardia_nuevo"))

    if modalidad not in ("JC", "PT", "EXT"):
        flash("Modalidad inválida.", "danger")
        return redirect(url_for("main.guardia_nuevo"))

    if empleador not in EMPLEADORES_VALIDOS:
        flash("Empleador inválido. Selecciona una opción de la lista.", "danger")
        return redirect(url_for("main.guardia_nuevo"))

    if not obra_base or obra_base not in inst_nombres_validos:
        flash("Obra base inválida. Selecciona una instalación permitida.", "danger")
        return redirect(url_for("main.guardia_nuevo"))

    if Guardia.query.get(rut):
        flash(
            "Ese RUT ya existe. Puedes editar el guardia desde el listado.", "warning"
        )
        return redirect(url_for("main.guardias_listado", q=rut))

    g = Guardia(
        rut=rut,
        ap_paterno=ap_paterno,
        ap_materno=ap_materno,
        nombres=nombres,
        cargo=cargo,
        empleador=empleador,
        obra_base=obra_base,
        modalidad=modalidad,
        activo=activo,
    )
    db.session.add(g)
    db.session.commit()

    flash("Guardia creado correctamente.", "success")
    return redirect(url_for("main.guardias_listado"))


@main.route("/guardias/<rut>/editar", methods=["GET", "POST"])
@login_required
@role_required("ADMIN", "OPERADOR")
def guardia_editar(rut):
    rut_n = normalizar_rut(rut)
    g = Guardia.query.get_or_404(rut_n)

    instalaciones = (
        instalaciones_permitidas_query().order_by(Instalacion.nombre.asc()).all()
    )
    inst_nombres_validos = {i.nombre for i in instalaciones}

    if request.method == "GET":
        return render_template(
            "guardia_form.html", modo="editar", instalaciones=instalaciones, g=g
        )

    ap_paterno = (request.form.get("ap_paterno") or "").strip()
    ap_materno = (request.form.get("ap_materno") or "").strip()
    nombres = (request.form.get("nombres") or "").strip()
    cargo = (request.form.get("cargo") or "").strip()
    empleador = (request.form.get("empleador") or "").strip()
    obra_base = (request.form.get("obra_base") or "").strip()
    modalidad = (request.form.get("modalidad") or "JC").strip().upper()
    activo = True if request.form.get("activo") == "on" else False

    if not ap_paterno or not nombres:
        flash("Debe indicar al menos Ap. Paterno y Nombres.", "danger")
        return redirect(url_for("main.guardia_editar", rut=g.rut))

    if modalidad not in ("JC", "PT", "EXT"):
        flash("Modalidad inválida.", "danger")
        return redirect(url_for("main.guardia_editar", rut=g.rut))

    if empleador not in EMPLEADORES_VALIDOS:
        flash("Empleador inválido. Selecciona una opción de la lista.", "danger")
        return redirect(url_for("main.guardia_editar", rut=g.rut))

    if not obra_base or obra_base not in inst_nombres_validos:
        flash("Obra base inválida. Selecciona una instalación permitida.", "danger")
        return redirect(url_for("main.guardia_editar", rut=g.rut))

    g.ap_paterno = ap_paterno
    g.ap_materno = ap_materno
    g.nombres = nombres
    g.cargo = cargo
    g.empleador = empleador
    g.obra_base = obra_base
    g.modalidad = modalidad
    g.activo = activo

    db.session.commit()
    flash("Guardia actualizado correctamente.", "success")
    return redirect(url_for("main.guardias_listado", q=g.rut))
