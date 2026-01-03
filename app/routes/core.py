import re
from datetime import date
from functools import wraps

import pandas as pd
from flask import (
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from .. import db
from ..models import (
    Feriado,
    Guardia,
    Instalacion,
)
from . import main

# -------------------------------------------------------------------
# Helpers generales
# -------------------------------------------------------------------


def normalizar_rut(rut: str) -> str:
    if not rut:
        return ""
    r = rut.strip().upper()
    r = re.sub(r"[^0-9K]", "", r)
    if len(r) < 2:
        return rut.strip()
    cuerpo, dv = r[:-1], r[-1]
    try:
        return f"{int(cuerpo)}-{dv}"
    except ValueError:
        return f"{cuerpo}-{dv}"


def nombre_dia_es(fecha: date) -> str:
    dias = {
        0: "Lunes",
        1: "Martes",
        2: "Miércoles",
        3: "Jueves",
        4: "Viernes",
        5: "Sábado",
        6: "Domingo",
    }
    return dias.get(fecha.weekday(), "")


# -------------------------------------------------------------------
# Seguridad / Roles / Scope por instalación
# -------------------------------------------------------------------


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
    if current_user.es_admin():
        return Instalacion.query

    ids = [i.id for i in (current_user.instalaciones or [])]
    if not ids:
        return Instalacion.query.filter(db.text("1=0"))

    return Instalacion.query.filter(Instalacion.id.in_(ids))


def exigir_acceso_instalacion(instalacion_id: int):
    if not current_user.puede_acceder_instalacion(instalacion_id):
        abort(403)


# -------------------------------------------------------------------
# Rutas generales (no turnos)
# -------------------------------------------------------------------


@main.get("/")
def index():
    stats = {
        "guardias": Guardia.query.count(),
        "instalaciones": Instalacion.query.count(),
        "feriados": Feriado.query.count(),
    }
    return render_template("index.html", stats=stats)


# -------------------------------------------------------------------
# Importación masiva de guardias (Excel)
# -------------------------------------------------------------------


@main.route("/import-guardias", methods=["GET", "POST"])
@login_required
@role_required("ADMIN", "OPERADOR")
def import_guardias():
    if request.method == "GET":
        return render_template("import_guardias.html")

    f = request.files.get("file")
    if not f:
        flash("No se adjuntó archivo.", "danger")
        return redirect(url_for("main.import_guardias"))

    try:
        df = pd.read_excel(f, engine="openpyxl")
    except Exception as e:
        flash(f"Error leyendo Excel: {e}", "danger")
        return redirect(url_for("main.import_guardias"))

    cols = {c.strip(): c for c in df.columns}
    required = [
        "RUT",
        "Ap. Paterno",
        "Ap. Materno",
        "Nombres",
        "Labor a realizar",
        "Nombre Obra",
        "Nombre Empleador",
    ]
    faltantes = [c for c in required if c not in cols]
    if faltantes:
        flash(f"Faltan columnas: {', '.join(faltantes)}", "danger")
        return redirect(url_for("main.import_guardias"))

    creados = 0
    actualizados = 0

    for _, row in df.iterrows():
        rut = normalizar_rut(str(row[cols["RUT"]]).strip())
        if not rut or rut.lower() == "nan":
            continue

        g = Guardia.query.get(rut)
        if not g:
            g = Guardia(
                rut=rut,
                ap_paterno=str(row[cols["Ap. Paterno"]]).strip(),
                ap_materno=str(row[cols["Ap. Materno"]]).strip(),
                nombres=str(row[cols["Nombres"]]).strip(),
                cargo=str(row[cols["Labor a realizar"]]).strip(),
                empleador=str(row[cols["Nombre Empleador"]]).strip(),
                obra_base=str(row[cols["Nombre Obra"]]).strip(),
                modalidad="JC",
                activo=True,
            )
            db.session.add(g)
            creados += 1
        else:
            actualizados += 1

    db.session.commit()
    flash(
        f"Importación OK. Guardias creados: {creados}, actualizados: {actualizados}.",
        "success",
    )
    return redirect(url_for("main.index"))
