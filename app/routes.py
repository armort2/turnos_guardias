from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    abort,
)
from datetime import datetime, timedelta, time, date
import re
from collections import defaultdict
from functools import wraps

import pandas as pd

from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.orm import selectinload
from sqlalchemy import func, case

from . import db
from .models import (
    Guardia,
    Instalacion,
    Feriado,
    TurnoRegistro,
    ConfiguracionRecargo,
    TurnoComentario,
    Usuario,
    AuditLog,
)

main = Blueprint("main", __name__)

# -------------------------------------------------------------------
# Auditoría de seguridad (login / logout)
# -------------------------------------------------------------------


def audit_login(accion: str, user_id=None, detalle: str = ""):
    """
    Auditoría simple y segura (si falla, no rompe la operación).
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


# -------------------------------------------------------------------
# Helpers generales
# -------------------------------------------------------------------


def normalizar_rut(rut: str) -> str:
    """
    Normaliza un RUT a formato '12345678-9' o '12345678-K'.
    Elimina puntos/guiones y mantiene DV en mayúscula.
    """
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


def minutos_solapados(
    a_ini: datetime, a_fin: datetime, b_ini: datetime, b_fin: datetime
) -> int:
    """
    Calcula minutos de solape entre intervalos [a_ini, a_fin) y [b_ini, b_fin).
    """
    ini = max(a_ini, b_ini)
    fin = min(a_fin, b_fin)
    if fin <= ini:
        return 0
    return int((fin - ini).total_seconds() // 60)


def calcular_minutos_feriado(inicio_dt: datetime, fin_dt: datetime) -> int:
    """
    Suma minutos del turno que caen dentro de días marcados como feriado
    (considerando ventana 00:00 a 24:00 por cada fecha).
    """
    total = 0
    d = inicio_dt.date()
    while d <= fin_dt.date():
        fer = Feriado.query.get(d)
        if fer:
            win_ini = datetime.combine(d, time(0, 0))
            win_fin = win_ini + timedelta(days=1)
            total += minutos_solapados(inicio_dt, fin_dt, win_ini, win_fin)
        d += timedelta(days=1)
    return total


def obtener_info_recargo_feriado(inicio_dt: datetime, fin_dt: datetime):
    """
    Retorna información trazable del/los feriado(s) tocados por el turno.
    - minutos_feriado_total: suma total de minutos en días feriados
    - aplicado: el feriado con mayor % (si empata, prioriza IRRENUNCIABLE)
    - detalle: string breve con desglose por fecha
    """
    items = []
    minutos_total = 0
    d = inicio_dt.date()

    while d <= fin_dt.date():
        fer = Feriado.query.get(d)
        if fer:
            win_ini = datetime.combine(d, time(0, 0))
            win_fin = win_ini + timedelta(days=1)
            mins = minutos_solapados(inicio_dt, fin_dt, win_ini, win_fin)
            if mins > 0:
                minutos_total += mins
                cfg = ConfiguracionRecargo.query.filter_by(
                    tipo_feriado=fer.tipo
                ).first()
                pct = int(cfg.porcentaje) if cfg and cfg.porcentaje is not None else 0
                items.append(
                    {
                        "fecha": d,
                        "tipo": fer.tipo,
                        "descripcion": fer.descripcion or "",
                        "minutos": mins,
                        "pct": pct,
                    }
                )
        d += timedelta(days=1)

    if not items:
        return {
            "minutos_feriado_total": 0,
            "tipo_aplicado": None,
            "pct_aplicado": None,
            "descripcion_aplicada": None,
            "detalle": None,
        }

    aplicado = max(
        items, key=lambda x: (x["pct"], 1 if x["tipo"] == "IRRENUNCIABLE" else 0)
    )

    partes = []
    for it in items:
        partes.append(
            f'{it["fecha"].strftime("%Y-%m-%d")} {it["tipo"]} {it["pct"]}% '
            f'({it["minutos"]} min) {it["descripcion"]}'.strip()
        )
    detalle = " | ".join(partes)
    if len(detalle) > 500:
        detalle = detalle[:497] + "..."

    return {
        "minutos_feriado_total": minutos_total,
        "tipo_aplicado": aplicado["tipo"],
        "pct_aplicado": aplicado["pct"],
        "descripcion_aplicada": (
            aplicado["descripcion"][:250] if aplicado.get("descripcion") else None
        ),
        "detalle": detalle,
    }


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


GUARDIAS_SIEMPRE_VALORIZAR = {
    "10700859-4": 33000,  # Mauricio Díaz: siempre adicional, base 33.000
}


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


# -------------------------------------------------------------------
# Reglas de negocio: adicionalidad, base y recargo
# -------------------------------------------------------------------


def es_turno_adicional(guardia: Guardia, inicio_dt: datetime, fin_dt: datetime) -> bool:
    if guardia.rut in GUARDIAS_SIEMPRE_VALORIZAR:
        return True

    if guardia.modalidad == "EXT":
        return True

    if guardia.modalidad == "PT":
        return True

    min_fer = calcular_minutos_feriado(inicio_dt, fin_dt)
    if min_fer > 0:
        return True

    wd_inicio = inicio_dt.weekday()
    inicia_fin_de_semana = wd_inicio in (5, 6)

    if guardia.modalidad == "JC":
        return inicia_fin_de_semana

    return False


def monto_base_turno(guardia: Guardia) -> int:
    if guardia.rut in GUARDIAS_SIEMPRE_VALORIZAR:
        return int(GUARDIAS_SIEMPRE_VALORIZAR[guardia.rut])

    if guardia.modalidad == "EXT":
        return 30000

    return 33000


def obtener_porcentaje_recargo_feriado(inicio_dt: datetime, fin_dt: datetime) -> int:
    max_pct = 0
    d = inicio_dt.date()
    while d <= fin_dt.date():
        fer = Feriado.query.get(d)
        if fer:
            cfg = ConfiguracionRecargo.query.filter_by(tipo_feriado=fer.tipo).first()
            if cfg and cfg.porcentaje is not None:
                max_pct = max(max_pct, int(cfg.porcentaje))
        d += timedelta(days=1)
    return max_pct


def recalcular_turno(
    t: TurnoRegistro, guardia: Guardia, inicio_dt: datetime, fin_dt: datetime
):
    minutos_totales = int((fin_dt - inicio_dt).total_seconds() // 60)

    info = obtener_info_recargo_feriado(inicio_dt, fin_dt)
    minutos_feriado = info["minutos_feriado_total"]

    adicional = es_turno_adicional(guardia, inicio_dt, fin_dt)

    if adicional:
        base = monto_base_turno(guardia)

        pct = info["pct_aplicado"] or 0
        if pct > 0 and minutos_feriado > 0 and minutos_totales > 0:
            horas_turno = minutos_totales / 60.0
            valor_hora = base / horas_turno
            recargo = int(valor_hora * (minutos_feriado / 60.0) * (pct / 100.0))
        else:
            recargo = 0

        total = base + recargo
    else:
        base = 0
        recargo = 0
        total = 0

    t.inicio_dt = inicio_dt
    t.fin_dt = fin_dt
    t.minutos_totales = minutos_totales
    t.minutos_feriado = minutos_feriado
    t.es_adicional = adicional
    t.monto_base = base
    t.monto_recargo = recargo
    t.monto_total = total

    if minutos_feriado > 0:
        t.feriado_tipo_aplicado = info["tipo_aplicado"]
        t.feriado_porcentaje_aplicado = info["pct_aplicado"]
        t.feriado_descripcion_aplicada = info["descripcion_aplicada"]
        t.feriado_detalle_calculo = info["detalle"]
    else:
        t.feriado_tipo_aplicado = None
        t.feriado_porcentaje_aplicado = None
        t.feriado_descripcion_aplicada = None
        t.feriado_detalle_calculo = None


# -------------------------------------------------------------------
# Rutas principales
# -------------------------------------------------------------------


@main.get("/")
def index():
    stats = {
        "guardias": Guardia.query.count(),
        "instalaciones": Instalacion.query.count(),
        "turnos": TurnoRegistro.query.count(),
        "feriados": Feriado.query.count(),
    }
    return render_template("index.html", stats=stats)


# -------------------------------------------------------------------
# Login / Logout (auditado)
# -------------------------------------------------------------------


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

        # Registrar último acceso
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
    instalaciones_creadas = 0

    for _, row in df.iterrows():
        rut = normalizar_rut(str(row[cols["RUT"]]).strip())
        if not rut or rut.lower() == "nan":
            continue

        ap_p = str(row[cols["Ap. Paterno"]]).strip()
        ap_m = str(row[cols["Ap. Materno"]]).strip()
        nom = str(row[cols["Nombres"]]).strip()
        cargo = str(row[cols["Labor a realizar"]]).strip()
        obra = str(row[cols["Nombre Obra"]]).strip()
        empleador = str(row[cols["Nombre Empleador"]]).strip()

        inst = Instalacion.query.filter_by(nombre=obra).first()
        if not inst:
            db.session.add(Instalacion(nombre=obra))
            instalaciones_creadas += 1

        g = Guardia.query.get(rut)

        modalidad_sugerida = "EXT" if "EXTERNO" in empleador.upper() else "JC"

        if not g:
            g = Guardia(
                rut=rut,
                ap_paterno=ap_p,
                ap_materno=ap_m if ap_m.lower() != "nan" else "",
                nombres=nom,
                cargo=cargo,
                empleador=empleador,
                obra_base=obra,
                modalidad=modalidad_sugerida,
                activo=True,
            )
            db.session.add(g)
            creados += 1
        else:
            g.ap_paterno = ap_p
            g.ap_materno = ap_m if ap_m.lower() != "nan" else ""
            g.nombres = nom
            g.cargo = cargo
            g.empleador = empleador
            g.obra_base = obra

            if not getattr(g, "modalidad", None):
                g.modalidad = modalidad_sugerida

            actualizados += 1

    db.session.commit()
    flash(
        f"Importación OK. Guardias creados: {creados}, actualizados: {actualizados}. "
        f"Instalaciones nuevas: {instalaciones_creadas}.",
        "success",
    )
    return redirect(url_for("main.index"))


# -------------------------------------------------------------------
# API para autocompletar guardias
# -------------------------------------------------------------------


@main.get("/api/guardias")
@login_required
def api_guardias():
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify([])

    res = (
        Guardia.query.filter(
            (Guardia.rut.ilike(f"%{q}%"))
            | (Guardia.ap_paterno.ilike(f"%{q}%"))
            | (Guardia.ap_materno.ilike(f"%{q}%"))
            | (Guardia.nombres.ilike(f"%{q}%"))
        )
        .limit(20)
        .all()
    )

    out = [
        {
            "rut": g.rut,
            "label": f"{g.rut} — {g.ap_paterno} {g.ap_materno or ''} {g.nombres} ({g.modalidad})",
        }
        for g in res
    ]
    return jsonify(out)


@main.get("/api/guardias-por-instalacion")
@login_required
def api_guardias_por_instalacion():
    inst_id = request.args.get("inst_id", type=int)
    if not inst_id:
        return jsonify([])

    exigir_acceso_instalacion(inst_id)

    ruts = (
        db.session.query(TurnoRegistro.guardia_rut)
        .filter(TurnoRegistro.instalacion_id == inst_id)
        .filter(TurnoRegistro.anulado == False)  # noqa: E712
        .distinct()
        .all()
    )

    ruts = [r[0] for r in ruts]
    if not ruts:
        return jsonify([])

    guardias = (
        Guardia.query.filter(Guardia.rut.in_(ruts))
        .filter(Guardia.activo == True)  # noqa: E712
        .order_by(Guardia.ap_paterno.asc(), Guardia.nombres.asc())
        .all()
    )

    out = [
        {
            "rut": g.rut,
            "label": f"{g.ap_paterno} {g.ap_materno or ''} {g.nombres} — {g.rut} ({g.modalidad})".replace(
                "  ", " "
            ).strip(),
        }
        for g in guardias
    ]

    return jsonify(out)


# -------------------------------------------------------------------
# Turnos: crear, listar, editar, anular
# -------------------------------------------------------------------


@main.route("/turnos/nuevo", methods=["GET", "POST"])
@login_required
@role_required("ADMIN", "OPERADOR")
def nuevo_turno():
    instalaciones = (
        instalaciones_permitidas_query().order_by(Instalacion.nombre.asc()).all()
    )
    if not instalaciones:
        flash("No tienes obras asignadas.", "warning")
        return redirect(url_for("main.index"))

    if request.method == "GET":
        return render_template("nuevo_turno.html", instalaciones=instalaciones)

    instalacion_id = int(request.form["instalacion_id"])
    exigir_acceso_instalacion(instalacion_id)

    fecha = request.form["fecha"]
    turno_codigo = request.form["turno_codigo"]
    guardia_rut = normalizar_rut(request.form["guardia_rut"])
    observacion = (request.form.get("observacion") or "").strip()

    guardia = Guardia.query.get(guardia_rut)
    if not guardia:
        flash(
            "Guardia no encontrado. Usa el autocompletar o importa la dotación.",
            "danger",
        )
        return redirect(url_for("main.nuevo_turno"))

    try:
        f = datetime.strptime(fecha, "%Y-%m-%d").date()
    except Exception:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("main.nuevo_turno"))

    if turno_codigo == "DIA":
        inicio_dt = datetime.combine(f, time(8, 0))
        fin_dt = datetime.combine(f, time(20, 0))
    else:
        inicio_dt = datetime.combine(f, time(20, 0))
        fin_dt = datetime.combine(f + timedelta(days=1), time(8, 0))

    t = TurnoRegistro(
        guardia_rut=guardia.rut,
        instalacion_id=instalacion_id,
        inicio_dt=inicio_dt,
        fin_dt=fin_dt,
        turno_codigo=turno_codigo,
        observacion=observacion,
    )
    recalcular_turno(t, guardia, inicio_dt, fin_dt)

    db.session.add(t)
    db.session.commit()

    flash(
        f"Turno guardado. Adicional: {'Sí' if t.es_adicional else 'No'}. "
        f"Minutos feriado: {t.minutos_feriado}. Monto: ${t.monto_total:,}".replace(
            ",", "."
        ),
        "success",
    )
    return redirect(url_for("main.turnos_listado"))


@main.get("/turnos")
@login_required
def turnos_listado():
    if current_user.es_admin():
        inst_ids = None
    else:
        inst_ids = [i.id for i in (current_user.instalaciones or [])]
        if not inst_ids:
            return render_template(
                "turnos_listado.html", dias=[], guardias_map={}, instalaciones_map={}
            )

    q = TurnoRegistro.query.options(
        selectinload(TurnoRegistro.comentarios).selectinload(TurnoComentario.autor)
    ).filter(
        TurnoRegistro.anulado == False
    )  # noqa: E712

    if inst_ids is not None:
        q = q.filter(TurnoRegistro.instalacion_id.in_(inst_ids))

    turnos = (
        q.order_by(TurnoRegistro.inicio_dt.asc(), TurnoRegistro.id.asc())
        .limit(500)
        .all()
    )

    ruts = list({t.guardia_rut for t in turnos})
    inst_ids2 = list({t.instalacion_id for t in turnos})

    guardias = Guardia.query.filter(Guardia.rut.in_(ruts)).all() if ruts else []
    instalaciones = (
        Instalacion.query.filter(Instalacion.id.in_(inst_ids2)).all()
        if inst_ids2
        else []
    )

    guardias_map = {g.rut: g for g in guardias}
    instalaciones_map = {i.id: i for i in instalaciones}

    grupos = defaultdict(list)
    for t in turnos:
        grupos[t.inicio_dt.date()].append(t)

    dias = []
    for dia, lista in grupos.items():
        lista.sort(key=lambda x: x.id)

        guardias_unicos = len({x.guardia_rut for x in lista})
        valorizados = [x for x in lista if x.es_adicional and (x.monto_total or 0) > 0]
        total_valorizado = sum((x.monto_total or 0) for x in valorizados)

        dias.append(
            {
                "fecha": dia,
                "nombre_dia": nombre_dia_es(dia),
                "turnos": lista,
                "guardias_unicos": guardias_unicos,
                "cantidad_turnos": len(lista),
                "cantidad_valorizados": len(valorizados),
                "total_valorizado": total_valorizado,
            }
        )

    dias.sort(key=lambda x: x["fecha"], reverse=True)

    return render_template(
        "turnos_listado.html",
        dias=dias,
        guardias_map=guardias_map,
        instalaciones_map=instalaciones_map,
    )


@main.route("/turnos/<int:turno_id>/editar", methods=["GET", "POST"])
@login_required
@role_required("ADMIN", "OPERADOR")
def editar_turno(turno_id):
    t = TurnoRegistro.query.get_or_404(turno_id)
    exigir_acceso_instalacion(t.instalacion_id)

    instalaciones = (
        instalaciones_permitidas_query().order_by(Instalacion.nombre.asc()).all()
    )

    if request.method == "GET":
        return render_template(
            "editar_turno.html", turno=t, instalaciones=instalaciones
        )

    instalacion_id = int(request.form["instalacion_id"])
    exigir_acceso_instalacion(instalacion_id)

    fecha = request.form["fecha"]
    turno_codigo = request.form["turno_codigo"]
    guardia_rut = normalizar_rut(request.form["guardia_rut"])
    observacion = (request.form.get("observacion") or "").strip()

    guardia = Guardia.query.get(guardia_rut)
    if not guardia:
        flash("Guardia no encontrado.", "danger")
        return redirect(url_for("main.editar_turno", turno_id=turno_id))

    try:
        f = datetime.strptime(fecha, "%Y-%m-%d").date()
    except Exception:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("main.editar_turno", turno_id=turno_id))

    if turno_codigo == "DIA":
        inicio_dt = datetime.combine(f, time(8, 0))
        fin_dt = datetime.combine(f, time(20, 0))
    else:
        inicio_dt = datetime.combine(f, time(20, 0))
        fin_dt = datetime.combine(f + timedelta(days=1), time(8, 0))

    t.guardia_rut = guardia.rut
    t.instalacion_id = instalacion_id
    t.turno_codigo = turno_codigo
    t.observacion = observacion

    recalcular_turno(t, guardia, inicio_dt, fin_dt)

    db.session.commit()
    flash("Turno actualizado y recalculado correctamente.", "success")
    return redirect(url_for("main.turnos_listado"))


@main.post("/turnos/<int:turno_id>/anular")
@login_required
@role_required("ADMIN", "OPERADOR")
def anular_turno(turno_id):
    t = TurnoRegistro.query.get_or_404(turno_id)
    exigir_acceso_instalacion(t.instalacion_id)

    motivo = (request.form.get("motivo") or "").strip()

    t.anulado = True
    t.anulado_en = datetime.utcnow()
    t.anulado_motivo = motivo[:250] if motivo else "Anulado por corrección"

    t.monto_base = 0
    t.monto_recargo = 0
    t.monto_total = 0
    t.es_adicional = False

    db.session.commit()
    flash("Turno anulado. Se mantuvo trazabilidad y se dejó en $0.", "warning")
    return redirect(url_for("main.turnos_listado"))


# -------------------------------------------------------------------
# Recalcular masivamente turnos PT (opcional)
# -------------------------------------------------------------------


@main.post("/turnos/recalcular-pt")
@login_required
@role_required("ADMIN", "OPERADOR")
def recalcular_turnos_pt():
    hoy = date.today()
    desde_str = (request.form.get("desde") or "").strip()
    hasta_str = (request.form.get("hasta") or "").strip()

    if desde_str:
        try:
            desde = datetime.strptime(desde_str, "%Y-%m-%d").date()
        except Exception:
            flash("Fecha 'desde' inválida (formato YYYY-MM-DD).", "danger")
            return redirect(request.referrer or url_for("main.turnos_listado"))
    else:
        desde = date(hoy.year, hoy.month, 1)

    if hasta_str:
        try:
            hasta = datetime.strptime(hasta_str, "%Y-%m-%d").date()
        except Exception:
            flash("Fecha 'hasta' inválida (formato YYYY-MM-DD).", "danger")
            return redirect(request.referrer or url_for("main.turnos_listado"))
    else:
        if hoy.month == 12:
            hasta = date(hoy.year, 12, 31)
        else:
            hasta = date(hoy.year, hoy.month + 1, 1) - timedelta(days=1)

    dt_desde = datetime.combine(desde, time(0, 0))
    dt_hasta_excl = datetime.combine(hasta + timedelta(days=1), time(0, 0))

    if current_user.es_admin():
        inst_ids = None
    else:
        inst_ids = [i.id for i in (current_user.instalaciones or [])]
        if not inst_ids:
            flash("No tienes obras asignadas.", "warning")
            return redirect(request.referrer or url_for("main.turnos_listado"))

    q = (
        db.session.query(TurnoRegistro)
        .join(Guardia, Guardia.rut == TurnoRegistro.guardia_rut)
        .filter(TurnoRegistro.anulado == False)  # noqa: E712
        .filter(Guardia.modalidad == "PT")
        .filter(TurnoRegistro.inicio_dt >= dt_desde)
        .filter(TurnoRegistro.inicio_dt < dt_hasta_excl)
    )

    if inst_ids is not None:
        q = q.filter(TurnoRegistro.instalacion_id.in_(inst_ids))

    turnos = q.order_by(TurnoRegistro.id.asc()).all()

    recalculados = 0
    for t in turnos:
        g = Guardia.query.get(t.guardia_rut)
        if not g:
            continue
        recalcular_turno(t, g, t.inicio_dt, t.fin_dt)
        recalculados += 1

    db.session.commit()
    flash(f"Recalculo PT OK. Turnos recalculados: {recalculados}.", "success")
    return redirect(request.referrer or url_for("main.turnos_listado"))


# -------------------------------------------------------------------
# Comentarios de revisión
# -------------------------------------------------------------------


@main.post("/turnos/<int:turno_id>/comentar")
@login_required
@role_required("ADMIN", "OPERADOR", "REVISOR")
def turno_comentar(turno_id):
    t = TurnoRegistro.query.get_or_404(turno_id)
    exigir_acceso_instalacion(t.instalacion_id)

    texto = (request.form.get("texto") or "").strip()
    if not texto:
        flash("El comentario no puede estar vacío.", "danger")
        return redirect(request.referrer or url_for("main.turnos_listado"))

    c = TurnoComentario(turno_id=t.id, autor_id=current_user.id, texto=texto[:500])
    db.session.add(c)
    db.session.commit()

    flash("Comentario registrado.", "success")
    return redirect(request.referrer or url_for("main.turnos_listado"))


@main.post("/comentarios/<int:comentario_id>/resolver")
@login_required
@role_required("ADMIN", "OPERADOR")
def comentario_resolver(comentario_id):
    c = TurnoComentario.query.get_or_404(comentario_id)
    exigir_acceso_instalacion(c.turno.instalacion_id)

    c.resuelto = True
    c.resuelto_en = datetime.utcnow()
    db.session.commit()

    flash("Comentario marcado como resuelto.", "success")
    return redirect(request.referrer or url_for("main.turnos_listado"))


# -------------------------------------------------------------------
# Consulta por trabajador
# -------------------------------------------------------------------


@main.route("/turnos/por-guardia", methods=["GET"])
@login_required
@role_required("ADMIN", "OPERADOR", "REVISOR")
def turnos_por_guardia():
    instalacion_id = request.args.get("instalacion_id", type=int)
    guardia_rut = normalizar_rut((request.args.get("guardia_rut") or "").strip())
    desde_str = (request.args.get("desde") or "").strip()
    hasta_str = (request.args.get("hasta") or "").strip()

    hoy = date.today()
    desde = None
    hasta = None

    if desde_str:
        try:
            desde = datetime.strptime(desde_str, "%Y-%m-%d").date()
        except Exception:
            flash("Fecha 'desde' inválida (formato YYYY-MM-DD).", "danger")
            return redirect(url_for("main.turnos_por_guardia"))

    if hasta_str:
        try:
            hasta = datetime.strptime(hasta_str, "%Y-%m-%d").date()
        except Exception:
            flash("Fecha 'hasta' inválida (formato YYYY-MM-DD).", "danger")
            return redirect(url_for("main.turnos_por_guardia"))

    sugerido_desde = date(hoy.year, hoy.month, 1)
    if hoy.month == 12:
        sugerido_hasta = date(hoy.year, 12, 31)
    else:
        sugerido_hasta = date(hoy.year, hoy.month + 1, 1) - timedelta(days=1)

    instalaciones = (
        instalaciones_permitidas_query().order_by(Instalacion.nombre.asc()).all()
    )
    guardia = Guardia.query.get(guardia_rut) if guardia_rut else None

    turnos = []
    resumen = {
        "instalacion_id": instalacion_id,
        "instalacion_nombre": "",
        "rut": guardia_rut or "",
        "nombre": "",
        "modalidad": "",
        "desde": desde,
        "hasta": hasta,
        "cantidad_turnos": 0,
        "cantidad_valorizados": 0,
        "monto_total": 0,
        "monto_base": 0,
        "monto_recargo": 0,
        "minutos_feriado": 0,
        "turnos_dia": 0,
        "turnos_noche": 0,
    }

    if instalacion_id:
        exigir_acceso_instalacion(instalacion_id)
        inst = Instalacion.query.get(instalacion_id)
        if inst:
            resumen["instalacion_nombre"] = inst.nombre

    if instalacion_id and guardia:
        q = (
            TurnoRegistro.query.options(
                selectinload(TurnoRegistro.comentarios).selectinload(
                    TurnoComentario.autor
                )
            )
            .filter_by(anulado=False)
            .filter(TurnoRegistro.instalacion_id == instalacion_id)
            .filter(TurnoRegistro.guardia_rut == guardia.rut)
        )

        if desde:
            q = q.filter(TurnoRegistro.inicio_dt >= datetime.combine(desde, time(0, 0)))
        if hasta:
            q = q.filter(
                TurnoRegistro.inicio_dt
                < datetime.combine(hasta + timedelta(days=1), time(0, 0))
            )

        turnos = q.order_by(TurnoRegistro.id.asc()).all()

        resumen["rut"] = guardia.rut
        resumen["nombre"] = (
            f"{guardia.ap_paterno} {guardia.ap_materno or ''} {guardia.nombres}".strip()
        )
        resumen["modalidad"] = guardia.modalidad or ""
        resumen["cantidad_turnos"] = len(turnos)

        valorizados = [t for t in turnos if (t.monto_total or 0) > 0 and t.es_adicional]
        resumen["cantidad_valorizados"] = len(valorizados)
        resumen["monto_total"] = sum((t.monto_total or 0) for t in valorizados)
        resumen["monto_base"] = sum((t.monto_base or 0) for t in valorizados)
        resumen["monto_recargo"] = sum((t.monto_recargo or 0) for t in valorizados)
        resumen["minutos_feriado"] = sum((t.minutos_feriado or 0) for t in turnos)
        resumen["turnos_dia"] = sum(1 for t in turnos if t.turno_codigo == "DIA")
        resumen["turnos_noche"] = sum(1 for t in turnos if t.turno_codigo != "DIA")

    return render_template(
        "turnos_por_guardia.html",
        instalaciones=instalaciones,
        instalacion_id=instalacion_id,
        guardia_rut=guardia_rut,
        guardia=guardia,
        turnos=turnos,
        resumen=resumen,
        sugerido_desde=sugerido_desde,
        sugerido_hasta=sugerido_hasta,
    )


# -------------------------------------------------------------------
# Gestión de recargos por tipo de feriado
# -------------------------------------------------------------------


@main.route("/config/recargos", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def config_recargos():
    tipos = ["NORMAL", "IRRENUNCIABLE"]

    if request.method == "POST":
        for tipo in tipos:
            pct_str = (request.form.get(f"pct_{tipo}") or "").strip()
            try:
                pct = int(pct_str)
            except Exception:
                pct = 0

            cfg = ConfiguracionRecargo.query.filter_by(tipo_feriado=tipo).first()
            if not cfg:
                cfg = ConfiguracionRecargo(tipo_feriado=tipo, porcentaje=pct)
                db.session.add(cfg)
            else:
                cfg.porcentaje = pct

        db.session.commit()
        flash("Configuración de recargos guardada correctamente.", "success")
        return redirect(url_for("main.config_recargos"))

    existentes = {c.tipo_feriado: c for c in ConfiguracionRecargo.query.all()}
    data = []
    for tipo in tipos:
        data.append(
            {
                "tipo": tipo,
                "pct": (
                    int(existentes[tipo].porcentaje)
                    if tipo in existentes and existentes[tipo].porcentaje is not None
                    else 0
                ),
            }
        )

    return render_template("config_recargos.html", data=data)


@main.route("/feriados", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def feriados_listado():
    if request.method == "POST":
        fecha_str = (request.form.get("fecha") or "").strip()
        tipo = (request.form.get("tipo") or "NORMAL").strip().upper()
        descripcion = (request.form.get("descripcion") or "").strip()

        try:
            f = datetime.strptime(fecha_str, "%Y-%m-%d").date()
        except Exception:
            flash("Fecha inválida.", "danger")
            return redirect(url_for("main.feriados_listado"))

        if tipo not in ("NORMAL", "IRRENUNCIABLE"):
            flash("Tipo inválido. Usa NORMAL o IRRENUNCIABLE.", "danger")
            return redirect(url_for("main.feriados_listado"))

        fer = Feriado.query.get(f)
        if not fer:
            fer = Feriado(fecha=f, tipo=tipo, descripcion=descripcion)
            db.session.add(fer)
        else:
            fer.tipo = tipo
            fer.descripcion = descripcion

        db.session.commit()
        flash("Feriado guardado correctamente.", "success")
        return redirect(url_for("main.feriados_listado"))

    feriados = Feriado.query.order_by(Feriado.fecha.desc()).limit(300).all()
    return render_template("feriados_listado.html", feriados=feriados)


@main.post("/feriados/<fecha>/eliminar")
@login_required
@role_required("ADMIN")
def feriado_eliminar(fecha):
    try:
        f = datetime.strptime(fecha, "%Y-%m-%d").date()
    except Exception:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("main.feriados_listado"))

    fer = Feriado.query.get_or_404(f)
    db.session.delete(fer)
    db.session.commit()
    flash("Feriado eliminado.", "warning")
    return redirect(url_for("main.feriados_listado"))


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

    if not rut or len(rut) < 3:
        flash("RUT inválido.", "danger")
        return redirect(url_for("main.guardia_nuevo"))

    if not ap_paterno or not nombres:
        flash("Debe indicar al menos Ap. Paterno y Nombres.", "danger")
        return redirect(url_for("main.guardia_nuevo"))

    if modalidad not in ("JC", "PT", "EXT"):
        flash("Modalidad inválida.", "danger")
        return redirect(url_for("main.guardia_nuevo"))

    if Guardia.query.get(rut):
        flash(
            "Ese RUT ya existe. Puedes editar el guardia desde el listado.", "warning"
        )
        return redirect(url_for("main.guardias_listado", q=rut))

    if obra_base:
        inst = Instalacion.query.filter_by(nombre=obra_base).first()
        if not inst:
            db.session.add(Instalacion(nombre=obra_base))

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

    g.ap_paterno = ap_paterno
    g.ap_materno = ap_materno
    g.nombres = nombres
    g.cargo = cargo
    g.empleador = empleador
    g.obra_base = obra_base
    g.modalidad = modalidad
    g.activo = activo

    if obra_base:
        inst = Instalacion.query.filter_by(nombre=obra_base).first()
        if not inst:
            db.session.add(Instalacion(nombre=obra_base))

    db.session.commit()
    flash("Guardia actualizado correctamente.", "success")
    return redirect(url_for("main.guardias_listado", q=g.rut))


# -------------------------------------------------------------------
# Reportes
# -------------------------------------------------------------------


@main.route("/reportes/resumen-turnos", methods=["GET"])
@login_required
@role_required("ADMIN", "OPERADOR", "REVISOR")
def reporte_resumen_turnos():
    instalacion_id = request.args.get("instalacion_id", type=int)
    desde_str = (request.args.get("desde") or "").strip()
    hasta_str = (request.args.get("hasta") or "").strip()
    solo_valorizados = True if request.args.get("solo_valorizados") == "1" else False
    incluir_anulados = True if request.args.get("incluir_anulados") == "1" else False

    hoy = date.today()
    sugerido_desde = date(hoy.year, hoy.month, 1)
    sugerido_hasta = (
        date(hoy.year, 12, 31)
        if hoy.month == 12
        else (date(hoy.year, hoy.month + 1, 1) - timedelta(days=1))
    )

    desde = None
    hasta = None
    if desde_str:
        try:
            desde = datetime.strptime(desde_str, "%Y-%m-%d").date()
        except Exception:
            flash("Fecha 'desde' inválida (YYYY-MM-DD).", "danger")
            return redirect(url_for("main.reporte_resumen_turnos"))
    if hasta_str:
        try:
            hasta = datetime.strptime(hasta_str, "%Y-%m-%d").date()
        except Exception:
            flash("Fecha 'hasta' inválida (YYYY-MM-DD).", "danger")
            return redirect(url_for("main.reporte_resumen_turnos"))

    if not desde:
        desde = sugerido_desde
    if not hasta:
        hasta = sugerido_hasta

    instalaciones = (
        instalaciones_permitidas_query().order_by(Instalacion.nombre.asc()).all()
    )
    if not current_user.es_admin():
        inst_ids_scope = [i.id for i in (current_user.instalaciones or [])]
    else:
        inst_ids_scope = None

    if instalacion_id:
        exigir_acceso_instalacion(instalacion_id)

    q = (
        db.session.query(
            TurnoRegistro.guardia_rut.label("rut"),
            func.count(TurnoRegistro.id).label("turnos_totales"),
            func.sum(case((TurnoRegistro.turno_codigo == "DIA", 1), else_=0)).label(
                "turnos_dia"
            ),
            func.sum(case((TurnoRegistro.turno_codigo != "DIA", 1), else_=0)).label(
                "turnos_noche"
            ),
            func.sum(
                case(
                    (
                        (TurnoRegistro.monto_total > 0)
                        & (TurnoRegistro.es_adicional == True),
                        1,
                    ),
                    else_=0,
                )
            ).label("turnos_valorizados"),
            func.coalesce(func.sum(TurnoRegistro.minutos_feriado), 0).label(
                "minutos_feriado"
            ),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (TurnoRegistro.monto_total > 0)
                            & (TurnoRegistro.es_adicional == True),
                            TurnoRegistro.monto_base,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("monto_base"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (TurnoRegistro.monto_total > 0)
                            & (TurnoRegistro.es_adicional == True),
                            TurnoRegistro.monto_recargo,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("monto_recargo"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (TurnoRegistro.monto_total > 0)
                            & (TurnoRegistro.es_adicional == True),
                            TurnoRegistro.monto_total,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("monto_total"),
        )
        .filter(TurnoRegistro.inicio_dt >= datetime.combine(desde, time(0, 0)))
        .filter(
            TurnoRegistro.inicio_dt
            < datetime.combine(hasta + timedelta(days=1), time(0, 0))
        )
    )

    if not incluir_anulados:
        q = q.filter(TurnoRegistro.anulado == False)  # noqa: E712

    if inst_ids_scope is not None:
        q = q.filter(TurnoRegistro.instalacion_id.in_(inst_ids_scope))

    if instalacion_id:
        q = q.filter(TurnoRegistro.instalacion_id == instalacion_id)

    if solo_valorizados:
        q = q.filter(TurnoRegistro.monto_total > 0).filter(
            TurnoRegistro.es_adicional == True
        )  # noqa: E712

    q = q.group_by(TurnoRegistro.guardia_rut)

    rows = q.all()

    ruts = [r.rut for r in rows]
    guardias = Guardia.query.filter(Guardia.rut.in_(ruts)).all() if ruts else []
    guardias_map = {g.rut: g for g in guardias}

    data = []
    for r in rows:
        g = guardias_map.get(r.rut)
        nombre = g.nombre_completo() if g else r.rut
        modalidad = g.modalidad if g else ""
        data.append(
            {
                "rut": r.rut,
                "nombre": nombre,
                "modalidad": modalidad,
                "turnos_totales": int(r.turnos_totales or 0),
                "turnos_valorizados": int(r.turnos_valorizados or 0),
                "turnos_dia": int(r.turnos_dia or 0),
                "turnos_noche": int(r.turnos_noche or 0),
                "minutos_feriado": int(r.minutos_feriado or 0),
                "monto_base": int(r.monto_base or 0),
                "monto_recargo": int(r.monto_recargo or 0),
                "monto_total": int(r.monto_total or 0),
            }
        )

    data.sort(key=lambda x: x["monto_total"], reverse=True)

    totales = {
        "guardias": len(data),
        "turnos_totales": sum(x["turnos_totales"] for x in data),
        "turnos_valorizados": sum(x["turnos_valorizados"] for x in data),
        "monto_base": sum(x["monto_base"] for x in data),
        "monto_recargo": sum(x["monto_recargo"] for x in data),
        "monto_total": sum(x["monto_total"] for x in data),
        "minutos_feriado": sum(x["minutos_feriado"] for x in data),
    }

    return render_template(
        "reporte_resumen_turnos.html",
        instalaciones=instalaciones,
        instalacion_id=instalacion_id,
        desde=desde,
        hasta=hasta,
        solo_valorizados=solo_valorizados,
        incluir_anulados=incluir_anulados,
        data=data,
        totales=totales,
        sugerido_desde=sugerido_desde,
        sugerido_hasta=sugerido_hasta,
    )
