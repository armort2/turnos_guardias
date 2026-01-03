from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from . import db


# -------------------------------------------------------------------
# ENUMS (PostgreSQL)
# -------------------------------------------------------------------
TIPO_FERIADO_ENUM = db.Enum("NORMAL", "IRRENUNCIABLE", name="tipo_feriado")
MODALIDAD_GUARDIA_ENUM = db.Enum("JC", "PT", "EXT", name="modalidad_guardia")
TURNO_CODIGO_ENUM = db.Enum("DIA", "NOCHE", name="turno_codigo")


# -------------------------------------------------------------------
# Tabla puente: usuarios asignados a instalaciones (scope)
# -------------------------------------------------------------------
usuario_instalacion = db.Table(
    "usuarios_instalaciones",
    db.Column("usuario_id", db.Integer, db.ForeignKey("usuarios.id"), primary_key=True),
    db.Column("instalacion_id", db.Integer, db.ForeignKey("instalaciones.id"), primary_key=True),
    db.Column("creado_en", db.DateTime, default=datetime.utcnow, nullable=False),
)


# -------------------------------------------------------------------
# Usuario (para login + roles + scope por instalaciones)
# -------------------------------------------------------------------
class Usuario(UserMixin, db.Model):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)

    # Puede ser correo o username. Si vas a usar email, este campo cumple perfecto.
    username = db.Column(db.String(120), unique=True, nullable=False)

    # Datos de perfil (para administración y auditoría)
    rut = db.Column(db.String(20), unique=True, nullable=True)              # Ej: 12345678-9
    nombre_completo = db.Column(db.String(160), nullable=True)              # Ej: Juan Pérez Soto
    email = db.Column(db.String(160), unique=True, nullable=True)           # contacto/recuperación
    ultimo_acceso = db.Column(db.DateTime, nullable=True)                   # auditoría

    # Hash de contraseña (nunca guardar la contraseña en texto)
    password_hash = db.Column(db.String(255), nullable=False)

    # Roles esperados: ADMIN / OPERADOR / REVISOR
    rol = db.Column(db.String(20), nullable=False, default="REVISOR")

    activo = db.Column(db.Boolean, nullable=False, default=True)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    debe_cambiar_password = db.Column(db.Boolean, default=True, nullable=False)

    instalaciones = db.relationship(
        "Instalacion",
        secondary=usuario_instalacion,
        lazy="selectin",
        backref=db.backref("usuarios", lazy="selectin"),
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def es_admin(self) -> bool:
        return (self.rol or "").upper() == "ADMIN"

    def puede_acceder_instalacion(self, instalacion_id: int) -> bool:
        if self.es_admin():
            return True
        return any(i.id == instalacion_id for i in (self.instalaciones or []))

    def nombre_display(self) -> str:
        return (self.nombre_completo or self.username or "").strip()

    def __repr__(self) -> str:
        return f"<Usuario id={self.id} username={self.username} rol={self.rol} activo={self.activo}>"


# -------------------------------------------------------------------
# Bitácora / auditoría
# -------------------------------------------------------------------
class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    actor_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True, index=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True, index=True)

    accion = db.Column(db.String(60), nullable=False)   # ej: USER_CREATE / USER_UPDATE / USER_RESET_PW
    detalle = db.Column(db.String(500), nullable=True)

    ip = db.Column(db.String(60), nullable=True)
    user_agent = db.Column(db.String(250), nullable=True)

    creado_en = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    actor = db.relationship("Usuario", foreign_keys=[actor_id], lazy="joined")
    target_user = db.relationship("Usuario", foreign_keys=[target_user_id], lazy="joined")

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} accion={self.accion} actor={self.actor_id} target={self.target_user_id}>"


# -------------------------------------------------------------------
# Guardia
# -------------------------------------------------------------------
class Guardia(db.Model):
    __tablename__ = "guardias"

    rut = db.Column(db.String(12), primary_key=True)

    ap_paterno = db.Column(db.String(50), nullable=False)
    ap_materno = db.Column(db.String(50))
    nombres = db.Column(db.String(100), nullable=False)

    cargo = db.Column(db.String(100))
    empleador = db.Column(db.String(100))
    obra_base = db.Column(db.String(100))

    modalidad = db.Column(MODALIDAD_GUARDIA_ENUM, nullable=False, default="JC")
    activo = db.Column(db.Boolean, nullable=False, default=True)

    def nombre_completo(self) -> str:
        return f"{self.ap_paterno} {self.ap_materno or ''} {self.nombres}".replace("  ", " ").strip()

    def __repr__(self) -> str:
        return f"<Guardia rut={self.rut} nombre={self.nombre_completo()} modalidad={self.modalidad}>"


# -------------------------------------------------------------------
# Instalación / Obra
# -------------------------------------------------------------------
class Instalacion(db.Model):
    __tablename__ = "instalaciones"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False, unique=True)

    def __repr__(self) -> str:
        return f"<Instalacion id={self.id} nombre={self.nombre}>"


# -------------------------------------------------------------------
# Feriados
# -------------------------------------------------------------------
class Feriado(db.Model):
    __tablename__ = "feriados"

    fecha = db.Column(db.Date, primary_key=True)
    tipo = db.Column(TIPO_FERIADO_ENUM, nullable=False)
    descripcion = db.Column(db.String(150))

    def __repr__(self) -> str:
        return f"<Feriado fecha={self.fecha} tipo={self.tipo}>"


# -------------------------------------------------------------------
# Turnos
# -------------------------------------------------------------------
class TurnoRegistro(db.Model):
    __tablename__ = "turnos_registro"

    id = db.Column(db.Integer, primary_key=True)

    guardia_rut = db.Column(db.String(12), db.ForeignKey("guardias.rut"), nullable=False)
    instalacion_id = db.Column(db.Integer, db.ForeignKey("instalaciones.id"), nullable=False)

    comentarios = db.relationship(
        "TurnoComentario",
        backref="turno",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    inicio_dt = db.Column(db.DateTime, nullable=False)
    fin_dt = db.Column(db.DateTime, nullable=False)

    turno_codigo = db.Column(TURNO_CODIGO_ENUM, nullable=False)
    observacion = db.Column(db.String(250))

    minutos_totales = db.Column(db.Integer, nullable=False)
    minutos_feriado = db.Column(db.Integer, nullable=False, default=0)

    es_adicional = db.Column(db.Boolean, nullable=False, default=False)

    monto_base = db.Column(db.Integer, nullable=False, default=0)
    monto_recargo = db.Column(db.Integer, nullable=False, default=0)
    monto_total = db.Column(db.Integer, nullable=False, default=0)

    creado_en = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    anulado = db.Column(db.Boolean, nullable=False, default=False)
    anulado_en = db.Column(db.DateTime)
    anulado_motivo = db.Column(db.String(250))

    guardia = db.relationship("Guardia", lazy="joined")
    instalacion = db.relationship("Instalacion", lazy="joined")

    feriado_tipo_aplicado = db.Column(db.String(20), nullable=True)
    feriado_porcentaje_aplicado = db.Column(db.Integer, nullable=True)
    feriado_descripcion_aplicada = db.Column(db.String(250), nullable=True)
    feriado_detalle_calculo = db.Column(db.String(500), nullable=True)

    def __repr__(self) -> str:
        return f"<TurnoRegistro id={self.id} guardia={self.guardia_rut} inst={self.instalacion_id} anulado={self.anulado}>"


# -------------------------------------------------------------------
# Configuración de recargos por tipo de feriado
# -------------------------------------------------------------------
class ConfiguracionRecargo(db.Model):
    __tablename__ = "configuracion_recargos"

    id = db.Column(db.Integer, primary_key=True)
    tipo_feriado = db.Column(TIPO_FERIADO_ENUM, unique=True, nullable=False)
    porcentaje = db.Column(db.Integer, nullable=False, default=0)

    def __repr__(self) -> str:
        return f"<ConfiguracionRecargo tipo={self.tipo_feriado} pct={self.porcentaje}>"


# -------------------------------------------------------------------
# Comentarios / auditoría de turnos
# -------------------------------------------------------------------
class TurnoComentario(db.Model):
    __tablename__ = "turnos_comentarios"

    id = db.Column(db.Integer, primary_key=True)

    turno_id = db.Column(db.Integer, db.ForeignKey("turnos_registro.id"), nullable=False, index=True)
    autor_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False, index=True)

    texto = db.Column(db.String(500), nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    resuelto = db.Column(db.Boolean, nullable=False, default=False)
    resuelto_en = db.Column(db.DateTime, nullable=True)

    autor = db.relationship("Usuario", lazy="joined")

    def __repr__(self) -> str:
        return f"<TurnoComentario id={self.id} turno_id={self.turno_id} autor_id={self.autor_id} resuelto={self.resuelto}>"
