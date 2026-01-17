# app/routes/__init__.py
from flask import Blueprint

main = Blueprint("main", __name__)

__all__ = ["main"]

# Importa módulos para registrar rutas en el blueprint.
# Estos imports deben ir al final para evitar ciclos (side-effects: registran endpoints).
from . import (
    auth,  # noqa: E402,F401
    guardias,  # noqa: E402,F401
    instalaciones,  # noqa: E402,F401
    turnos,  # noqa: E402,F401
)
