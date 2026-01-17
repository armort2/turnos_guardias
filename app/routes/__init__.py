from flask import Blueprint

main = Blueprint("main", __name__)

# Registro explícito de módulos de rutas
from . import (
    auth,  # noqa: F401,E402
    core,  # noqa: F401,E402
    guardias,  # noqa: F401,E402
    turnos,  # noqa: F401,E402
)
