from flask import Blueprint

from . import (
    auth,  # noqa: F401
    core,  # noqa: F401
)

main = Blueprint("main", __name__)
