from flask import Blueprint, render_template
from flask_login import current_user, login_required

perfil_bp = Blueprint("perfil", __name__)


@perfil_bp.get("/perfil")
@login_required
def mi_perfil():
    return render_template("perfil.html", u=current_user)
