from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

from .config import Config

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()


def create_app(config_class=Config):
    """
    Application Factory.
    Permite crear la app con distintas configuraciones (prod, dev, test)
    sin acoplarse a una sola clase fija.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Inicializar extensiones
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Configuración de login
    login_manager.login_view = "main.login"
    login_manager.login_message_category = "warning"

    # Importar modelos (para que SQLAlchemy/Migrate los “vea”)
    from . import models  # noqa: F401,E402
    from .models import Usuario  # noqa: E402

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(Usuario, int(user_id))
        except Exception:
            return None

    # Registrar blueprints
    from .routes import main  # noqa: E402

    app.register_blueprint(main)

    from .usuarios_routes import usuarios_bp  # noqa: E402

    app.register_blueprint(usuarios_bp)

    from .perfil_routes import perfil_bp  # noqa: E402

    app.register_blueprint(perfil_bp)

    return app
