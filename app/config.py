import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "cambia-esto-por-algo-serio")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://turnos_user:turnos_pass@db:5432/turnos",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
