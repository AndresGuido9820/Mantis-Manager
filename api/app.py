from fastapi import FastAPI

from middlewares.auth_midddleware import AuthMiddleware
from middlewares.logger_middleware import LogRequestsMiddleware
from routers.user_auth_router import user_auth_router
from routers.tokens_router import tokens_router
from routers.user_image_router import user_image_router

# Crear la instancia principal de FastAPI
app = FastAPI(
    title="MANTIS MANAGER API",
    description=(
        "Mantis Manager API proporciona un conjunto de servicios avanzados para gestionar "
        "el mantenimiento de equipos y recursos dentro de la empresa Balalika S.A. "
        "Este sistema facilita la creación, seguimiento y administración de tickets de mantenimiento, "
        "incluyendo la gestión de usuarios, autenticación segura, y carga y acceso de imágenes de perfil. "
        "Es compatible con futuras ampliaciones hacia aplicaciones móviles y otros sistemas externos."
    ),
    version="0.5"
)

# Agregar el middleware de autenticación
app.add_middleware(AuthMiddleware)
app.add_middleware(LogRequestsMiddleware)

# Agregar los routers
app.include_router(user_auth_router)
app.include_router(tokens_router)   
app.include_router(user_image_router)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)