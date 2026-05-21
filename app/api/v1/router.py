"""
api/v1/router.py  (Step 4: aggiornato)
"""
from fastapi import APIRouter

from app.api.v1.endpoints import auth, tenants, roles, admin

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(tenants.router)
api_router.include_router(auth.router)
api_router.include_router(roles.router)
api_router.include_router(admin.router)
