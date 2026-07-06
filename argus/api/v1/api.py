from fastapi import APIRouter
from argus.api.v1.endpoints import scan, redirect_scan

api_router = APIRouter()
api_router.include_router(scan.router, prefix="/scan", tags=["scan"])
api_router.include_router(redirect_scan.router, prefix="/scan-redirect", tags=["scan-redirect"])
