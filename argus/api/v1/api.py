from fastapi import APIRouter
from argus.api.v1.endpoints import scan

api_router = APIRouter()
api_router.include_router(scan.router, prefix="/scan", tags=["scan"])
