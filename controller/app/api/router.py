# app/api/router.py
from fastapi import APIRouter
from .endpoints import (
    admin,
    scan_jobs,
    scan_results,
    utils,
    vpn,
    workflows,
    ai_advisor,
    ai_status,
    ip_pool,
    settings,
)

api_router = APIRouter()
api_router.include_router(admin.router)
api_router.include_router(scan_jobs.router)
api_router.include_router(scan_results.router)
api_router.include_router(utils.router)
api_router.include_router(vpn.router)
api_router.include_router(workflows.router)
api_router.include_router(ai_advisor.router)
api_router.include_router(ai_status.router)
api_router.include_router(ip_pool.router)
api_router.include_router(settings.router)
