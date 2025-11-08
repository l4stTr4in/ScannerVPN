# app/api/endpoints/vpn.py
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.orm import Session
from app import crud
from app.schemas import vpn_profile
from app.api.deps import get_db
from app.services.vpn_service import VPNService

router = APIRouter()
vpn_service = VPNService()

# Giữ nguyên endpoint gốc: GET /api/vpn_profiles
@router.get("/api/vpn_profiles", summary="Lấy danh sách VPN profiles trong DB")
def get_db_vpn_profiles(db: Session = Depends(get_db)):
    profiles_db = crud.crud_vpn_profile.get_all(db)
    return profiles_db

# Giữ nguyên endpoint gốc: POST /api/vpn_profiles/update
@router.post("/api/vpn_profiles/update", summary="Cập nhật trạng thái một VPN profile")
def update_db_vpn_profile_status(
        payload: dict = Body(...),
        db: Session = Depends(get_db)
):
    filename = payload.get("filename")
    vpn_db = crud.crud_vpn_profile.get_by_filename(db, filename=filename)
    if not vpn_db:
        raise HTTPException(status_code=404, detail="VPN profile not found in database")

    return crud.crud_vpn_profile.update_status(
        db, vpn_profile=vpn_db, action=payload.get("action"),
        scanner_id=payload.get("scanner_id"), status=payload.get("status")
    )

# Giữ nguyên endpoint gốc: GET /api/vpns
@router.get("/api/vpns", summary="Lấy danh sách VPN đang sẵn có từ proxy")
async def get_available_vpns_from_proxy():
    try:
        vpns = await vpn_service.fetch_vpns()
        return {"total": len(vpns), "vpns": vpns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Giữ nguyên endpoint gốc: GET /api/vpns/by-country
@router.get("/api/vpns/by-country", summary="Lấy VPN sẵn có, phân loại theo quốc gia")
async def get_vpns_by_country():
    try:
        vpns = await vpn_service.fetch_vpns()
        categorized = await vpn_service.categorize_vpns_by_country(vpns)
        return categorized
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/vpn_profiles/reset", summary="Reset all VPN profiles in DB to default idle state")
def reset_vpn_profiles(db: Session = Depends(get_db)):
    try:
        count = vpn_service.reset_vpn_profiles(db)
        return {"reset_count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))