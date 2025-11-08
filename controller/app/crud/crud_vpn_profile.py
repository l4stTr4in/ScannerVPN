# app/crud/crud_vpn_profile.py
from sqlalchemy.orm import Session
from app.models.vpn_profile import VpnProfile
from datetime import datetime


def _ensure_list(v):
    return list(v) if v else []

def get_all(db: Session) -> list[VpnProfile]:
    return db.query(VpnProfile).all()

def get_by_filename(db: Session, *, filename: str) -> VpnProfile | None:
    return db.query(VpnProfile).filter(VpnProfile.filename == filename).first()


def update(db: Session, db_obj: VpnProfile, obj_in: dict) -> VpnProfile:
    """Generic update helper: apply keys from obj_in to db_obj and commit."""
    for k, v in (obj_in or {}).items():
        if hasattr(db_obj, k):
            setattr(db_obj, k, v)
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def set_reserved(db: Session, filename: str, reserved_by: str, reserved_until_iso: str) -> bool:
    vpn = get_by_filename(db, filename=filename)
    if not vpn:
        return False
    vpn.reserved_by = reserved_by
    vpn.reserved_until = reserved_until_iso
    vpn.status = "reserved"
    # Do not modify in_use_by here; reserved_by is separate
    db.add(vpn)
    db.commit()
    db.refresh(vpn)
    return True


def clear_reservation(db: Session, vpn: VpnProfile) -> VpnProfile:
    vpn.reserved_by = None
    vpn.reserved_until = None
    # If not in use, ensure status is idle
    if not (vpn.in_use_by or []):
        vpn.status = "idle"
    db.add(vpn)
    db.commit()
    db.refresh(vpn)
    return vpn


def reset_all(db: Session) -> int:
    """Reset all vpn profiles to default idle state. Returns number of profiles updated."""
    vpns = get_all(db)
    count = 0
    for v in vpns:
        v.status = "idle"
        v.in_use_by = []
        v.reserved_by = None
        v.reserved_until = None
        db.add(v)
        count += 1
    db.commit()
    return count

def update_status(db: Session, *, vpn_profile: VpnProfile, action: str, scanner_id: str | None, status: str | None) -> VpnProfile:
    """Cập nhật trạng thái và danh sách sử dụng của một VPN profile."""
    if action == "connect":
        # Add scanner to in_use_by if not present
        if scanner_id:
            in_use = _ensure_list(vpn_profile.in_use_by)
            if scanner_id not in in_use:
                in_use.append(scanner_id)
            vpn_profile.in_use_by = in_use
        # On connect, clear reservation metadata
        vpn_profile.reserved_by = None
        vpn_profile.reserved_until = None
        vpn_profile.status = status or "connected"
    elif action == "disconnect":
        if scanner_id:
            in_use = _ensure_list(vpn_profile.in_use_by)
            in_use = [sid for sid in in_use if sid != scanner_id]
            vpn_profile.in_use_by = in_use
        # If no scanners using it, clear reservation and set idle
        if not (vpn_profile.in_use_by or []):
            vpn_profile.status = status or "idle"
            vpn_profile.reserved_by = None
            vpn_profile.reserved_until = None

    db.add(vpn_profile)
    db.commit()
    db.refresh(vpn_profile)
    return vpn_profile