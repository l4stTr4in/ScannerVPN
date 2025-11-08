# app/models/vpn_profile.py
from sqlalchemy import Column, Integer, String
from sqlalchemy.types import PickleType
from app.db.base import Base # <--- Thay đổi ở đây

class VpnProfile(Base):
    __tablename__ = "vpn_profiles"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, unique=True, index=True)
    hostname = Column(String, nullable=True)
    ip = Column(String, nullable=True)
    country = Column(String, nullable=True)
    status = Column(String, default="idle")
    in_use_by = Column(PickleType, default=list)
    # Reservation metadata
    reserved_until = Column(String, nullable=True)
    reserved_by = Column(String, nullable=True)