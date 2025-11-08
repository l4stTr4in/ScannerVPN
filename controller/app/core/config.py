# app/core/config.py
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database configuration
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/scan_results.db")

    # Service URLs
    SCANNER_NODE_URL: str = os.getenv("SCANNER_NODE_URL", "http://10.102.199.221:8000")
    CONTROLLER_CALLBACK_URL: str = os.getenv("CONTROLLER_CALLBACK_URL", "http://10.102.199.42:8000")
    VPN_PROXY_NODE: str = os.getenv("VPN_PROXY_NODE", "http://10.102.199.37:8000")
    # Reservation TTL in seconds for assigned VPN profiles (default 900s)
    VPN_RESERVATION_TTL: int = int(os.getenv("VPN_RESERVATION_TTL", "900"))

    # AI RAG Configuration
    RAG_SERVER_URL: str = os.getenv("RAG_SERVER_URL", "http://10.102.199.221:8080")
    AUTO_WORKFLOW_ENABLED: bool = os.getenv("AUTO_WORKFLOW_ENABLED", "true").lower() == "true"
    
    # Auto Workflow Limits - đếm tổng số scanner trong chuỗi workflows liên quan
    MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN: int = int(os.getenv("MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN", "25"))
    
    # Tool-specific API keys
    WPSCAN_API_TOKEN: str = os.getenv("WPSCAN_API_TOKEN", "")

    # Project Information
    PROJECT_NAME: str = "Distributed Scanner Controller"
    API_V1_STR: str = "/api/v1"

    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()
