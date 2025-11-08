# app/api/endpoints/settings.py
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any
import os
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

class APITokenUpdate(BaseModel):
    token: str
    tool: str = "wpscan"  # Support for future tools

class WorkflowLimitsUpdate(BaseModel):
    max_total_scanners_per_workflow_chain: int

class AutoWorkflowToggle(BaseModel):
    enabled: bool

class SettingsResponse(BaseModel):
    message: str
    success: bool

@router.put("/api/settings/api-tokens", response_model=SettingsResponse)
def update_api_token(token_update: APITokenUpdate):
    """
    Cập nhật API token cho các tools.
    Hiện tại hỗ trợ: wpscan
    """
    try:
        if token_update.tool.lower() == "wpscan":
            # Validate token format (basic check)
            if not token_update.token or len(token_update.token.strip()) < 10:
                raise HTTPException(
                    status_code=400, 
                    detail="Invalid WPScan API token format"
                )
            
            # Set environment variable for current session
            os.environ["WPSCAN_API_TOKEN"] = token_update.token.strip()
            
            # Update settings object if it exists
            try:
                from app.core.config import settings
                settings.WPSCAN_API_TOKEN = token_update.token.strip()
                logger.info("WPScan API token updated successfully")
            except Exception as e:
                logger.warning(f"Could not update settings object: {e}")
            
            return SettingsResponse(
                message=f"WPScan API token updated successfully. Will be used for new AI workflows.",
                success=True
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported tool: {token_update.tool}. Supported: wpscan"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating API token: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while updating API token"
        )

@router.get("/api/settings/api-tokens", response_model=Dict[str, Any])
def get_api_token_status():
    """
    Kiểm tra trạng thái API tokens (không trả về token thực tế vì bảo mật)
    """
    try:
        from app.core.config import settings
        
        # Check if tokens are configured (without exposing them)
        wpscan_configured = bool(settings.WPSCAN_API_TOKEN and settings.WPSCAN_API_TOKEN.strip())
        
        return {
            "wpscan": {
                "configured": wpscan_configured,
                "length": len(settings.WPSCAN_API_TOKEN) if wpscan_configured else 0,
                "masked_preview": f"{settings.WPSCAN_API_TOKEN[:4]}...{settings.WPSCAN_API_TOKEN[-4:]}" if wpscan_configured and len(settings.WPSCAN_API_TOKEN) > 8 else None
            },
            "supported_tools": ["wpscan"],
            "note": "API tokens are not returned for security reasons"
        }
        
    except Exception as e:
        logger.error(f"Error getting API token status: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while checking API token status"
        )

@router.delete("/api/settings/api-tokens/{tool}")
def clear_api_token(tool: str):
    """
    Xóa API token cho tool cụ thể
    """
    try:
        if tool.lower() == "wpscan":
            # Clear environment variable
            os.environ.pop("WPSCAN_API_TOKEN", None)
            
            # Clear settings object
            try:
                from app.core.config import settings
                settings.WPSCAN_API_TOKEN = ""
                logger.info("WPScan API token cleared")
            except Exception as e:
                logger.warning(f"Could not clear settings object: {e}")
            
            return SettingsResponse(
                message="WPScan API token cleared successfully",
                success=True
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported tool: {tool}. Supported: wpscan"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error clearing API token: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while clearing API token"
        )

@router.put("/api/settings/workflow-limits", response_model=SettingsResponse)
def update_workflow_limits(limits: WorkflowLimitsUpdate):
    """
    Cập nhật giới hạn cho auto workflow chain
    """
    try:
        # Validate input
        if limits.max_total_scanners_per_workflow_chain < 1:
            raise HTTPException(
                status_code=400,
                detail="Max scanners must be at least 1"
            )
        
        if limits.max_total_scanners_per_workflow_chain > 1000:
            raise HTTPException(
                status_code=400, 
                detail="Max scanners cannot exceed 1000 for system stability"
            )
        
        # Update environment variable
        os.environ["MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN"] = str(limits.max_total_scanners_per_workflow_chain)
        
        # Update settings object
        try:
            from app.core.config import settings
            settings.MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN = limits.max_total_scanners_per_workflow_chain
            logger.info(f"Workflow chain limit updated to {limits.max_total_scanners_per_workflow_chain}")
        except Exception as e:
            logger.warning(f"Could not update settings object: {e}")
        
        return SettingsResponse(
            message=f"Workflow chain limit updated to {limits.max_total_scanners_per_workflow_chain} scanners",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating workflow limits: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while updating workflow limits"
        )

@router.get("/api/settings/workflow-limits")
def get_workflow_limits():
    """
    Lấy thông tin giới hạn workflow hiện tại
    """
    try:
        from app.core.config import settings
        
        return {
            "max_total_scanners_per_workflow_chain": settings.MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN,
            "auto_workflow_enabled": settings.AUTO_WORKFLOW_ENABLED,
            "description": "Maximum total scanners allowed across all workflows in a related chain",
            "recommendations": {
                "light_usage": "10-25 scanners",
                "moderate_usage": "25-50 scanners", 
                "heavy_usage": "50-100 scanners",
                "enterprise": "100+ scanners (monitor resource usage)"
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting workflow limits: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while getting workflow limits"
        )

@router.put("/api/settings/auto-workflow", response_model=SettingsResponse)
def toggle_auto_workflow(toggle: AutoWorkflowToggle):
    """
    Bật/tắt auto workflow feature
    """
    try:
        # Update environment variable
        os.environ["AUTO_WORKFLOW_ENABLED"] = "true" if toggle.enabled else "false"
        
        # Update settings object
        try:
            from app.core.config import settings
            settings.AUTO_WORKFLOW_ENABLED = toggle.enabled
            status = "enabled" if toggle.enabled else "disabled"
            logger.info(f"Auto workflow {status}")
        except Exception as e:
            logger.warning(f"Could not update settings object: {e}")
        
        return SettingsResponse(
            message=f"Auto workflow {'enabled' if toggle.enabled else 'disabled'} successfully",
            success=True
        )
        
    except Exception as e:
        logger.error(f"Error toggling auto workflow: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while toggling auto workflow"
        )

@router.get("/api/settings/all")
def get_all_settings():
    """
    Lấy tất cả cấu hình hệ thống (không bao gồm sensitive data)
    """
    try:
        from app.core.config import settings
        
        # API tokens status (masked for security)
        wpscan_configured = bool(settings.WPSCAN_API_TOKEN and settings.WPSCAN_API_TOKEN.strip())
        
        return {
            "auto_workflow": {
                "enabled": settings.AUTO_WORKFLOW_ENABLED,
                "max_total_scanners_per_workflow_chain": settings.MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN
            },
            "api_tokens": {
                "wpscan": {
                    "configured": wpscan_configured,
                    "masked_preview": f"{settings.WPSCAN_API_TOKEN[:4]}...{settings.WPSCAN_API_TOKEN[-4:]}" if wpscan_configured and len(settings.WPSCAN_API_TOKEN) > 8 else None
                }
            },
            "services": {
                "rag_server_url": settings.RAG_SERVER_URL,
                "scanner_node_url": settings.SCANNER_NODE_URL,
                "vpn_proxy_node": settings.VPN_PROXY_NODE
            },
            "system": {
                "vpn_reservation_ttl": settings.VPN_RESERVATION_TTL,
                "database_url": "***masked***"  # Don't expose DB path
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting all settings: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while getting settings"
        )