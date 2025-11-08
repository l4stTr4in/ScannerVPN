# app/api/endpoints/workflows.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.schemas import workflow
from app import crud
from app.services.workflow_service import WorkflowService
from app.services.result_service import ResultService
from app.api.deps import get_workflow_service, get_result_service, get_db
from app.core.config import settings

router = APIRouter()

# Giữ nguyên endpoint gốc: POST /api/scan/workflow
@router.post("/api/workflow", status_code=201, summary="Tạo và bắt đầu một workflow quét mới")
async def create_workflow(
        *,
        workflow_in: workflow.WorkflowRequest,
        workflow_service: WorkflowService = Depends(get_workflow_service)
):
    try:
        # Lấy workflow_id từ payload nếu có
        workflow_id = getattr(workflow_in, "workflow_id", None)
        # Nếu muốn truyền workflow_phase, lấy từ payload hoặc tự động tăng
        workflow_phase = getattr(workflow_in, "workflow_phase", None)
        result = await workflow_service.create_and_dispatch_workflow(
            workflow_in=workflow_in,
            workflow_id=workflow_id,
            workflow_phase=workflow_phase
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating workflow: {str(e)}")

# Giữ nguyên endpoint gốc: GET /api/workflows/{workflow_id}
@router.get("/api/workflows/{workflow_id}", summary="Lấy trạng thái chi tiết của một workflow")
def get_workflow_details(
    workflow_id: str,
    workflow_service: WorkflowService = Depends(get_workflow_service)
):
    return workflow_service.get_workflow_detail(workflow_id=workflow_id)

# Giữ nguyên endpoint gốc: GET /api/workflows
@router.get("/api/workflows", summary="Lấy danh sách các workflow")
def get_workflows_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    workflow_service: WorkflowService = Depends(get_workflow_service)
):
    return workflow_service.list_workflows(page=page, page_size=page_size)

# Giữ nguyên endpoint gốc: GET /api/workflows/{workflow_id}/summary
@router.get("/api/workflows/{workflow_id}/summary", summary="Lấy bản tóm tắt kết quả của một workflow")
def get_workflow_summary(
        workflow_id: str,
        result_service: ResultService = Depends(get_result_service)
):
    return result_service.get_workflow_summary(workflow_id)

# Giữ nguyên endpoint gốc: DELETE /api/workflows/{workflow_id}
@router.delete("/api/workflows/{workflow_id}", status_code=200, summary="Xóa một workflow và các tài nguyên liên quan")
def delete_workflow(
        workflow_id: str,
        workflow_service: WorkflowService = Depends(get_workflow_service)
):
    return workflow_service.delete_workflow(workflow_id=workflow_id)

# Thêm endpoint: GET /api/workflows/{workflow_id}/status
@router.get("/api/workflows/{workflow_id}/status", summary="Lấy trạng thái hiện tại của workflow, bao gồm sub-jobs, progress, target, vpn, thời gian tạo")
def get_workflow_status(
    workflow_id: str,
    workflow_service: WorkflowService = Depends(get_workflow_service)
):
    return workflow_service.get_workflow_status(workflow_id=workflow_id)

# Thêm endpoint: GET /api/workflows/{workflow_id}/chain-info
@router.get("/api/workflows/{workflow_id}/chain-info", summary="Lấy thông tin về workflow chain và scanner limits")
def get_workflow_chain_info(
    workflow_id: str,
    db: Session = Depends(get_db)
):
    from app.services.auto_workflow_service import AutoWorkflowService
    auto_service = AutoWorkflowService(db)
    
    # Tìm root workflow
    root_workflow_id = auto_service._find_root_workflow(workflow_id)
    
    # Lấy tất cả workflows trong chain
    all_workflows = auto_service._get_all_workflows_in_chain(root_workflow_id)
    
    # Đếm scanners
    total_scanners = auto_service._count_total_scanners_in_chain(root_workflow_id)
    
    # Kiểm tra limits
    can_continue = auto_service._should_continue_workflow_chain(workflow_id)
    
    return {
        "workflow_id": workflow_id,
        "root_workflow_id": root_workflow_id,
        "chain_workflows": all_workflows,
        "total_scanners": total_scanners,
        "max_scanners_limit": getattr(settings, 'MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN', 50),
        "can_continue": can_continue,
        "chain_depth": len(all_workflows)
    }