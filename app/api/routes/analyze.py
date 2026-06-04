from fastapi import APIRouter, BackgroundTasks, status
from app.schemas.analyze import AnalyzeRequest

router = APIRouter()

@router.post("/internal/analyze", status_code=status.HTTP_202_ACCEPTED)
async def analyze(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    """
    분석 요청을 수신하고 백그라운드 태스크로 등록.
    Spring Boot는 이 응답을 받으면 즉시 클라이언트에게 analysis_id 반환.
    """
    # 추후: background_tasks.add_task(run_pipeline, request)
    return {
        "accepted": True,
        "analysis_id": request.analysis_id,
        "message": "Analysis queued for processing"
    }