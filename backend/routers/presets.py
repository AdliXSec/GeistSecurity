import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, status
from backend.models.schemas import PresetCreateRequest, PresetResponse
from backend.routers.auth import get_current_user_optional
from backend.database import (
    list_presets,
    save_preset,
    delete_preset,
    restore_demo_presets,
)

router = APIRouter(prefix="/api/v1/presets", tags=["Presets"])
legacy_router = APIRouter(prefix="/api/presets", tags=["Presets"], include_in_schema=False)

@router.get("", response_model=List[PresetResponse])
@legacy_router.get("", response_model=List[PresetResponse])
async def get_presets_endpoint(user: Optional[dict] = Depends(get_current_user_optional)):
    user_id = user["id"] if user else None
    return await list_presets(user_id=user_id)

@router.post("", response_model=PresetResponse, status_code=status.HTTP_201_CREATED)
@legacy_router.post("", response_model=PresetResponse, status_code=status.HTTP_201_CREATED)
async def create_preset_endpoint(
    payload: PresetCreateRequest,
    user: Optional[dict] = Depends(get_current_user_optional)
):
    user_id = user["id"] if user else None
    preset_id = f"custom-{uuid.uuid4().hex[:10]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    saved = await save_preset(
        preset_id=preset_id,
        project_name=payload.project_name.strip(),
        mode=payload.mode.value if hasattr(payload.mode, "value") else str(payload.mode),
        url=payload.url.strip() if payload.url else "",
        repo=payload.repo.strip() if payload.repo else "",
        branch=payload.branch.strip() if payload.branch else "main",
        created_at=now_iso,
        updated_at=now_iso,
        user_id=user_id,
        is_demo=bool(payload.is_demo),
    )
    return saved

@router.delete("/{preset_id}")
@legacy_router.delete("/{preset_id}")
async def delete_preset_endpoint(
    preset_id: str,
    user: Optional[dict] = Depends(get_current_user_optional)
):
    user_id = user["id"] if user else None
    success = await delete_preset(preset_id=preset_id, user_id=user_id)
    return {"success": success, "preset_id": preset_id}

@router.post("/restore-demo", response_model=List[PresetResponse])
@legacy_router.post("/restore-demo", response_model=List[PresetResponse])
async def restore_demo_endpoint(
    user: Optional[dict] = Depends(get_current_user_optional)
):
    user_id = user["id"] if user else None
    return await restore_demo_presets(user_id=user_id)
