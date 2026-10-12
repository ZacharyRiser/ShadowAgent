"""Replay intercepted requests against the current policy stack."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import _decision_payload
from app.auth_helpers import _principal_label
from app.schemas import ReplayRequest
from app.serializers import _serialize_replay_run
from app.tenancy import new_row_org_id, scoped_query
from app.utils import _json_loads_safe
from database import get_db
from models import InterceptLog, ReplayRun
from security_controls import Principal, require_admin, sanitize_json
from security_engine import behavior_risk_check

router = APIRouter(prefix="/api/v1/replays", tags=["replays"])


def _build_replay_details(log: InterceptLog) -> dict[str, Any]:
    details = _json_loads_safe(log.details, {})
    tool_name = details.get("tool_name") if isinstance(details, dict) else None
    parameters = details.get("parameters") if isinstance(details, dict) else None
    external_context = details.get("external_context") if isinstance(details, dict) else None
    behavior_decision = behavior_risk_check(
        prompt=log.original_prompt,
        external_context=external_context if isinstance(external_context, str) else None,
        tool_name=tool_name if isinstance(tool_name, str) else None,
        parameters=parameters if isinstance(parameters, dict) else None,
    )
    return {
        "request_id": details.get("request_id"),
        "original_threat_type": log.threat_type,
        "original_action": log.action_taken,
        "replayed_behavior_risk": _decision_payload(behavior_decision),
        "source_details": sanitize_json(details),
    }


@router.post("")
async def replay_request_by_request_id(
    payload: ReplayRequest,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    matched_log = (
        scoped_query(db, InterceptLog, principal)
        .filter(InterceptLog.request_id == payload.request_id)
        .order_by(InterceptLog.timestamp.desc(), InterceptLog.id.desc())
        .first()
    )

    if matched_log is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "replay_source_not_found",
                "message": "No intercepted request matched that request_id.",
            },
        )

    replay_request_id = f"replay-{uuid.uuid4()}"
    replay_details = _build_replay_details(matched_log)
    replay_behavior = replay_details["replayed_behavior_risk"]
    run = ReplayRun(
        org_id=new_row_org_id(principal),
        source_request_id=payload.request_id,
        replay_request_id=replay_request_id,
        triggered_by=_principal_label(principal, db),
        verdict="blocked" if not bool(replay_behavior["allowed"]) else "allowed",
        risk_score=str(replay_behavior["risk_score"]),
        category=str(replay_behavior["category"]),
        details=json.dumps(sanitize_json(replay_details), ensure_ascii=False),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return {"item": _serialize_replay_run(run)}


@router.get("")
async def list_replay_runs(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    items = (
        scoped_query(db, ReplayRun, principal)
        .order_by(ReplayRun.created_at.desc(), ReplayRun.id.desc())
        .limit(100)
        .all()
    )
    return {"items": [_serialize_replay_run(item) for item in items]}
