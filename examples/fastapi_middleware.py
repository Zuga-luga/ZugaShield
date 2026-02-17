"""
ZugaShield FastAPI Integration
================================

Demonstrates three integration patterns in a single app:

    1. Global middleware  — perimeter layer checks every request (Layer 1)
    2. Per-route decorator — shield_protect() on individual sensitive endpoints
    3. Dashboard router   — read-only monitoring API at /api/shield/*

Run:
    pip install zugashield[fastapi] uvicorn
    python examples/fastapi_middleware.py

Then test:
    curl http://localhost:8080/api/chat -X POST -H "Content-Type: application/json" \
         -d '{"message": "Hello"}'
    curl http://localhost:8080/api/shield/dashboard
    curl http://localhost:8080/api/shield/threats
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from zugashield import ZugaShield
from zugashield.integrations.fastapi import (
    create_dashboard_router,
    create_shield_middleware,
    shield_protect,
)


# ---------------------------------------------------------------------------
# Configure the shield (use builder for non-default settings)
# ---------------------------------------------------------------------------

shield = (
    ZugaShield.builder()
    .fail_closed(True)
    .set_tool_policy("web_search", rate=10, approval=False, risk="medium")
    .add_sensitive_endpoint("/api/admin", rate_limit=5)
    .build()
)


# ---------------------------------------------------------------------------
# Lifespan: log startup info
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    stats = shield.catalog.get_stats()
    print(
        f"[ZugaShield] Active — "
        f"{stats['total_signatures']} signatures, "
        f"fail_closed={shield.config.fail_closed}"
    )
    yield


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="ZugaShield FastAPI Example", lifespan=lifespan)

# Pattern 1: Global middleware — all requests go through the perimeter layer.
# Blocked requests receive a 403 before any route handler runs.
create_shield_middleware(app, shield=shield)

# Pattern 3: Dashboard API at /api/shield/*
# Exposes: /status, /threats, /anomaly-score, /dashboard, /audit
app.include_router(
    create_dashboard_router(shield_getter=lambda: shield),
    prefix="/api/shield",
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"


class ChatResponse(BaseModel):
    response: str
    shield_verdict: str
    elapsed_ms: float


# ---------------------------------------------------------------------------
# Pattern 2a: Manual per-endpoint shield checks (fine-grained control)
# ---------------------------------------------------------------------------

@app.post("/api/chat", response_model=ChatResponse)
async def chat(body: ChatRequest):
    # Layer 2: Prompt Armor — block injection attempts in the user message
    input_decision = await shield.check_prompt(
        body.message,
        context={"session_id": body.session_id},
    )
    if input_decision.is_blocked:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "blocked_by_zugashield",
                "layer": input_decision.layer,
                "threats": [t.description for t in input_decision.threats_detected],
            },
        )

    # ... your LLM call here ...
    llm_response = f"Echo: {body.message}"

    # Layer 5: Exfiltration Guard — prevent secret leakage in responses
    output_decision = await shield.check_output(
        llm_response,
        context={"session_id": body.session_id},
    )
    if output_decision.is_blocked:
        return ChatResponse(
            response="[Response blocked: potential data leak detected]",
            shield_verdict=output_decision.verdict.value,
            elapsed_ms=output_decision.elapsed_ms,
        )

    return ChatResponse(
        response=llm_response,
        shield_verdict=input_decision.verdict.value,
        elapsed_ms=input_decision.elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Pattern 2b: @shield_protect() decorator for sensitive routes
# ---------------------------------------------------------------------------

@app.post("/api/admin/action")
@shield_protect(shield=shield, check_body=True)
async def admin_action(request: Request):
    """
    The @shield_protect() decorator runs the perimeter layer before this
    handler executes. Use it instead of middleware when you want route-level
    control without wrapping the entire app.
    """
    return {"status": "ok", "message": "Admin action completed"}


# ---------------------------------------------------------------------------
# Tool call example (Layer 3: Tool Guard)
# ---------------------------------------------------------------------------

@app.post("/api/tools/execute")
async def execute_tool(request: Request):
    body = await request.json()
    tool_name = body.get("tool", "")
    params = body.get("params", {})
    session_id = body.get("session_id", "default")

    decision = await shield.check_tool_call(
        tool_name=tool_name,
        params=params,
        session_id=session_id,
    )
    if decision.is_blocked:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "tool_blocked",
                "tool": tool_name,
                "verdict": decision.verdict.value,
                "threats": [t.description for t in decision.threats_detected],
            },
        )

    return {
        "tool": tool_name,
        "status": "executed",
        "shield_verdict": decision.verdict.value,
    }


# ---------------------------------------------------------------------------
# Anomaly score endpoint (Layer 6)
# ---------------------------------------------------------------------------

@app.get("/api/sessions/{session_id}/risk")
async def session_risk(session_id: str):
    score = shield.get_session_risk(session_id)
    return {
        "session_id": session_id,
        "score": score.session_score,
        "threat_level": score.threat_level.value,
        "contributing_events": len(score.contributing_events),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
