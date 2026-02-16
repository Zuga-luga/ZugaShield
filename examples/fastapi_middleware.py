"""
ZugaShield FastAPI Middleware Example
=======================================

Shows how to integrate ZugaShield with a FastAPI application.
Requires: pip install zugashield[fastapi]
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from zugashield import ZugaShield
from zugashield.integrations.fastapi import create_shield_router

shield = ZugaShield()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[ZugaShield] Active with {shield.catalog.get_stats()['total_signatures']} signatures")
    yield


app = FastAPI(title="ZugaShield Example", lifespan=lifespan)

# Mount the dashboard router
app.include_router(create_shield_router(lambda: shield), prefix="/api/shield")


@app.post("/api/chat")
async def chat(request: Request):
    body = await request.json()
    user_message = body.get("message", "")

    # Check input for injection
    decision = await shield.check_prompt(user_message)
    if decision.is_blocked:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Blocked by ZugaShield",
                "threats": [t.description for t in decision.threats_detected],
            },
        )

    # ... your LLM call here ...
    llm_response = f"Echo: {user_message}"

    # Check output for data leakage
    output_decision = await shield.check_output(llm_response)
    if output_decision.is_blocked:
        return {"response": "[Response blocked: potential data leak detected]"}

    return {"response": llm_response}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
