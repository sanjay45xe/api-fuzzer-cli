import asyncio
import logging
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock_server")

app = FastAPI(
    title="Fuzzing Mock Target API",
    description="A target API specifically designed to test vulnerability finding and parser resilience under fuzzing.",
    version="1.0.0"
)

class UserPayload(BaseModel):
    username: Any  # Use Any to allow Pydantic to parse, but we do manual checks to test type errors or raise exceptions
    age: Any
    is_active: Any

@app.post("/api/users")
async def create_user(request: Request):
    # Try parsing raw JSON first to test parser resilience
    raw_body = await request.body()
    body_str = raw_body.decode("utf-8", errors="ignore")
    
    # 1. Test malformed JSON injection manually (or let FastAPI's middleware do it, but doing it manually is more customizable)
    try:
        data = await request.json()
    except Exception as e:
        logger.error(f"Malformed JSON parsing exception: {e}")
        # Return 400 for malformed json (resilient parser behavior)
        return JSONResponse(
            status_code=400,
            content={"error": "Malformed JSON syntax", "details": str(e)}
        )

    # Validate schema fields
    username = data.get("username")
    age = data.get("age")
    is_active = data.get("is_active")

    # 2. Type Fuzzing Detection
    # Let's say username MUST be a string, age MUST be an integer/float, is_active MUST be a boolean
    if username is not None and not isinstance(username, str):
        # We can return a 422 error or crash with a 500 if the code lacks exception handling!
        # Let's simulate a crash (500) if type is dict or list (unhandled list serialization crash)
        if isinstance(username, (dict, list)):
            raise RuntimeError(f"Unhandled type crash: expected string, got {type(username).__name__}")
        return JSONResponse(
            status_code=422,
            content={"error": "Unprocessable Entity", "details": "username must be a string"}
        )

    if age is not None and not isinstance(age, (int, float)) or isinstance(age, bool):
        return JSONResponse(
            status_code=422,
            content={"error": "Unprocessable Entity", "details": "age must be a number"}
        )

    if is_active is not None and not isinstance(is_active, bool):
        return JSONResponse(
            status_code=422,
            content={"error": "Unprocessable Entity", "details": "is_active must be a boolean"}
        )

    # 3. Boundary & Overflow Fuzzing Detection
    # Username length bounds
    if isinstance(username, str):
        if len(username) > 5000:
            # Simulate memory exhaustion/database save error (500)
            logger.critical("DB Buffer Overflow: string payload exceeds max database column width.")
            raise HTTPException(
                status_code=500,
                detail="Internal Database Error: string value too long for database buffer."
            )
        elif len(username) > 500:
            # Normal validation limit
            return JSONResponse(
                status_code=400,
                content={"error": "Bad Request", "details": "username must be under 500 characters."}
            )

    # Age bounds
    if isinstance(age, (int, float)):
        if age > 1e100 or age == float('inf') or age == float('-inf'):
            # Simulate arithmetic overflow crash (500)
            logger.critical("Arithmetic Overflow in age calculations.")
            raise ArithmeticError("Float value outside allowable range in processing pipeline.")
        elif age < 0:
            # Let's simulate a slow connection timeout!
            # If age is negative, we sleep for 6 seconds to trigger client timeout (timeout is 5.0)
            logger.info("Simulating long connection timeout because negative age was provided.")
            await asyncio.sleep(6.0)
            return {"status": "delayed_response"}

    # Special payload check (indicators of security issues)
    if isinstance(username, str) and "../../etc/passwd" in username:
        # Threat detection triggers internal crash
        logger.warning("Directory traversal attack indicator detected.")
        raise HTTPException(
            status_code=500,
            detail="Security Filter Failure: Uncaught exception in sandbox checker."
        )

    return {
        "status": "success",
        "message": "User validation succeeded",
        "received": {
            "username": username,
            "age": age,
            "is_active": is_active
        }
    }

@app.get("/health")
async def health():
    return {"status": "ok"}
