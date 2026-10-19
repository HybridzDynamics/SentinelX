"""FastAPI application for the Module 01 detection engine."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.parser import BatchParseError, EventParseError
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    DetectionConfig,
    ErrorDetail,
    ErrorResponse,
    HealthResponse,
    RuleInfo,
)
from app.services.analyzer import analyze_request, list_rules

MAX_REQUEST_BYTES = 1_048_576

app = FastAPI(
    title="SentinelX Detection Engine",
    description=(
        "Rules-based analyzer that turns structured authentication events into "
        "explainable incident findings. This service only processes the events "
        "supplied in each request."
    ),
    version=__version__,
)


@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content=ErrorResponse(
                        error="Request body exceeds the 1 MiB limit.",
                    ).model_dump(),
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(error="Invalid Content-Length header.").model_dump(),
            )
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def request_validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    details: list[ErrorDetail] = []
    for error in exc.errors():
        location = [str(part) for part in error.get("loc", ()) if part != "body"]
        field = ".".join(location) or None
        details.append(ErrorDetail(message="Invalid request payload.", field=field))
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(error="Request validation failed.", details=details).model_dump(),
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    message = "Not found." if exc.status_code == 404 else "HTTP error."
    if exc.status_code == 405:
        message = "Method not allowed."
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=message).model_dump(),
    )


@app.exception_handler(BatchParseError)
async def batch_parse_handler(_: Request, exc: BatchParseError) -> JSONResponse:
    details = [
        ErrorDetail(message=error.message, index=error.index, field=error.field)
        for error in exc.errors
    ]
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="One or more events failed validation.",
            details=details,
        ).model_dump(),
    )


@app.exception_handler(EventParseError)
async def event_parse_handler(_: Request, exc: EventParseError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error=exc.message,
            details=[ErrorDetail(message=exc.message, index=exc.index, field=exc.field)],
        ).model_dump(),
    )


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="sentinelx-detection-engine",
        module="01-explainable-security-detection",
        version=__version__,
    )


@app.get("/api/v1/rules", response_model=list[RuleInfo])
def get_rules() -> list[RuleInfo]:
    return list_rules(DetectionConfig())


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    return analyze_request(payload)
