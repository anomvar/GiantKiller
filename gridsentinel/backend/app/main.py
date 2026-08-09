from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import CORS_ORIGINS, UPLOAD_DIR
from .database import init_db
from .routers import report, scan, upload


@asynccontextmanager
async def lifespan(app: FastAPI):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    yield


app = FastAPI(
    title="GridSentinel",
    description="Power Sector Software Security Scanner — SIH1388",
    version="2.4.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")
app.include_router(report.router, prefix="/api/v1")


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "GridSentinel", "version": "2.4.0"}
