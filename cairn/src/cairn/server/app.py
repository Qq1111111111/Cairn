from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from cairn import __version__
from cairn.server import db
from cairn.server.auth import protected_route, request_uses_internal_token, require_authenticated_user
from cairn.server.project_files import ensure_project_files_root
from cairn.server.routers import auth, export, hints, intents, projects, prompts, settings, traffic

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    ensure_project_files_root()
    yield


app = FastAPI(
    title="Cairn",
    description="Fact-graph based collaborative exploration protocol",
    version=__version__,
    lifespan=lifespan,
)

@app.middleware("http")
async def auth_and_security_middleware(request: Request, call_next):
    if protected_route(request.url.path) and not request_uses_internal_token(request):
        try:
            require_authenticated_user(request)
        except Exception as exc:
            if getattr(exc, "status_code", None) == 401:
                return JSONResponse({"detail": "Authentication required"}, status_code=401)
            raise
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response

app.include_router(auth.router)
app.include_router(settings.router)
app.include_router(projects.router)
app.include_router(hints.router)
app.include_router(intents.router)
app.include_router(prompts.router)
app.include_router(export.router)
app.include_router(traffic.router)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
