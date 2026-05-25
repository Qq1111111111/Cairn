from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cairn import __version__
from cairn.server.auth import (
    extract_session_token,
    load_web_auth_config,
    resolve_authenticated_username,
    sync_web_auth_user,
)
from cairn.server import db
from cairn.server.routers import auth, export, hints, intents, projects, settings

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    web_auth_config = load_web_auth_config(Path("dispatch.yaml"))
    app.state.auth_enabled = web_auth_config is not None
    if web_auth_config is not None:
        with db.get_conn() as conn:
            sync_web_auth_user(conn, web_auth_config)
    yield


app = FastAPI(
    title="Cairn",
    description="Fact-graph based collaborative exploration protocol",
    version=__version__,
    lifespan=lifespan,
)


@app.middleware("http")
async def web_auth_middleware(request: Request, call_next):
    if not getattr(app.state, "auth_enabled", False):
        return await call_next(request)

    path = request.url.path
    if (
        request.method == "OPTIONS"
        or path == "/"
        or path == "/healthz"
        or path.startswith("/auth/")
        or path.startswith("/static/")
    ):
        return await call_next(request)

    username = None
    with db.get_conn() as conn:
        username = resolve_authenticated_username(
            conn,
            enabled=True,
            session_token=extract_session_token(request),
        )
    if username is None:
        return JSONResponse({"detail": "请先登录"}, status_code=401)
    request.state.auth_user = username
    return await call_next(request)


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}


app.include_router(auth.router)
app.include_router(settings.router)
app.include_router(projects.router)
app.include_router(hints.router)
app.include_router(intents.router)
app.include_router(export.router)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
