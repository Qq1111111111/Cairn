# Repository Guidelines

## Project Structure & Module Organization
The Python package lives in `cairn/`. Application code is under `cairn/src/cairn/`: `server/` contains the FastAPI API and static UI, while `dispatcher/` contains scheduling, runtime, worker adapters, and prompt templates. Tests live in `cairn/tests/` and mirror runtime areas with files like `test_server_api.py` and `test_scheduler_logic.py`. Operational files sit at the repo root: `docker-compose.yaml`, `dispatch.example.yaml`, and `dispatch_mock.yaml`. Design notes are in `docs/specs/`; container-specific material is isolated in `container/`.

## Build, Test, and Development Commands
Use `uv` for local development from the repository root.

- `uv run --project cairn cairn serve` starts the API server on `127.0.0.1:8000`.
- `uv run --project cairn cairn dispatch --config dispatch.yaml` runs the dispatcher against a local config.
- `uv run --project cairn --group dev pytest` runs the regression suite.
- `docker compose up --build` starts the server and dispatcher together with the documented container setup.

If you need dependencies locally, use `uv sync --project cairn --group dev`.

## Coding Style & Naming Conventions
Follow existing Python style: 4-space indentation, type hints on public functions, and small focused modules. Use `snake_case` for functions, variables, and test files; `PascalCase` for classes; and concise imperative Click command names. Keep FastAPI routers thin and move stateful logic into `server/services.py` or dispatcher runtime modules. Preserve the current plain-Markdown prompt files under `cairn/src/cairn/dispatcher/prompts/`.

## Testing Guidelines
Pytest is configured in `cairn/pyproject.toml` with `testpaths = ["tests"]`. Add tests beside the affected behavior and prefer names of the form `test_<behavior>.py` or `test_<scenario>`. Cover API changes with `fastapi.testclient` cases and dispatcher/runtime changes with regression tests that avoid live model endpoints or Docker when possible.

## Commit & Pull Request Guidelines
Recent history uses Conventional Commit prefixes such as `feat:`, `fix:`, `test:`, and `chore:`. Keep subjects short and imperative, for example `feat: add startup healthcheck toggle`. PRs should describe the user-visible behavior change, note any config or Docker impact, link the related issue when available, and include screenshots only for changes touching the static UI. Update docs or example configs when protocol, prompt, or workflow behavior changes.
