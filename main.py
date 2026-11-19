import sqlite3
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from database import DATABASE_PATH, init_db
from schemas import RegistrationRequest
from users import create_user


def create_app(db_path: Path = DATABASE_PATH) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
        init_db(db_path)
        yield

    application = FastAPI(
        title="Secure Vault",
        lifespan=lifespan,
    )

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(
        _request: Request,
        _exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": "Invalid request."},
        )

    @application.get("/health")
    def health_check() -> dict[str, str]:
        return {"status": "ok"}

    @application.post(
        "/register",
        status_code=status.HTTP_201_CREATED,
    )
    def register(
        registration: RegistrationRequest,
    ) -> dict[str, str]:
        try:
            create_user(
                username=registration.username,
                password=registration.password.get_secret_value(),
                db_path=db_path,
            )
        except sqlite3.IntegrityError as exc:
            if exc.sqlite_errorcode == sqlite3.SQLITE_CONSTRAINT_UNIQUE:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username is unavailable.",
                ) from exc
            raise

        return {"username": registration.username}

    return application


app = create_app()
