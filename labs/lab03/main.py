from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from labs.lab03.config import APP_DESCRIPTION, APP_TITLE
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared import student


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ініціалізувати базу даних під час запуску API."""
    initialize_database()
    yield


app = FastAPI(
    title=f"{APP_TITLE} (Варіант 13)",
    description=APP_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
def root_redirect():
    """Перенаправити користувача на документацію API."""
    return RedirectResponse(url="/docs")


app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", summary="Перевірка доступності API")
def ping():
    return {"status": "ok"}


@app.get("/student", summary="Інформація про студента")
def student_info():
    return {
        "student_name": student.STUDENT_NAME,
        "group_name": student.GROUP_NAME,
        "variant_number": student.VARIANT_NUMBER,
    }
