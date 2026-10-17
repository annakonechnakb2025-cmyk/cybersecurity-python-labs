import sqlite3
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query, status

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[RecordRead])
def get_records(
    category_id: int | None = Query(None, gt=0),
    status_filter: Literal["new", "in_progress", "done"] | None = Query(
        None, alias="status"
    ),
    min_value: float | None = Query(None, ge=0, le=10),
    q: str | None = Query(None, min_length=1, max_length=120),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return repository.get_records_filtered(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/{record_id}", response_model=RecordRead)
def get_record(record_id: Annotated[int, Path(gt=0)]):
    record = repository.get_record_by_id(record_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис не знайдено.",
        )

    return record


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
)
def create_record(record: RecordCreate):
    try:
        return repository.create_record(record.model_dump())
    except sqlite3.IntegrityError as error:
        error_message = str(error).lower()

        if "foreign key" in error_message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Вказана категорія не існує.",
            ) from error

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Запис із таким кодом вже існує.",
        ) from error


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
)
def create_records_bulk(records: list[RecordCreate]):
    if not 1 <= len(records) <= 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Пакет повинен містити від 1 до 100 елементів.",
        )

    data_list = [record.model_dump() for record in records]

    try:
        return repository.create_records_bulk(data_list)
    except sqlite3.IntegrityError as error:
        error_message = str(error).lower()

        if "foreign key" in error_message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Один із записів посилається на неіснуючу категорію.",
            ) from error

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Конфлікт унікальності коду в пакеті або базі.",
        ) from error


@router.put("/{record_id}", response_model=RecordRead)
def update_record(
    record_id: Annotated[int, Path(gt=0)],
    record: RecordReplace,
):
    try:
        updated = repository.update_record(
            record_id,
            record.model_dump(),
        )

        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Запис не знайдено.",
            )

        return updated

    except sqlite3.IntegrityError as error:
        error_message = str(error).lower()

        if "foreign key" in error_message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Вказана категорія не існує.",
            ) from error

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Дублікат коду.",
        ) from error


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_record(record_id: Annotated[int, Path(gt=0)]):
    success = repository.delete_record(record_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис не знайдено.",
        )
