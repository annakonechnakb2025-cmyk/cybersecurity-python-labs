import sqlite3

from fastapi import APIRouter, HTTPException, Path, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.get("", response_model=list[CategoryRead])
def get_categories():
    return repository.get_all_categories()


@router.post("", response_model=CategoryRead, status_code=status.HTTP_201_CREATED)
def create_category(category: CategoryCreate):
    try:
        return repository.create_category(category.name)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Категорія з такою назвою вже існує."
        )


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(category_id: int = Path(gt=0)):
    try:
        success = repository.delete_category(category_id)
        if not success:
            raise HTTPException(status_code=404, detail="Категорію не знайдено.")
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Неможливо видалити категорію, яка містить записи."
        )
