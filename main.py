from abc import ABC, abstractmethod
from datetime import datetime
from typing import Annotated, Literal, Optional, Union

from fastapi import Depends, FastAPI, HTTPException, Response, status
from pydantic import BaseModel

app = FastAPI()


class CredentialDTO(BaseModel):
    username: str
    password: str


class KeyDTO(BaseModel):
    username: str
    password: str
    created_at: str
    updated_at: str
    password_strength: Literal["weak", "strong"]


class PasswordManagerRepository(ABC):
    @abstractmethod
    def get_categories(self, category: str, key: str) -> list[str]:
        pass

    @abstractmethod
    def create_category(self, category: str) -> bool:
        pass

    @abstractmethod
    def get_category(self, category: str) -> Union[list[str], None]:
        pass

    @abstractmethod
    def category_exist(self, category: str) -> bool:
        pass

    @abstractmethod
    def delete_category(self, category: str) -> bool:
        pass

    @abstractmethod
    def create_credential(
        self, category: str, key: str, username: str, password: str
    ) -> None:
        pass

    @abstractmethod
    def update_credential(
        self, category: str, key: str, username: str, password: str
    ) -> bool:
        pass

    @abstractmethod
    def get_credential(self, category: str, key: str) -> Union[KeyDTO, None]:
        pass

    @abstractmethod
    def delete_credential(self, category: str, key: str) -> bool:
        pass


_category_map = {}


class InMemoryStorage(PasswordManagerRepository):
    def key_exist(self, category, key) -> bool:
        if not self.category_exist(category):
            return False
        return True if key in _category_map[category] else False

    def get_categories(self) -> list[str]:
        return list(_category_map.keys())

    def create_category(self, category) -> bool:
        if self.category_exist(category):
            return False
        _category_map[category] = {}
        return True

    def get_category(self, category) -> Union[list[str], None]:
        if not self.category_exist(category):
            return None
        return list(_category_map[category].keys())

    def category_exist(self, category) -> bool:
        return True if category in _category_map else False

    def delete_category(self, category) -> bool:
        if not self.category_exist(category):
            return False
        _category_map.pop(category)
        return True

    def create_credential(self, category, key, username, password) -> None:
        now = datetime.now().strftime(format="%d/%m/%Y, %H:%M:%S")

        _category_map[category][key] = KeyDTO(
            username=username,
            password=password,
            created_at=now,
            updated_at=now,
            password_strength="weak" if len(password) < 13 else "strong",
        )

    def get_credential(self, category, key) -> Union[KeyDTO, None]:
        if not self.key_exist(category, key):
            return {}
        return _category_map[category][key]

    def update_credential(self, category, key, username, password) -> bool:
        old_credential: KeyDTO = self.get_credential(category, key)
        if not old_credential:
            return False
        else:
            now = datetime.now().strftime(format="%d/%m/%Y, %H:%M:%S")
            old_credential.username = username
            old_credential.password = password
            old_credential.updated_at = now
            old_credential.password_strength = (
                "weak" if len(password) < 13 else "strong"
            )

            _category_map[category][key] = old_credential
            return True

    def delete_credential(self, category, key) -> bool:
        if not self.key_exist(category, key):
            return False
        _category_map[category].pop(key)
        return True


@app.get("/")
def get_categories(
    repo: Annotated[PasswordManagerRepository, Depends(InMemoryStorage)],
):
    return repo.get_categories()


@app.put(
    "/{category_name}",
    status_code=status.HTTP_201_CREATED,
    responses={"409": {"description": "Category already created"}},
)
def create_categories(
    repo: Annotated[PasswordManagerRepository, Depends(InMemoryStorage)],
    category_name: str,
):
    if not repo.create_category(category_name):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="category already created",
        )


@app.get(
    "/{category_name}",
    responses={"404": {"description": "Not Found"}},
)
def get_category(
    repo: Annotated[PasswordManagerRepository, Depends(InMemoryStorage)],
    category_name: str,
):
    if not repo.category_exist(category_name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return repo.get_category(category_name)


@app.delete(
    "/{category_name}",
    responses={"404": {"description": "Not Found"}},
)
def delete_category(
    repo: Annotated[PasswordManagerRepository, Depends(InMemoryStorage)],
    category_name: str,
):
    if not repo.delete_category(category_name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@app.put(
    "/{category_name}/{key}",
    status_code=status.HTTP_201_CREATED,
    responses={"404": {"description": "Category Not Found"}},
)
def create_credentials(
    repo: Annotated[PasswordManagerRepository, Depends(InMemoryStorage)],
    category_name: str,
    key: str,
    credential: CredentialDTO,
):
    if not repo.category_exist(category_name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Category Not Found"
        )
    if repo.key_exist(category_name, key):
        repo.update_credential(
            category=category_name,
            key=key,
            username=credential.username,
            password=credential.password,
        )
    else:
        repo.create_credential(
            category=category_name,
            key=key,
            username=credential.username,
            password=credential.password,
        )


@app.delete(
    "/{category_name}/{key}",
    responses={"404": {"description": "Not Found"}},
)
def delete_credenials(
    repo: Annotated[PasswordManagerRepository, Depends(InMemoryStorage)],
    category_name: str,
    key: str,
):
    if not repo.delete_credential(category_name, key):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@app.get(
    "/{category_name}/{key}",
    responses={"404": {"description": "Not Found"}},
)
def get_credential(
    repo: Annotated[PasswordManagerRepository, Depends(InMemoryStorage)],
    response: Response,
    category_name: str,
    key: str,
) -> CredentialDTO:
    credential = repo.get_credential(category_name, key)
    if not credential:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    response.headers["X-PM-Created-At"] = credential.created_at
    response.headers["X-PM-Updated-At"] = credential.updated_at
    response.headers["X-PM-Password-Strength"] = credential.password_strength

    return CredentialDTO(username=credential.username, password=credential.password)
