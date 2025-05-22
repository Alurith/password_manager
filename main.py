from abc import ABC, abstractmethod
from datetime import datetime
from typing import Annotated, Literal, Optional, Union

from fastapi import Depends, FastAPI, HTTPException, Response, status
from pydantic import BaseModel

# --- Creazione dell'app FastAPI ---
app = FastAPI()


# --- Definizione dei Data Transfer Object (DTO) con pydantic ---
class CredentialDTO(BaseModel):
    # DTO per ricevere username e password in input
    username: str
    password: str


class KeyDTO(BaseModel):
    # DTO per rappresentare una credenziale salvata, con metadati
    username: str
    password: str
    created_at: str  # timestamp di creazione
    updated_at: str  # timestamp di ultimo aggiornamento
    password_strength: Literal["weak", "strong"]  # forza della password


# --- Interfaccia astratta per il repository della password manager ---
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


# --- Implementazione in memoria del repository ---
_category_map = {}  # struttura dati globale: { category: { key: KeyDTO, ... }, ... }


class InMemoryStorage(PasswordManagerRepository):
    # Metodo ausiliario per verificare esistenza di una chiave in una categoria
    def key_exist(self, category, key) -> bool:
        if not self.category_exist(category):
            return False
        return key in _category_map[category]

    # Restituisce tutte le categorie esistenti
    def get_categories(self) -> list[str]:
        return list(_category_map.keys())

    # Crea una nuova categoria se non esiste già
    def create_category(self, category) -> bool:
        if self.category_exist(category):
            return False
        _category_map[category] = {}
        return True

    # Ottiene tutte le chiavi (nomi delle credenziali) di una categoria
    def get_category(self, category) -> Union[list[str], None]:
        if not self.category_exist(category):
            return None
        return list(_category_map[category].keys())

    # Controlla se una categoria esiste
    def category_exist(self, category) -> bool:
        return category in _category_map

    # Elimina una categoria e tutte le sue credenziali
    def delete_category(self, category) -> bool:
        if not self.category_exist(category):
            return False
        _category_map.pop(category)
        return True

    # Crea una nuova credenziale all’interno di una categoria
    def create_credential(self, category, key, username, password) -> None:
        now = datetime.now().strftime(format="%d/%m/%Y, %H:%M:%S")
        _category_map[category][key] = KeyDTO(
            username=username,
            password=password,
            created_at=now,
            updated_at=now,
            password_strength="weak" if len(password) < 13 else "strong",
        )

    # Recupera una credenziale (o {} se non esiste)
    def get_credential(self, category, key) -> Union[KeyDTO, None]:
        if not self.key_exist(category, key):
            return {}
        return _category_map[category][key]

    # Aggiorna username/password e metadata di una credenziale esistente
    def update_credential(self, category, key, username, password) -> bool:
        old_credential: KeyDTO = self.get_credential(category, key)
        if not old_credential:
            return False
        now = datetime.now().strftime(format="%d/%m/%Y, %H:%M:%S")
        old_credential.username = username
        old_credential.password = password
        old_credential.updated_at = now
        old_credential.password_strength = "weak" if len(password) < 13 else "strong"
        _category_map[category][key] = old_credential
        return True

    # Elimina una specifica credenziale da una categoria
    def delete_credential(self, category, key) -> bool:
        if not self.key_exist(category, key):
            return False
        _category_map[category].pop(key)
        return True


# --- Definizione degli endpoint FastAPI ---
@app.get("/")
def get_categories(
    repo: Annotated[PasswordManagerRepository, Depends(InMemoryStorage)],
):
    # GET /: restituisce la lista delle categorie
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
    # PUT /{category_name}: crea una nuova categoria
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
    # GET /{category_name}: restituisce tutte le chiavi di una categoria
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
    # DELETE /{category_name}: elimina la categoria
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
    # PUT /{category_name}/{key}: crea o aggiorna una credenziale
    if not repo.category_exist(category_name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Category Not Found"
        )
    if repo.key_exist(category_name, key):
        # se esiste già la chiave, esegue l’update
        repo.update_credential(
            category=category_name,
            key=key,
            username=credential.username,
            password=credential.password,
        )
    else:
        # altrimenti crea una nuova credenziale
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
    # DELETE /{category_name}/{key}: elimina una credenziale
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
    # GET /{category_name}/{key}: recupera una credenziale e imposta header custom
    credential = repo.get_credential(category_name, key)
    if not credential:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    # Aggiunta di metadati negli header HTTP
    response.headers["X-PM-Created-At"] = credential.created_at
    response.headers["X-PM-Updated-At"] = credential.updated_at
    response.headers["X-PM-Password-Strength"] = credential.password_strength

    # Restituisce solo username e password nel body
    return CredentialDTO(username=credential.username, password=credential.password)
