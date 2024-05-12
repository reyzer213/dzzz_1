from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from starlette.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import Dict, List
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.hash import bcrypt

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Підключення до бази даних
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Створення сесії для взаємодії з базою даних
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

# Оголошення базової моделі
Base = declarative_base()

# Модель користувача
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    login = Column(String, unique=True, index=True)
    password_hash = Column(String)

# Створення таблиці в базі даних
Base.metadata.create_all(bind=engine)

# Хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Оголошення схеми аутентифікації OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Функція для отримання хешу пароля
def get_password_hash(password):
    return pwd_context.hash(password)

# Функція для верифікації пароля
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Функція для отримання користувача з бази даних
def get_user(login: str):
    return db.query(User).filter(User.login == login).first()

# Модель для отримання токена
class Token(BaseModel):
    access_token: str
    token_type: str

# Роут для отримання токена
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неправильне ім'я користувача або пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=30)
    to_encode = {"sub": user.login, "exp": datetime.utcnow() + access_token_expires}
    encoded_jwt = jwt.encode(to_encode, "SECRET_KEY", algorithm="HS256")
    return {"access_token": encoded_jwt, "token_type": "bearer"}

# Приклад захищеного роуту
@app.get("/protected")
async def protected_data(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, "SECRET_KEY", algorithms=["HS256"])
        login: str = payload.get("sub")
        if login is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недійсний токен")
        return {"protected_data": f"Привіт, {login}!"}
    except PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недійсний токен")


@app.post("/books/")
def create_Book(book: Book):
    if book.Author not in library:
        library[book.Author] = []
    library[book.Author].append(book)
    return {"message": "Книжка додана і т.д"}


@app.get("/books/{author}")
def get_books_by_author(author: str):
    if author not in library:
        raise HTTPException(status_code=404, detail="Автора не знайдено")
    return library[author]


@app.put("/books/{author}/{title}")
def update_book(author: str, title: str, new_pages: int):
    if author not in library or not any(book.Title == title for book in library[author]):
        raise HTTPException(status_code=404, detail="Книжку не знайдено")
    for book in library[author]:
        if book.Title == title:
            book.Pages = new_pages  # Changed attribute name
            return {"message": "Книжка оновлена успішно"}


@app.delete("/books/{author}/{title}")
def delete_book(author: str, title: str):
    if author not in library or not any(book.Title == title for book in library[author]):
        raise HTTPException(status_code=404, detail="Книжку не знайдено")
    library[author] = [book for book in library[author] if book.Title != title]
    return {"message": "Книжка видалена успішно"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
