from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base 
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import jwt

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#Database Setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
SECRET_KEY="344da2b3a7ab77713b6f72acfd4586e5"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=30
engine =create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

#defining alchemy models
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)

class Book(Base):
    __tablename__="books"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    author = Column(String)
    published_year = Column(Integer)

class Loan(Base):
    __tablename__ = "loans"

    id = Column(Integer, primary_key=True, index=True)
    book_id = Column(Integer, ForeignKey("books.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    borrow_date = Column(DateTime, default=datetime.now(tz=timezone.utc))
    return_date = Column(DateTime, nullable=True)

    book = relationship("Book", back_populates="loans")
    user = relationship("User", back_populates="loans")

Book.loans = relationship("Loan", back_populates="book")
User.loans = relationship("Loan", back_populates="user")

#creating database table
Base.metadata.create_all(bind=engine)

#implementing token generation and authentication
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password,hashed_password)

def get_user(db_session, username:str):
    return db_session.query(User).filter(User.username == username).first()

def authenticate_user(db_session, username:str, password:str):
    user = get_user(db_session, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data:dict, expires_delta:timedelta):
    to_encode=data.copy()
    expire=datetime.now(tz=timezone.utc) + expires_delta
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#Dependency to get the Database Session
def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
    
#Dependency to get the current User
def get_current_user(token: str = Depends(oauth2_scheme),db:Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username:str=payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate" : "Bearer"},
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate":"Bearer"},
        )
    user = get_user(db, username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


#Pydantic models

class UserBase(BaseModel):
    username:str

class UserCreate(UserBase):
    password:str
    
class UserResponse(UserBase):
    id:int
    is_admin:bool

    class Config:
        orm_mode:True

class BookBase(BaseModel):
    title:str 
    author:str
    published_year:int

class BookCreate(BookBase):
    pass 

class BookResponse(BookBase):
    id:int
    class Config:
        orm_mode:True

class LoanBase(BaseModel):
    user_id:int
    book_id:int

class LoanCreate(LoanBase):
    pass 

class LoanResponse(LoanBase):
    id:int
    borrow_date:datetime
    return_date:Optional[datetime]

    class Config:
        orm_mode:True

#API endpoints

@app.post("/users", response_model=UserResponse)
def create_user(user:UserCreate, db: Session=Depends(get_db)):
    existing_user = db.query(User).filter(User.username==user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub":user.username}, expires_delta=access_token_expires

    )
    return {"access_token": access_token,"token_type":"bearer"}

@app.post("/books", response_model=BookResponse)
def create_book(book: BookCreate, db: Session=Depends(get_db), current_user: User = Depends(get_current_user)):
    db_book=Book(**book.model_dump())
    db.add(db_book)
    db.commit()
    db.refresh(db_book)
    return db_book

@app.get("/books", response_model=List[BookResponse])
def get_books(skip:int=0, limit:int = 10, db:Session=Depends(get_db)):
    books = db.query(Book).offset(skip).limit(limit).all()
    return books

@app.get("/books/{book_id}", response_model=BookResponse)
def get_book(book_id:int , db: Session=Depends(get_db)):
    book = db.query(Book).filter(Book.id==book_id).first()
    if not book: 
        raise HTTPException(status_code=404, detail="Book not found")
    return book

@app.post("/loans", response_model=LoanResponse)
def create_loan(loan:LoanCreate, db:Session=Depends(get_db)):
    db_loan = Loan(**loan.model_dump(), borrow_date=datetime.now(tz=timezone.utc))
    db.add(db_loan)
    db.commit()
    db.refresh(db_loan)
    return db_loan


@app.put("/loans/{loan_id}", response_model=LoanResponse)
def return_book(loan_id:int, db:Session = Depends(get_db)):
    loan = db.query(Loan).filter(Loan.id==loan_id).first()
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")
    loan.return_date=datetime.now(tz=timezone.utc)
    db.commit()
    db.refresh(loan)
    return loan

@app.put("/books{book_id}", response_model=BookResponse)
def update_book(book_id:int, book:BookCreate, db:Session=Depends(get_db), current_user: User=Depends(get_current_user)):
    db_book=db.query(Book).filter(Book.id==book_id).first()
    if not db_book:
        raise HTTPException(status_code=404,detail="Book not Found")
    db_book.title=book.title
    db_book.author=book.author
    db_book.published_year=book.published_year
    db.commit()
    db.refresh(db_book)
    return db_book