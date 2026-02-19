from typing import Annotated
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, Path,Request,Form
from starlette import status
from ..models import Users
from ..database import SessionLocal
from .auth import get_current_user,authenticate_user,bcrypt_context
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates 

router = APIRouter(
    prefix='/user',
    tags=['user']
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
templates = Jinja2Templates(directory="TODOapp/templates")

class UserVerification(BaseModel):
    username : str
    password: str
    new_password: str = Field(min_length=6)


@router.get('/', status_code=status.HTTP_200_OK)
async def get_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    return db.query(Users).filter(Users.id == user.get('id')).first()


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(user: user_dependency, db: db_dependency,
                          user_verification: UserVerification):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()

    if not bcrypt_context.verify(user_verification.password, user_model.hashed_password):
        raise HTTPException(status_code=401, detail='Error on password change')
    user_model.hashed_password = bcrypt_context.hash(user_verification.new_password)
    db.add(user_model)
    db.commit()


@router.put("/phonenumber/{phone_number}", status_code=status.HTTP_204_NO_CONTENT)
async def change_phonenumber(user: user_dependency, db: db_dependency,
                          phone_number: str):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()
    user_model.phone_number = phone_number
    db.add(user_model)
    db.commit()


@router.get("/edit-password")
def edit_user_view(request : Request):
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    return templates.TemplateResponse("edit-user-password.html",{"request" : request , "user" : user } )


@router.post("/edit-user-password")
def user_change_password(
    request: Request,
    db: db_dependency,
    username: str = Form(...),
    password: str = Form(...),
    new_password: str = Form(...),
    user=Depends(get_current_user)
):
    user_data = db.query(Users).filter(Users.username == username).first()
    msg = "Invalid username or password"

    if user_data:
        if bcrypt_context.verify(password, user_data.hashed_password):
            user_data.hashed_password = bcrypt_context.hash(new_password)
            db.commit()
            msg = "Password updated successfully"

    return templates.TemplateResponse(
        "edit-user-password.html",
        {
            "request": request,
            "user": user,
            "msg": msg
        }
    )

