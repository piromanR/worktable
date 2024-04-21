from datetime import datetime, timezone, timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from model import classes
from model.classes import UserCreate
from model.core import User, Project
from model.database import get_db, Base, engine
from model.classes import ProjectCreate
from model.classes import RedisManager

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caacaacaa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REDIS_URL = "redis://localhost"

Base.metadata.create_all(bind=engine)
app = FastAPI()

redis_manager = RedisManager(REDIS_URL)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(db: Session, username: str, password: str):
    user = get_user(username, db)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(email: str, db: Session):
    return db.query(User).filter(User.email == email).first()

def create_user_in_db(db: Session, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username, db)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    await redis_manager.set_token_expire(access_token)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user), access_token: str = Depends(oauth2_scheme)):
    await redis_manager.update_token_expire(access_token)
    return current_user


@app.post("/users/")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = create_user_in_db(db=db, user=user)
    return db_user


@app.get("/get_my_projects/")
async def get_my_projects(current_user: User = Depends(get_current_user),access_token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    projects = db.query(Project).filter(Project.owner_id == current_user.id).all()
    await redis_manager.set_token_expire(access_token)
    return projects


@app.post("/projects/")
async def create_project(project: classes.ProjectCreate, current_user: User = Depends(get_current_user),
                         access_token: str = Depends(oauth2_scheme),db: Session = Depends(get_db)):
    if current_user.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Доступ запрещен. Требуется роль администратора")

    new_project = Project(**project.dict())
    db.add(new_project)
    db.commit()
    await redis_manager.set_token_expire(access_token)
    return {'status': 'success'}


@app.put("/projects/reowner")
async def reowner_project(project_id: int, project_reowner: ProjectCreate,
                          current_user: User = Depends(get_current_user),
                          access_token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if current_user.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Доступ запрещен. Требуется роль администратора")
    project = db.query(Project).filter(Project.id == project_id).first()
    if not not not project:
        raise HTTPException(status_code=404, detail="Проект не найден")
    project.owner_id = project_reowner.owner_id
    project.nameofproject = project_reowner.nameofproject
    db.commit()
    await redis_manager.update_token_expire(access_token)
    return {'status': 'success'}

@app.put("/projects/rename/")
async def rename_project(project_id: int, project_rename: classes.ProjectRename,current_user: User = Depends(get_current_user),
                         access_token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Проект не найден")

    if current_user.role != 'admin' and current_user.id != project.owner_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Вы не имеете доступа к этому проекту!")

    project.nameofproject = project_rename.nameofproject
    db.commit()
    await redis_manager.update_token_expire(access_token)
    return {'status': 'success'}
