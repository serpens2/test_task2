from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import bcrypt
import os
from dotenv import find_dotenv, load_dotenv

load_dotenv( find_dotenv() )
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST') #change to localhost in .env when running outside docker container

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:5432/{DB_NAME}" # port 5432 by default

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# creates database, if it does not exist
# also adds admin user and test user
def init_db():
    import models
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(models.User).filter_by(email="admin").first():
            admin_password_hash = bcrypt.hashpw('admin'.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            admin_user = models.User(
                email="admin",
                password_hash=admin_password_hash,
                full_name="admin",
                role="admin"
            )
            db.add(admin_user)
            db.commit()
        if not db.query(models.User).filter_by(email="my_emai@mail.ru").first():
            user_password_hash = bcrypt.hashpw('qwerty'.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            test_user = models.User(
                email="my_email@mail.ru",
                password_hash=user_password_hash,
                full_name="John Doe",
                role="user"
            )
            db.add(test_user)
            db.commit()
    finally:
        db.close()
