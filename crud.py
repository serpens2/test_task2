from sqlalchemy.orm import Session
import models
from schemas import UserSchema

def create_user(db: Session, user_schema: UserSchema, password_hash: str, role: str = "user"):
    db_user = models.User(email=user_schema.email, full_name=user_schema.full_name,
                          password_hash=password_hash, role=role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_accounts_by_user(db: Session, user_id: str):
    return db.query(models.Account).filter(models.Account.user_id == user_id).all()

def get_transactions_by_user(db: Session, user_id):
    transactions = (
        db.query(models.Transaction)
        .join(models.Account, models.Transaction.account_id == models.Account.id)
        .filter(models.Account.user_id == user_id)
        .all()
    )
    return transactions

def delete_user(db: Session, user_id: str):
    user = db.get(models.User, user_id)
    if not user:
        return False
    db.delete(user)
    db.commit()
    return True