import database, crud, schemas, models
from fastapi import FastAPI, Depends, HTTPException, Form, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session, joinedload
import bcrypt, jwt, uuid, hashlib
import datetime, time, random
import os
from dotenv import find_dotenv, load_dotenv

load_dotenv( find_dotenv() )
PRIVATE_JWT_KEY = os.getenv('PRIVATE_JWT_KEY')
PUBLIC_JWT_KEY = os.getenv('PUBLIC_JWT_KEY')
SHA_KEY = os.getenv('SHA_KEY')
EXP_MIN = int(os.getenv('EXP_MIN'))
EXP_TIME = datetime.timedelta(minutes=EXP_MIN)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def decode_token(token: str):
    try:
        return jwt.decode(token, PUBLIC_JWT_KEY, algorithms=["RS256"])
    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))

def generate_signature(data: dict) -> str:
    string = "".join( str(data[k]) for k in data if not k == "signature" ) + SHA_KEY
    return hashlib.sha256(string.encode("utf-8")).hexdigest()

http_bearer = HTTPBearer()
app = FastAPI()

@app.on_event("startup")
def startup_event():
    database.init_db()

@app.post("/login")
def login(email: str = Form(...), password: str = Form(...),
          db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        raise HTTPException(status_code=400, detail="Wrong password")

    payload = {"sub": user.email, "role": user.role, "exp": datetime.datetime.utcnow() + EXP_TIME}
    token = jwt.encode(payload, PRIVATE_JWT_KEY, algorithm="RS256")
    return {"access_token": token, "token_type": "Bearer"}

@app.get("/create_bank_account")
def create_account(creds: HTTPAuthorizationCredentials = Depends(http_bearer),
                   db: Session = Depends(get_db)):
    payload = decode_token(creds.credentials)
    user_id = crud.get_user_by_email(db, payload.get('sub')).id
    if not db.query(models.User).filter_by(id=user_id).first():
        raise HTTPException(status_code=404, detail="User not found")
    account = models.Account(user_id=user_id, amount=0)
    db.add(account)
    db.commit()
    db.refresh(account)
    return {'info': 'Bank account created'}

@app.post('/top_up', status_code=202)
def top_up(account_id: uuid.UUID, amount: float,
            background_tasks: BackgroundTasks,
           creds: HTTPAuthorizationCredentials = Depends(http_bearer),
           db: Session = Depends(get_db)):
    payload = decode_token(creds.credentials)
    account = db.query(models.Account).filter_by(id=account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Bank account not found")
    user = crud.get_user_by_email(db, payload.get('sub'))
    if account.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not your bank account")
    background_tasks.add_task(simulate_webhook, account.user_id, account.id, amount, db)
    return {'info': 'Bank account will be updated soon'}

def simulate_webhook(user_id, account_id, amount, db):
    time.sleep(random.uniform(2,7))
    transaction_id = str(uuid.uuid4())
    data = {
        "transaction_id": transaction_id,
        "user_id": str(user_id),
        "account_id": str(account_id),
        "amount": amount
    }
    signature = generate_signature(data)
    data["signature"] = signature
    webhook_catcher(data,db)

@app.post("/webhook")
def webhook_catcher(data, db):
    expected_signature = generate_signature(data)
    if data["signature"] != expected_signature:
        raise HTTPException(status_code=400, detail="Invalid signature")
    if db.query(models.Transaction).filter_by(id=data["transaction_id"]).first():
        raise HTTPException(status_code=400, detail="Duplicate transaction")
    account = db.query(models.Account).filter_by(id=data["account_id"]).first()
    if not account:
        account = models.Account(id=data["account_id"], user_id=data["user_id"], amount=0)
        db.add(account)
        db.commit()
        db.refresh(account)
    transaction = models.Transaction(
        id = data["transaction_id"],
        account_id = data["account_id"],
        amount = data["amount"],
        time = datetime.datetime.utcnow()
    )
    db.add(transaction)
    account.amount += data["amount"]
    db.commit()
    print(f"Transaction completed: {data['transaction_id']}")
    return {'info': 'Transaction successful'}

@app.post("/admin/create_user")
def register(creds: HTTPAuthorizationCredentials = Depends(http_bearer),
             email: str = Form(...), full_name: str = Form(...), password: str = Form(...),
             db: Session = Depends(get_db)):
    payload = decode_token(creds.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not an admin")
    if crud.get_user_by_email(db, email):
        raise HTTPException(status_code=400, detail="User already exists")
    try:
        user_schema = schemas.UserSchema(full_name=full_name, email=email)
    except Exception as e:
        raise HTTPException(status_code=400, detail = str(e))
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    crud.create_user(db, user_schema, password_hash)
    return {'info': 'User created'}

@app.delete("/admin/delete_user/{user_id}")
def delete_user(user_id: str, creds: HTTPAuthorizationCredentials = Depends(http_bearer),
                db: Session = Depends(get_db)):
    payload = decode_token(creds.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not an admin")
    if not crud.delete_user(db, user_id):
        raise HTTPException(status_code=404, detail="User not found")
    return {'info': 'User deleted'}

@app.get("/admin/get_users", description="Users with 'admin' role are not included")
def get_users(creds: HTTPAuthorizationCredentials = Depends(http_bearer),
           db: Session = Depends(get_db)):
    payload = decode_token(creds.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not an admin")
    users = db.query(models.User).options(joinedload(models.User.accounts)).all() # LEFT JOIN
    result = []
    for user in users:
        if user.role != 'admin':
            result.append({
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "accounts": [
                    {
                        "account_id": account.id,
                        "amount": account.amount
                    }
                    for account in user.accounts
                ]
            })
    if result != []:
        return result
    else:
        return {'info': 'No users found'}

@app.get("/me")
def get_me(creds: HTTPAuthorizationCredentials = Depends(http_bearer),
           db: Session = Depends(get_db)):
    payload = decode_token(creds.credentials)
    user = crud.get_user_by_email(db, payload.get('sub'))
    user_data = {col.name: getattr(user, col.name) for col in user.__table__.columns}
    user_data.pop("password_hash", None)
    return user_data

@app.get("/my_bank_accounts")
def get_my_accounts(creds: HTTPAuthorizationCredentials = Depends(http_bearer),
           db: Session = Depends(get_db)):
    payload = decode_token(creds.credentials)
    user = crud.get_user_by_email(db, payload.get('sub'))
    accounts = []
    for account in crud.get_accounts_by_user(db, user.id):
        account_data = {col.name: getattr(account, col.name) for col in account.__table__.columns}
        account_data.pop('user_id',None)
        accounts.append(account_data)
    if accounts != []:
        return accounts
    else:
        return {'info': 'No bank accounts found'}

@app.get("/my_transactions")
def get_my_transactions(creds: HTTPAuthorizationCredentials = Depends(http_bearer),
           db: Session = Depends(get_db)):
    payload = decode_token(creds.credentials)
    user = crud.get_user_by_email(db, payload.get('sub'))
    transactions = []
    for transaction in crud.get_transactions_by_user(db, user.id):
        transaction_data = {col.name: getattr(transaction, col.name) for col in transaction.__table__.columns}
        transaction_data.pop('user_id',None)
        transactions.append(transaction_data)
    if transactions != []:
        return transactions
    else:
        return {'info': 'No transactions found'}