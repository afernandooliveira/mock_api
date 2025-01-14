from fastapi import Depends, FastAPI, HTTPException, Header, Query, Form, Request
from pydantic import BaseModel, Field
from typing import Optional, List
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import sqlite3
import uuid
import base64
import hashlib
import os
import jwt


load_dotenv()


# FastAPI instance
app = FastAPI()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY")

# Database initialization
DATABASE = 'data/users.db'


def initialize_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS USERS (
            ID TEXT PRIMARY KEY,
            SOURCE_ID TEXT,
            NAME TEXT NOT NULL,
            EMAIL TEXT NOT NULL,
            USERNAME TEXT NOT NULL UNIQUE,
            ACCOUNT_ID TEXT,
            PASSWORD TEXT NOT NULL
        )
    ''')
    # Insert initial user
    try:
        password = "QRpwd123!"
        encoded_password = base64.b64encode(password.encode()).decode()
        cursor.execute('''
            INSERT INTO USERS (ID, SOURCE_ID, NAME, EMAIL, USERNAME, ACCOUNT_ID, PASSWORD)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (str(uuid.uuid4()), str(uuid.uuid4()), 'Administrador', 'admin@mock.com', 'admin', 'CN=admin,OU=Brazil,OU=Sailpoint_Mock,DC=qriar,DC=com', encoded_password))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # User already exists
    finally:
        conn.close()


initialize_db()


# Pydantic model
class User(BaseModel):
    name: str
    email: str
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    identityId: str = Field(..., min_length=1)
    encryptedPassword: str = Field(..., min_length=1)
    publicKeyId: str = Field(..., min_length=1)
    accountId: str = Field(..., min_length=1)
    sourceId: str = Field(..., min_length=1)


class QueryPassword(BaseModel):
    userName: str = Field(..., min_length=1)
    sourceName: str = Field(..., min_length=1)


async def verify_token(authorization: str = Header(...)):
    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        expiration_time = datetime.fromtimestamp(payload["exp"], timezone.utc)
        if  datetime.now(timezone.utc) > expiration_time:
            raise HTTPException(status_code=401, detail={"error": "JWT validation failed: JWT is expired"})
        return payload
    except Exception as error:
        raise HTTPException(status_code=401, detail= {
                    "detailCode": "400.1 Bad Request Content",
                    "trackingId": "e7eab60924f64aa284175b9fa3309599",
                    "messages": [
                        {
                            "locale": "en-US",
                            "localeOrigin": "DEFAULT",
                            "text": "The request was syntactically correct but its content is semantically invalid."
                        }
                    ],
                    "causes": [
                        {
                            "locale": "en-US",
                            "localeOrigin": "DEFAULT",
                            "text": "The request was syntactically correct but its content is semantically invalid."
                        }
                    ]
                }
        )


# Helper function to validate Base64 encoding
def is_base64(s: str) -> bool:
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False


@app.middleware("http")
async def log_requests(request: Request, call_next):
    log_filename = datetime.now().strftime("LOG-%d%m%Y.log")
    log_entry = f"{datetime.now()} - {request.method} {request.url}\n"

    with open(log_filename, "a") as log_file:
        log_file.write(log_entry)

    response = await call_next(request)
    return response    


@app.post("/v2024/set-password/")
def set_password(
    request: PasswordChangeRequest,
    token_payload: dict = Depends(verify_token)
):
    try :
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Verificar se existe usuário com identityId
        cursor.execute("SELECT * FROM USERS WHERE ID = ?", (request.identityId,))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=401, detail="Identity not found")

        # Localizar usuário pelo sourceId
        cursor.execute("SELECT * FROM USERS WHERE ID = ?", (request.sourceId,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")

        # Atualizar a senha
        encoded_password = base64.b64encode(request.encryptedPassword.encode()).decode() 
        cursor.execute(
            "UPDATE USERS SET PASSWORD = ? WHERE ID = ? AND USERNAME = ?",
            (encoded_password, request.sourceId, request.accountId)
        )

        conn.commit()
        conn.close()
        
        retorno_id = str(uuid.uuid4())

        return {"requestId": retorno_id, "state": "FINISHED"}
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail=f"'requestId': {retorno_id}, 'state': 'FAILED'")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {e}")


@app.post("/v2024/query-password-info")
def query_password(
    request: QueryPassword,
    token_payload: dict = Depends(verify_token)
):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM USERS WHERE USERNAME = ?", (request.userName,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            raise HTTPException(status_code=401, detail="Identity not found")      

        result = {
            "identityId": user[0],
            "sourceId": user[1],
            "publicKeyId": ''.join([line[15:] for line in open('cacert/publicKeyId.file')]),
            "publicKey": ''.join([line for line in open('cacert/public_key.pem').readlines()[1:-1]]),
            "accounts": [
                {
                    "accountId": user[5],
                    "accountName": user[4]
                }
            ],
            "policies": [
                "passwordRepeatedChar is 3",
                "passwordMinAlpha is 1",
                "passwordMinLength is 5",
                "passwordMinNumeric is 1"
            ]
        }
        conn.close()
        return result        

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {e}")


@app.post("/oauth/token")
def generate_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...)
):
    if grant_type != "client_credentials":
        raise HTTPException(status_code=400, detail="Invalid grant_type")

    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Geração do token JWT
    payload = {
        "client_id": client_id,
        "exp": datetime.utcnow() + timedelta(hours=1)  # Token válido por 1 hora
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return {"token": token}    


@app.post("/v2024/users")
def create_user(user: User):
    encoded_password = base64.b64encode(user.password.encode()).decode()

    user_id = str(uuid.uuid4())
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO USERS (ID, SOURCE_ID, NAME, EMAIL, USERNAME, ACCOUNT_ID, PASSWORD)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, str(uuid.uuid4()), user.name, user.email, user.username, f"CN={user.username},OU=Brazil,OU=Sailpoint_Mock,DC=qriar,DC=com", encoded_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists.")
    finally:
        conn.close()
    return {"id": user_id}


@app.get("/v2024/query")
def get_users(username: Optional[str] = None):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    if username:
        cursor.execute("SELECT * FROM USERS WHERE USERNAME=?", (username,))
    else:
        cursor.execute("SELECT * FROM USERS")
    users = cursor.fetchall()
    conn.close()

    if not users:
        raise HTTPException(status_code=404, detail="User(s) not found.")

    result = []
    for user in users:
        result.append({
            "id": user[0],
            "sourceId": user[1],
            "name": user[2],
            "email": user[3],
            "username": user[4],
            "accountId": user[5],
            "password": user[6]  
        })
    return result


@app.put("/v2024/users/{user_id}")
def update_user(user_id: str, user: User):

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE USERS
        SET NAME=?, EMAIL=?, USERNAME=?, ACCOUNT_ID=? WHERE ID=?
    ''', (user.name, user.email, user.username, f"CN={user.username},OU=Brazil,OU=Sailpoint_Mock,DC=qriar,DC=com", user_id))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found.")
    conn.commit()
    conn.close()
    return {"detail": "User updated successfully."}


@app.delete("/v2024/users/{user_id}")
def delete_user(user_id: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM USERS WHERE ID=?', (user_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found.")
    conn.commit()
    conn.close()
    return {"detail": "User deleted successfully."}
