import os
from datetime import datetime, timedelta
import hmac
import hashlib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PasswordPayload(BaseModel):
    password: str


def verify_password(pw: str) -> bool:
    expected = os.getenv("ADITI_PASSWORD", "aditi19")
    return hmac.compare_digest(pw, expected)


def sign_token() -> str:
    secret = os.getenv("SECRET_KEY", "the19thscroll-secret")
    expires = int((datetime.utcnow() + timedelta(hours=12)).timestamp())
    payload = f"aditi|{expires}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def verify_token(token: str) -> bool:
    try:
        secret = os.getenv("SECRET_KEY", "the19thscroll-secret")
        parts = token.split("|")
        if len(parts) != 3:
            return False
        subject, exp_str, sig = parts
        if subject != "aditi":
            return False
        expected_sig = hmac.new(secret.encode(), f"{subject}|{exp_str}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return False
        if int(exp_str) < int(datetime.utcnow().timestamp()):
            return False
        return True
    except Exception:
        return False


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.post("/api/auth/verify")
def verify(payload: PasswordPayload):
    if verify_password(payload.password):
        return {"success": True, "token": sign_token()}
    raise HTTPException(status_code=401, detail="Invalid password")


@app.post("/api/auth/validate")
def validate(token: str):
    return {"valid": verify_token(token)}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    
    try:
        # Try to import database module
        from database import db
        
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            
            # Try to list collections to verify connectivity
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]  # Show first 10 collections
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
            
    except ImportError:
        response["database"] = "❌ Database module not found (run enable-database first)"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    
    # Check environment variables
    import os
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
