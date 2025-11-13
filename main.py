import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import Category, Product, Customer

import base64

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkeychange")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Auth models
class UserIn(BaseModel):
    name: str
    email: str
    password: str
    role: str  # owner | staff


class UserOut(BaseModel):
    id: str
    name: str
    email: str
    role: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginBody(BaseModel):
    email: str
    password: str


# Utils

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    from bson import ObjectId
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    if db is None:
        raise credentials_exception
    try:
        user = db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        user = None
    if not user:
        raise credentials_exception
    return {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user["role"]}


async def require_owner(user=Depends(get_current_user)):
    if user["role"] != "owner":
        raise HTTPException(status_code=403, detail="Owner access required")
    return user


# Health and DB test
@app.get("/")
def read_root():
    return {"message": "Grocery POS API ready"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Auth routes
@app.post("/auth/register", response_model=UserOut)
def register(user: UserIn):
    if db is None:
        raise HTTPException(500, "Database not configured")
    existing = db["user"].find_one({"email": user.email})
    if existing:
        raise HTTPException(400, "Email already registered")
    doc = {
        "name": user.name,
        "email": user.email,
        "password": get_password_hash(user.password),
        "role": user.role,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(doc)
    return {"id": str(result.inserted_id), "name": user.name, "email": user.email, "role": user.role}


@app.post("/auth/login", response_model=Token)
def login(body: LoginBody):
    if db is None:
        raise HTTPException(500, "Database not configured")
    user = db["user"].find_one({"email": body.email})
    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": str(user["_id"]), "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer"}


# Category endpoints (owner only for create/update)
@app.post("/categories", dependencies=[Depends(require_owner)])
def create_category(category: Category):
    if db is None:
        raise HTTPException(500, "Database not configured")
    _id = create_document("category", category)
    return {"id": _id}


@app.get("/categories")
def list_categories():
    items = get_documents("category") if db else []
    # Normalize id
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# Product endpoints
@app.post("/products", dependencies=[Depends(require_owner)])
def create_product(product: Category | Product):
    # Accepting both Category by mistake would be wrong; ensure Product only
    if isinstance(product, Category):
        raise HTTPException(400, "Invalid payload")
    if db is None:
        raise HTTPException(500, "Database not configured")
    _id = create_document("product", product)
    return {"id": _id}


@app.get("/products")
def list_products(category: Optional[str] = None, q: Optional[str] = None):
    if db is None:
        return []
    filter_dict = {}
    if category:
        filter_dict["category"] = category
    if q:
        filter_dict["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"barcode": {"$regex": q, "$options": "i"}},
        ]
    docs = get_documents("product", filter_dict)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs


# Barcode registration (owner)
class BarcodeRegistration(BaseModel):
    product_id: str
    barcode: str


@app.post("/products/barcode", dependencies=[Depends(require_owner)])
def register_barcode(payload: BarcodeRegistration):
    if db is None:
        raise HTTPException(500, "Database not configured")
    from bson import ObjectId
    try:
        db["product"].update_one({"_id": ObjectId(payload.product_id)}, {"$set": {"barcode": payload.barcode, "updated_at": datetime.now(timezone.utc)}})
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(400, str(e))


# Orders & billing
class CheckoutRequest(BaseModel):
    customer: Optional[Customer] = None
    items: List[dict]  # {product_id, title, quantity, price, variant}
    payment_method: str  # cash | online
    note: Optional[str] = None


@app.post("/checkout")
def checkout(payload: CheckoutRequest, user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(500, "Database not configured")

    # Calculate totals
    subtotal = sum([it["price"] * it["quantity"] for it in payload.items])
    tax = 0
    discount = 0
    total = subtotal + tax - discount

    order_doc = {
        "customer": (payload.customer.dict() if payload.customer else {}),
        "items": payload.items,
        "subtotal": subtotal,
        "discount": discount,
        "tax": tax,
        "total": total,
        "status": "paid" if payload.payment_method == "cash" else "pending",
        "payment_method": payload.payment_method,
        "notes": payload.note,
        "created_by": user["id"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    result = db["order"].insert_one(order_doc)

    # Decrement inventory
    from bson import ObjectId
    for it in payload.items:
        try:
            db["product"].update_one({"_id": ObjectId(it["product_id"])}, {"$inc": {"stock": -int(it["quantity"])}})
        except Exception:
            pass

    return {"order_id": str(result.inserted_id), "total": total, "status": order_doc["status"]}


# Generate payment QR (UPI-like placeholder)
class PaymentIntent(BaseModel):
    order_id: str
    amount: float
    note: Optional[str] = None


@app.post("/payments/qr")
def generate_qr(intent: PaymentIntent, user=Depends(get_current_user)):
    import qrcode
    import io
    if db is None:
        raise HTTPException(500, "Database not configured")

    # Create a simple payment URL data. In real life, integrate with UPI/Stripe etc.
    pay_url = f"pay://grocery-app?order={intent.order_id}&amount={intent.amount}"
    if intent.note:
        pay_url += f"&note={intent.note}"

    img = qrcode.make(pay_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {"qr": f"data:image/png;base64,{b64}", "pay_url": pay_url}


# Simple sales dashboard
@app.get("/dashboard/summary")
def sales_summary(user=Depends(get_current_user)):
    if db is None:
        raise HTTPException(500, "Database not configured")
    pipeline = [
        {"$group": {"_id": None, "orders": {"$sum": 1}, "revenue": {"$sum": "$total"}}}
    ]
    res = list(db["order"].aggregate(pipeline))
    if res:
        return {"orders": res[0].get("orders", 0), "revenue": res[0].get("revenue", 0)}
    return {"orders": 0, "revenue": 0}


# Locker drawer trigger (placeholder)
@app.post("/pos/open-drawer")
def open_cash_drawer(user=Depends(get_current_user)):
    # In a real environment, integrate with the hardware via a printer ESC/POS command
    # Here we just return success to simulate
    return {"status": "triggered"}


# Search products by barcode or text
@app.get("/products/search")
def search_products(q: str):
    if db is None:
        return []
    docs = get_documents("product", {"$or": [
        {"title": {"$regex": q, "$options": "i"}},
        {"barcode": {"$regex": q, "$options": "i"}},
    ]}, limit=20)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
