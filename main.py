import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Literal, Dict, Any
from supabase import create_client, Client

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    UploadFile,
    File,
    Form,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from jose import jwt, JWTError
from passlib.context import CryptContext

# -------------------------------------------------------------------
# ENV & CONFIG
# -------------------------------------------------------------------
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "rentapartment")

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


# -------------------------------------------------------------------
# DB (Motor)
# -------------------------------------------------------------------
client = AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB]

# -------------------------------------------------------------------
# AUTH HELPERS
# -------------------------------------------------------------------
# AUTH HELPERS
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")



def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def objid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc = dict(doc)
    doc["id"] = str(doc["_id"])
    doc.pop("_id", None)
    return doc


def serialize_user(doc: Dict[str, Any]) -> Dict[str, Any]:
    doc = serialize_doc(doc)
    doc.pop("hashed_password", None)
    return doc


# -------------------------------------------------------------------
# Pydantic MODELS
# -------------------------------------------------------------------
UserRole = Literal["user", "landlord", "admin"]


class UserBase(BaseModel):
    name: str
    email: EmailStr
    role: UserRole = "user"
    mobile: Optional[str] = None
    address: Optional[str] = None
    profile_picture_url: Optional[str] = None
    is_active: bool = True


class UserCreate(UserBase):
    password: str


class UserRead(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: UserRole
    mobile: Optional[str]
    address: Optional[str]
    profile_picture_url: Optional[str]
    is_active: bool

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    name: Optional[str] = None
    mobile: Optional[str] = None
    address: Optional[str] = None
    profile_picture_url: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class GoogleLoginRequest(BaseModel):
    id_token: str


# Apartments ---------------------------------------------------------

class ApartmentBase(BaseModel):
    title: str
    description: Optional[str] = None
    address: str
    city: str
    lat: Optional[float] = None
    lng: Optional[float] = None
    price: float
    bedrooms: int
    bathrooms: int
    area_sqft: Optional[float] = None
    availability_date: Optional[str] = None  # ISO string (YYYY-MM-DD)
    amenities: Optional[List[str]] = None
    is_active: bool = True


class ApartmentCreate(ApartmentBase):
    pass


class ApartmentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    price: Optional[float] = None
    bedrooms: Optional[int] = None
    bathrooms: Optional[int] = None
    area_sqft: Optional[float] = None
    availability_date: Optional[str] = None
    amenities: Optional[List[str]] = None
    is_active: Optional[bool] = None


class ApartmentPhotoRead(BaseModel):
    id: str
    apartment_id: str
    image_url: str
    description: Optional[str] = None


class ApartmentRead(ApartmentBase):
    id: str
    landlord_id: str
    photos: List[ApartmentPhotoRead] = []


# Favorites ----------------------------------------------------------

class FavoriteRead(BaseModel):
    id: str
    apartment_id: str
    user_id: str
    created_at: datetime


# Bookings -----------------------------------------------------------

class BookingStatus(str):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class BookingCreate(BaseModel):
    apartment_id: str
    message: Optional[str] = None
    start_date: Optional[str] = None  # ISO date string
    end_date: Optional[str] = None


class BookingUpdateStatus(BaseModel):
    status: Literal["approved", "rejected"]


class BookingRead(BaseModel):
    id: str
    apartment_id: str
    renter_id: str
    message: Optional[str]
    start_date: Optional[str]
    end_date: Optional[str]
    status: str
    created_at: datetime


# Chat / Messages ----------------------------------------------------

class ChatThreadCreate(BaseModel):
    apartment_id: Optional[str] = None
    landlord_id: str
    first_message: Optional[str] = None


class ChatThreadRead(BaseModel):
    id: str
    apartment_id: Optional[str]
    landlord_id: str
    user_id: str
    created_at: datetime
    updated_at: datetime


class MessageCreate(BaseModel):
    text: str


class MessageRead(BaseModel):
    id: str
    thread_id: str
    sender_id: str
    text: str
    created_at: datetime


# Reviews ------------------------------------------------------------

class ReviewCreate(BaseModel):
    landlord_id: str
    rating: int
    comment: str


class ReviewRead(BaseModel):
    id: str
    landlord_id: str
    user_id: str
    rating: int
    comment: str
    created_at: datetime


# -------------------------------------------------------------------
# AUTH DEPENDENCIES
# -------------------------------------------------------------------
async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    return await db.users.find_one({"email": email})


async def get_current_user(
    token: str = Depends(oauth2_scheme),
) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await db.users.find_one({"_id": objid(user_id)})
    if not user or not user.get("is_active", True):
        raise credentials_exception
    return user


def require_roles(*roles: UserRole):
    async def dep(current_user: Dict[str, Any] = Depends(get_current_user)):
        if current_user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
            )
        return current_user

    return dep


# -------------------------------------------------------------------
# APP & CORS & STATIC
# -------------------------------------------------------------------
app = FastAPI(title="RentApartment Mongo API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




# -------------------------------------------------------------------
# AUTH ROUTES
# -------------------------------------------------------------------

@app.get("/debug/db")
async def debug_db():
    try:
        doc = await db.users.insert_one({"test": True})
        return {"ok": True, "id": str(doc.inserted_id)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/auth/register", response_model=UserRead)
async def register(data: UserCreate):
    existing = await get_user_by_email(data.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    doc = data.dict()
    password = doc.pop("password")
    doc["hashed_password"] = hash_password(password)
    doc["created_at"] = datetime.utcnow()

    res = await db.users.insert_one(doc)
    user = await db.users.find_one({"_id": res.inserted_id})
    return UserRead(**serialize_user(user))


@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await get_user_by_email(form_data.username)
    if not user or "hashed_password" not in user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    token = create_access_token(
        {"sub": str(user["_id"]), "role": user.get("role", "user")}
    )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/auth/google", response_model=Token)
async def google_login(payload: GoogleLoginRequest):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=500,
            detail="Google CLIENT_ID not configured on server",
        )

    try:
        info = id_token.verify_oauth2_token(
            payload.id_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Google token")

    google_sub = info.get("sub")
    email = info.get("email")
    name = info.get("name") or "Google User"
    picture = info.get("picture")

    if not google_sub or not email:
        raise HTTPException(status_code=400, detail="Missing Google account info")

    user = await db.users.find_one({"google_sub": google_sub})
    if not user:
        user = await get_user_by_email(email)
        if user:
            await db.users.update_one(
                {"_id": user["_id"]},
                {"$set": {"google_sub": google_sub, "profile_picture_url": picture}},
            )
        else:
            doc = {
                "email": email,
                "name": name,
                "role": "user",
                "google_sub": google_sub,
                "profile_picture_url": picture,
                "is_active": True,
                "created_at": datetime.utcnow(),
            }
            res = await db.users.insert_one(doc)
            user = await db.users.find_one({"_id": res.inserted_id})
    else:
        updates = {"email": email, "name": name}
        if picture:
            updates["profile_picture_url"] = picture
        await db.users.update_one({"_id": user["_id"]}, {"$set": updates})
        user.update(updates)

    token = create_access_token(
        {"sub": str(user["_id"]), "role": user.get("role", "user")}
    )
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/me", response_model=UserRead)
async def read_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return UserRead(**serialize_user(current_user))


# -------------------------------------------------------------------
# USER ROUTES
# -------------------------------------------------------------------
@app.put("/users/me", response_model=UserRead)
async def update_me(
    data: UserUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    update_data = {k: v for k, v in data.dict().items() if v is not None}
    if not update_data:
        return UserRead(**serialize_user(current_user))

    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": update_data},
    )
    user = await db.users.find_one({"_id": current_user["_id"]})
    return UserRead(**serialize_user(user))


@app.get("/admin/users", response_model=List[UserRead])
async def admin_list_users(
    admin: Dict[str, Any] = Depends(require_roles("admin")),
):
    cursor = db.users.find({})
    users: List[UserRead] = []
    async for u in cursor:
        users.append(UserRead(**serialize_user(u)))
    return users


# -------------------------------------------------------------------
# APARTMENTS
# -------------------------------------------------------------------
async def fetch_apartment_with_photos(ap_doc: Dict[str, Any]) -> ApartmentRead:
    apt_id = str(ap_doc["_id"])
    photos_cursor = db.photos.find({"apartment_id": apt_id})
    photos: List[ApartmentPhotoRead] = []
    async for p in photos_cursor:
        p_ser = serialize_doc(p)
        photos.append(
            ApartmentPhotoRead(
                id=p_ser["id"],
                apartment_id=p_ser["apartment_id"],
                image_url=p_ser["image_url"],
                description=p_ser.get("description"),
            )
        )

    ap_ser = serialize_doc(ap_doc)
    return ApartmentRead(
        **{
            **ap_ser,
            "landlord_id": ap_ser["landlord_id"],
            "photos": photos,
        }
    )




from fastapi import Form

@app.post("/apartmentwithpic", response_model=ApartmentRead)
async def create_apartment(
    apartment_json: str = Form(...),
    photos: List[UploadFile] = File([]),
    current_user=Depends(require_roles("landlord", "admin"))
):
    # Parse JSON apartment data
    import json
    try:
        data = json.loads(apartment_json)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON for apartment")

    if len(photos) > 5:
        raise HTTPException(status_code=400, detail="Maximum 5 photos allowed")

    doc = data
    doc["landlord_id"] = str(current_user["_id"])
    doc["created_at"] = datetime.utcnow()
    doc["updated_at"] = datetime.utcnow()

    # Insert apartment
    res = await db.apartments.insert_one(doc)
    apartment_id = str(res.inserted_id)

    uploaded_photos = []

    # Upload each photo (max 5)
    for file in photos:
        ext = file.filename.split('.')[-1]
        filename = f"{apartment_id}_{int(datetime.utcnow().timestamp())}.{ext}"

        contents = await file.read()
        supabase.storage.from_(SUPABASE_BUCKET).upload(filename, contents)

        image_url = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{filename}"

        photo_doc = {
            "apartment_id": apartment_id,
            "image_url": image_url,
            "created_at": datetime.utcnow()
        }

        photo_res = await db.photos.insert_one(photo_doc)
        photo_inserted = await db.photos.find_one({"_id": photo_res.inserted_id})
        uploaded_photos.append(ApartmentPhotoRead(**serialize_doc(photo_inserted)))

    # Build full response
    ap = await db.apartments.find_one({"_id": res.inserted_id})
    ap_ser = serialize_doc(ap)

    return ApartmentRead(
        **ap_ser,
        photos=uploaded_photos
    )



@app.post("/apartments", response_model=ApartmentRead)
async def create_apartment(
    data: ApartmentCreate,
    current_user: Dict[str, Any] = Depends(require_roles("landlord", "admin")),
):
    doc = data.dict()
    doc["landlord_id"] = str(current_user["_id"])
    doc["created_at"] = datetime.utcnow()
    doc["updated_at"] = datetime.utcnow()

    res = await db.apartments.insert_one(doc)
    ap = await db.apartments.find_one({"_id": res.inserted_id})
    return await fetch_apartment_with_photos(ap)


@app.get("/apartments", response_model=List[ApartmentRead])
async def list_apartments(
    city: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    bedrooms: Optional[int] = None,
):
    query: Dict[str, Any] = {"is_active": True}
    if city:
        query["city"] = {"$regex": city, "$options": "i"}
    if min_price is not None:
        query.setdefault("price", {})
        query["price"]["$gte"] = min_price
    if max_price is not None:
        query.setdefault("price", {})
        query["price"]["$lte"] = max_price
    if bedrooms is not None:
        query["bedrooms"] = {"$gte": bedrooms}

    cursor = db.apartments.find(query).sort("created_at", -1)
    results: List[ApartmentRead] = []
    async for ap in cursor:
        results.append(await fetch_apartment_with_photos(ap))
    return results


@app.get("/apartments/{apartment_id}", response_model=ApartmentRead)
async def get_apartment(apartment_id: str):
    ap = await db.apartments.find_one({"_id": objid(apartment_id)})
    if not ap or not ap.get("is_active", True):
        raise HTTPException(status_code=404, detail="Apartment not found")
    return await fetch_apartment_with_photos(ap)


@app.get("/landlord/apartments", response_model=List[ApartmentRead])
async def my_apartments(
    current_user: Dict[str, Any] = Depends(require_roles("landlord", "admin")),
):
    query: Dict[str, Any] = {}
    if current_user.get("role") == "landlord":
        query["landlord_id"] = str(current_user["_id"])

    cursor = db.apartments.find(query).sort("created_at", -1)
    results: List[ApartmentRead] = []
    async for ap in cursor:
        results.append(await fetch_apartment_with_photos(ap))
    return results


@app.patch("/apartments/{apartment_id}", response_model=ApartmentRead)
async def update_apartment(
    apartment_id: str,
    data: ApartmentUpdate,
    current_user: Dict[str, Any] = Depends(require_roles("landlord", "admin")),
):
    ap = await db.apartments.find_one({"_id": objid(apartment_id)})
    if not ap:
        raise HTTPException(status_code=404, detail="Apartment not found")

    if current_user.get("role") != "admin" and ap["landlord_id"] != str(
        current_user["_id"]
    ):
        raise HTTPException(status_code=403, detail="Not allowed")

    update_data = {k: v for k, v in data.dict().items() if v is not None}
    if update_data:
        update_data["updated_at"] = datetime.utcnow()
        await db.apartments.update_one(
            {"_id": ap["_id"]},
            {"$set": update_data},
        )

    ap = await db.apartments.find_one({"_id": ap["_id"]})
    return await fetch_apartment_with_photos(ap)


@app.delete("/apartments/{apartment_id}", status_code=204)
async def delete_apartment(
    apartment_id: str,
    current_user: Dict[str, Any] = Depends(require_roles("landlord", "admin")),
):
    ap = await db.apartments.find_one({"_id": objid(apartment_id)})
    if not ap:
        raise HTTPException(status_code=404, detail="Apartment not found")

    if current_user.get("role") != "admin" and ap["landlord_id"] != str(
        current_user["_id"]
    ):
        raise HTTPException(status_code=403, detail="Not allowed")

    await db.apartments.delete_one({"_id": ap["_id"]})
    await db.photos.delete_many({"apartment_id": str(ap["_id"])})
    return None


# -------------------------------------------------------------------
# PHOTO UPLOAD
# -------------------------------------------------------------------
@app.post("/apartments/{apartment_id}/photos", response_model=ApartmentPhotoRead)
async def upload_apartment_photo(
    apartment_id: str,
    file: UploadFile = File(...),
    description: Optional[str] = Form(default=None),
    current_user: Dict[str, Any] = Depends(require_roles("landlord", "admin")),
):
    ap = await db.apartments.find_one({"_id": objid(apartment_id)})
    if not ap:
        raise HTTPException(status_code=404, detail="Apartment not found")

    if current_user.get("role") != "admin" and ap["landlord_id"] != str(
        current_user["_id"]
    ):
        raise HTTPException(status_code=403, detail="Not allowed")

    ext = file.filename.split(".")[-1]
    filename = f"apt_{apartment_id}_{int(datetime.utcnow().timestamp())}.{ext}"
    filepath = UPLOAD_DIR / filename

    content = await file.read()
    with filepath.open("wb") as f:
        f.write(content)

    image_url = f"/static/{filename}"
    doc = {
        "apartment_id": apartment_id,
        "image_url": image_url,
        "description": description,
        "created_at": datetime.utcnow(),
    }
    res = await db.photos.insert_one(doc)
    photo = await db.photos.find_one({"_id": res.inserted_id})
    p_ser = serialize_doc(photo)
    return ApartmentPhotoRead(
        id=p_ser["id"],
        apartment_id=p_ser["apartment_id"],
        image_url=p_ser["image_url"],
        description=p_ser.get("description"),
    )


# -------------------------------------------------------------------
# FAVORITES
# -------------------------------------------------------------------
@app.post("/favorites/{apartment_id}", status_code=204)
async def add_favorite(
    apartment_id: str,
    current_user: Dict[str, Any] = Depends(require_roles("user", "landlord", "admin")),
):
    await db.favorites.update_one(
        {"user_id": str(current_user["_id"]), "apartment_id": apartment_id},
        {
            "$set": {
                "user_id": str(current_user["_id"]),
                "apartment_id": apartment_id,
                "created_at": datetime.utcnow(),
            }
        },
        upsert=True,
    )
    return None


@app.delete("/favorites/{apartment_id}", status_code=204)
async def remove_favorite(
    apartment_id: str,
    current_user: Dict[str, Any] = Depends(require_roles("user", "landlord", "admin")),
):
    await db.favorites.delete_one(
        {"user_id": str(current_user["_id"]), "apartment_id": apartment_id}
    )
    return None


@app.get("/favorites", response_model=List[ApartmentRead])
async def list_favorites(
    current_user: Dict[str, Any] = Depends(require_roles("user", "landlord", "admin")),
):
    cursor = db.favorites.find({"user_id": str(current_user["_id"])})
    apt_ids: List[str] = []
    async for fav in cursor:
        apt_ids.append(fav["apartment_id"])
    if not apt_ids:
        return []

    ap_cursor = db.apartments.find({"_id": {"$in": [objid(i) for i in apt_ids]}})
    results: List[ApartmentRead] = []
    async for ap in ap_cursor:
        results.append(await fetch_apartment_with_photos(ap))
    return results


# -------------------------------------------------------------------
# BOOKINGS
# -------------------------------------------------------------------
@app.post("/bookings", response_model=BookingRead)
async def create_booking(
    data: BookingCreate,
    current_user: Dict[str, Any] = Depends(require_roles("user", "admin")),
):
    ap = await db.apartments.find_one({"_id": objid(data.apartment_id)})
    if not ap or not ap.get("is_active", True):
        raise HTTPException(status_code=404, detail="Apartment not found")

    doc = {
        "apartment_id": data.apartment_id,
        "renter_id": str(current_user["_id"]),
        "message": data.message,
        "start_date": data.start_date,
        "end_date": data.end_date,
        "status": BookingStatus.PENDING,
        "created_at": datetime.utcnow(),
    }
    res = await db.bookings.insert_one(doc)
    b = await db.bookings.find_one({"_id": res.inserted_id})
    b_ser = serialize_doc(b)
    return BookingRead(
        id=b_ser["id"],
        apartment_id=b_ser["apartment_id"],
        renter_id=b_ser["renter_id"],
        message=b_ser.get("message"),
        start_date=b_ser.get("start_date"),
        end_date=b_ser.get("end_date"),
        status=b_ser["status"],
        created_at=b_ser["created_at"],
    )


@app.get("/bookings/me", response_model=List[BookingRead])
async def my_bookings(
    current_user: Dict[str, Any] = Depends(require_roles("user", "admin")),
):
    cursor = db.bookings.find({"renter_id": str(current_user["_id"])}).sort(
        "created_at", -1
    )
    results: List[BookingRead] = []
    async for b in cursor:
        b_ser = serialize_doc(b)
        results.append(
            BookingRead(
                id=b_ser["id"],
                apartment_id=b_ser["apartment_id"],
                renter_id=b_ser["renter_id"],
                message=b_ser.get("message"),
                start_date=b_ser.get("start_date"),
                end_date=b_ser.get("end_date"),
                status=b_ser["status"],
                created_at=b_ser["created_at"],
            )
        )
    return results


@app.get("/bookings/landlord", response_model=List[BookingRead])
async def landlord_bookings(
    current_user: Dict[str, Any] = Depends(require_roles("landlord", "admin")),
):
    # get apartments for this landlord
    apt_cursor = db.apartments.find({"landlord_id": str(current_user["_id"])})
    apt_ids: List[str] = []
    async for ap in apt_cursor:
        apt_ids.append(str(ap["_id"]))
    if not apt_ids:
        return []

    cursor = db.bookings.find({"apartment_id": {"$in": apt_ids}}).sort(
        "created_at", -1
    )
    results: List[BookingRead] = []
    async for b in cursor:
        b_ser = serialize_doc(b)
        results.append(
            BookingRead(
                id=b_ser["id"],
                apartment_id=b_ser["apartment_id"],
                renter_id=b_ser["renter_id"],
                message=b_ser.get("message"),
                start_date=b_ser.get("start_date"),
                end_date=b_ser.get("end_date"),
                status=b_ser["status"],
                created_at=b_ser["created_at"],
            )
        )
    return results


@app.patch("/bookings/{booking_id}", response_model=BookingRead)
async def update_booking_status(
    booking_id: str,
    data: BookingUpdateStatus,
    current_user: Dict[str, Any] = Depends(require_roles("landlord", "admin")),
):
    b = await db.bookings.find_one({"_id": objid(booking_id)})
    if not b:
        raise HTTPException(status_code=404, detail="Booking not found")

    ap = await db.apartments.find_one({"_id": objid(b["apartment_id"])})
    if not ap:
        raise HTTPException(status_code=404, detail="Apartment not found")

    if current_user.get("role") != "admin" and ap["landlord_id"] != str(
        current_user["_id"]
    ):
        raise HTTPException(status_code=403, detail="Not allowed")

    await db.bookings.update_one(
        {"_id": b["_id"]},
        {"$set": {"status": data.status}},
    )
    b = await db.bookings.find_one({"_id": b["_id"]})
    b_ser = serialize_doc(b)
    return BookingRead(
        id=b_ser["id"],
        apartment_id=b_ser["apartment_id"],
        renter_id=b_ser["renter_id"],
        message=b_ser.get("message"),
        start_date=b_ser.get("start_date"),
        end_date=b_ser.get("end_date"),
        status=b_ser["status"],
        created_at=b_ser["created_at"],
    )


# -------------------------------------------------------------------
# CHATS & MESSAGES
# -------------------------------------------------------------------
@app.post("/chats", response_model=ChatThreadRead)
async def create_chat(
    data: ChatThreadCreate,
    current_user: Dict[str, Any] = Depends(require_roles("user", "landlord", "admin")),
):
    # current user is renter side for new chat
    doc = {
        "apartment_id": data.apartment_id,
        "landlord_id": data.landlord_id,
        "user_id": str(current_user["_id"]),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    res = await db.chat_threads.insert_one(doc)
    thread = await db.chat_threads.find_one({"_id": res.inserted_id})

    if data.first_message:
        msg_doc = {
            "thread_id": str(thread["_id"]),
            "sender_id": str(current_user["_id"]),
            "text": data.first_message,
            "created_at": datetime.utcnow(),
        }
        await db.messages.insert_one(msg_doc)
        await db.chat_threads.update_one(
            {"_id": thread["_id"]},
            {"$set": {"updated_at": msg_doc["created_at"]}},
        )
        thread["updated_at"] = msg_doc["created_at"]

    t_ser = serialize_doc(thread)
    return ChatThreadRead(
        id=t_ser["id"],
        apartment_id=t_ser.get("apartment_id"),
        landlord_id=t_ser["landlord_id"],
        user_id=t_ser["user_id"],
        created_at=t_ser["created_at"],
        updated_at=t_ser["updated_at"],
    )


@app.get("/chats", response_model=List[ChatThreadRead])
async def list_chats(
    current_user: Dict[str, Any] = Depends(require_roles("user", "landlord", "admin")),
):
    if current_user.get("role") == "landlord":
        query = {"landlord_id": str(current_user["_id"])}
    elif current_user.get("role") == "admin":
        query = {}
    else:
        query = {"user_id": str(current_user["_id"])}

    cursor = db.chat_threads.find(query).sort("updated_at", -1)
    results: List[ChatThreadRead] = []
    async for t in cursor:
        t_ser = serialize_doc(t)
        results.append(
            ChatThreadRead(
                id=t_ser["id"],
                apartment_id=t_ser.get("apartment_id"),
                landlord_id=t_ser["landlord_id"],
                user_id=t_ser["user_id"],
                created_at=t_ser["created_at"],
                updated_at=t_ser["updated_at"],
            )
        )
    return results


@app.get("/chats/{thread_id}", response_model=ChatThreadRead)
async def get_chat(
    thread_id: str,
    current_user: Dict[str, Any] = Depends(require_roles("user", "landlord", "admin")),
):
    t = await db.chat_threads.find_one({"_id": objid(thread_id)})
    if not t:
        raise HTTPException(status_code=404, detail="Chat not found")

    if current_user.get("role") != "admin" and str(current_user["_id"]) not in [
        t["user_id"],
        t["landlord_id"],
    ]:
        raise HTTPException(status_code=403, detail="Not part of this chat")

    t_ser = serialize_doc(t)
    return ChatThreadRead(
        id=t_ser["id"],
        apartment_id=t_ser.get("apartment_id"),
        landlord_id=t_ser["landlord_id"],
        user_id=t_ser["user_id"],
        created_at=t_ser["created_at"],
        updated_at=t_ser["updated_at"],
    )


@app.get("/chats/{thread_id}/messages", response_model=List[MessageRead])
async def list_messages(
    thread_id: str,
    current_user: Dict[str, Any] = Depends(require_roles("user", "landlord", "admin")),
):
    t = await db.chat_threads.find_one({"_id": objid(thread_id)})
    if not t:
        raise HTTPException(status_code=404, detail="Chat not found")

    if current_user.get("role") != "admin" and str(current_user["_id"]) not in [
        t["user_id"],
        t["landlord_id"],
    ]:
        raise HTTPException(status_code=403, detail="Not part of this chat")

    cursor = db.messages.find({"thread_id": thread_id}).sort("created_at", 1)
    results: List[MessageRead] = []
    async for m in cursor:
        m_ser = serialize_doc(m)
        results.append(
            MessageRead(
                id=m_ser["id"],
                thread_id=m_ser["thread_id"],
                sender_id=m_ser["sender_id"],
                text=m_ser["text"],
                created_at=m_ser["created_at"],
            )
        )
    return results


@app.post("/chats/{thread_id}/messages", response_model=MessageRead)
async def send_message(
    thread_id: str,
    data: MessageCreate,
    current_user: Dict[str, Any] = Depends(require_roles("user", "landlord", "admin")),
):
    t = await db.chat_threads.find_one({"_id": objid(thread_id)})
    if not t:
        raise HTTPException(status_code=404, detail="Chat not found")

    if current_user.get("role") != "admin" and str(current_user["_id"]) not in [
        t["user_id"],
        t["landlord_id"],
    ]:
        raise HTTPException(status_code=403, detail="Not part of this chat")

    now = datetime.utcnow()
    doc = {
        "thread_id": thread_id,
        "sender_id": str(current_user["_id"]),
        "text": data.text,
        "created_at": now,
    }
    res = await db.messages.insert_one(doc)
    await db.chat_threads.update_one(
        {"_id": t["_id"]},
        {"$set": {"updated_at": now}},
    )

    m = await db.messages.find_one({"_id": res.inserted_id})
    m_ser = serialize_doc(m)
    return MessageRead(
        id=m_ser["id"],
        thread_id=m_ser["thread_id"],
        sender_id=m_ser["sender_id"],
        text=m_ser["text"],
        created_at=m_ser["created_at"],
    )


# -------------------------------------------------------------------
# REVIEWS
# -------------------------------------------------------------------
@app.post("/reviews", response_model=ReviewRead)
async def create_review(
    data: ReviewCreate,
    current_user: Dict[str, Any] = Depends(require_roles("user", "admin")),
):
    doc = {
        "landlord_id": data.landlord_id,
        "user_id": str(current_user["_id"]),
        "rating": data.rating,
        "comment": data.comment,
        "created_at": datetime.utcnow(),
    }
    res = await db.reviews.insert_one(doc)
    r = await db.reviews.find_one({"_id": res.inserted_id})
    r_ser = serialize_doc(r)
    return ReviewRead(
        id=r_ser["id"],
        landlord_id=r_ser["landlord_id"],
        user_id=r_ser["user_id"],
        rating=r_ser["rating"],
        comment=r_ser["comment"],
        created_at=r_ser["created_at"],
    )


@app.get("/landlords/{landlord_id}/reviews", response_model=List[ReviewRead])
async def list_landlord_reviews(landlord_id: str):
    cursor = db.reviews.find({"landlord_id": landlord_id}).sort("created_at", -1)
    results: List[ReviewRead] = []
    async for r in cursor:
        r_ser = serialize_doc(r)
        results.append(
            ReviewRead(
                id=r_ser["id"],
                landlord_id=r_ser["landlord_id"],
                user_id=r_ser["user_id"],
                rating=r_ser["rating"],
                comment=r_ser["comment"],
                created_at=r_ser["created_at"],
            )
        )
    return results



@app.post("/apartments/{id}/photos")
async def upload_photo(id: str, file: UploadFile = File(...)):
    contents = await file.read()
    ext = file.filename.split('.')[-1]
    filename = f"{id}_{int(datetime.utcnow().timestamp())}.{ext}"

    supabase.storage \
        .from_(os.getenv("SUPABASE_BUCKET")) \
        .upload(filename, contents)

    image_url = f"{SUPABASE_URL}/storage/v1/object/public/{os.getenv('SUPABASE_BUCKET')}/{filename}"

    await db.photos.insert_one({
        "apartment_id": id,
        "image_url": image_url,
        "created_at": datetime.utcnow()
    })

    return {"image_url": image_url}


# -------------------------------------------------------------------
# HEALTH
# -------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}
