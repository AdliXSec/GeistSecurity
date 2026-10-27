import uuid
import datetime
import hashlib
import secrets
from typing import Optional
import jwt
from fastapi import APIRouter, HTTPException, status, Header, Depends
from backend.config import settings
from backend.models.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    AuthTokenResponse,
)
from backend.database import (
    create_user,
    get_user_by_id,
    get_user_by_username_or_email,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

# ====================================================================
#  Password Cryptographic Helpers (PBKDF2-HMAC-SHA256)
# ====================================================================

def hash_password(password: str) -> str:
    """Hash password using salted PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000,
    )
    return f"{salt}${key.hex()}"

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against stored salt and key hash using constant-time comparison."""
    try:
        salt, key_hex = hashed_password.split("$", 1)
        expected_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        )
        return secrets.compare_digest(expected_key.hex(), key_hex)
    except Exception:
        return False

# ====================================================================
#  JWT Token Helpers
# ====================================================================

def create_access_token(user_id: str, username: str) -> str:
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        hours=settings.AUTH_TOKEN_EXPIRE_HOURS
    )
    payload = {
        "sub": user_id,
        "username": username,
        "exp": expire,
        "iat": datetime.datetime.now(datetime.timezone.utc),
    }
    return jwt.encode(payload, settings.AUTH_SECRET_KEY, algorithm="HS256")

async def get_current_user_optional(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    if not authorization:
        return None
    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() != "bearer":
            return None
        payload = jwt.decode(token, settings.AUTH_SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            return None
        return await get_user_by_id(user_id)
    except Exception:
        return None

async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    user = await get_current_user_optional(authorization)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# ====================================================================
#  Endpoints
# ====================================================================

@router.post("/register", response_model=AuthTokenResponse)
async def register(req: UserRegisterRequest):
    """
    Register a new operator with username, email, and password.
    """
    clean_username = req.username.lower().strip()
    clean_email = req.email.lower().strip()

    # Check if username exists
    try:
        existing_user = await get_user_by_username_or_email(clean_username)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database lookup error (user): {type(e).__name__}: {str(e)}",
        )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{req.username}' is already taken.",
        )

    # Check if email exists
    try:
        existing_email = await get_user_by_username_or_email(clean_email)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database lookup error (email): {type(e).__name__}: {str(e)}",
        )

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email '{req.email}' is already registered.",
        )

    user_id = str(uuid.uuid4())
    pw_hash = hash_password(req.password)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        created = await create_user(
            user_id=user_id,
            username=clean_username,
            email=clean_email,
            password_hash=pw_hash,
            full_name=req.full_name.strip() if req.full_name else None,
            created_at=now_iso,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error creating user: {type(e).__name__}: {str(e)}",
        )

    try:
        token = create_access_token(user_id=user_id, username=clean_username)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating token: {type(e).__name__}: {str(e)}",
        )

    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=created["id"],
            username=created["username"],
            email=created["email"],
            full_name=created.get("full_name"),
            created_at=created["created_at"],
        ),
    )

@router.post("/login", response_model=AuthTokenResponse)
async def login(req: UserLoginRequest):
    """
    Authenticate an operator with username/email and password.
    """
    identifier = req.username_or_email.lower().strip()
    try:
        user = await get_user_by_username_or_email(identifier)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database lookup error during login: {type(e).__name__}: {str(e)}",
        )

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user_id=user["id"], username=user["username"])

    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            full_name=user.get("full_name"),
            created_at=user["created_at"],
        ),
    )

@router.get("/me", response_model=UserResponse)
async def get_me(user: dict = Depends(get_current_user)):
    """
    Retrieve profile details for the authenticated operator.
    """
    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        full_name=user.get("full_name"),
        created_at=user["created_at"],
    )
