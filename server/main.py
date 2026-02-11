import os
import uuid
import secrets
import requests
from datetime import datetime, timedelta
from typing import Optional

from fastapi import (
    FastAPI,
    HTTPException,
    Form,
    Request,
    Depends,
    Body,
    Query,
)
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from passlib.context import CryptContext
from jose import jwt, JWTError
import psycopg2
from dotenv import load_dotenv
from mangum import Mangum

# =====================
# ENV
# =====================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("ELY_JWT_SECRET")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "elyadmin")

ALGO = "HS256"
TOKEN_DAYS = int(os.getenv("TOKEN_DAYS", 7))
USE_SECURE_COOKIES = bool(os.getenv("VERCEL")) or os.getenv("ENV") == "production"

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =====================
# APP
# =====================
app = FastAPI()
handler = Mangum(app)

# =====================
# STATIC FILES
# =====================
STATIC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Static"))
if os.path.isdir(STATIC_ROOT):
    app.mount("/static", StaticFiles(directory=STATIC_ROOT, html=True), name="static")

# =====================
# CORS
# =====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================
# DATABASE
# =====================
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL missing")
    return psycopg2.connect(DATABASE_URL)

@app.on_event("startup")
def init_db():
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                gmail TEXT UNIQUE,
                password_hash TEXT,
                discord_id TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY,
                product TEXT,
                duration TEXT,
                used_by TEXT,
                used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        conn.commit()

# =====================
# AUTH HELPERS
# =====================
def create_token(uid: str) -> str:
    return jwt.encode(
        {"sub": uid, "exp": datetime.utcnow() + timedelta(days=TOKEN_DAYS)},
        JWT_SECRET,
        algorithm=ALGO,
    )

def decode_token(token: str) -> Optional[str]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGO]).get("sub")
    except JWTError:
        return None

def set_cookie(res, token: str):
    res.set_cookie(
        "ely_token",
        token,
        httponly=True,
        samesite="lax",
        secure=USE_SECURE_COOKIES,
        max_age=TOKEN_DAYS * 86400,
        path="/",
    )

def require_auth(req: Request):
    token = req.cookies.get("ely_token")
    uid = decode_token(token) if token else None
    if not uid:
        raise HTTPException(401, "Unauthorized")
    return uid

# =====================
# ROUTES YOU REQUESTED
# =====================

# /login
@app.get("/login")
def login():
    return RedirectResponse("/static/login.html")

# /dashboard
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(uid=Depends(require_auth)):
    path = os.path.join(STATIC_ROOT, "dashboard.html")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard</h1>"

# /api/register
@app.post("/api/register")
def register(email: str = Form(...), password: str = Form(...)):
    uid = str(uuid.uuid4())
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (id, gmail, password_hash) VALUES (%s,%s,%s)",
                (uid, email, pwd.hash(password)),
            )
            conn.commit()
    except psycopg2.Error:
        raise HTTPException(400, "Email exists")

    res = JSONResponse({"ok": True})
    set_cookie(res, create_token(uid))
    return res

# /api/logout
@app.post("/api/logout")
def logout():
    res = JSONResponse({"ok": True})
    res.delete_cookie("ely_token", path="/")
    return res

# /api/me
@app.get("/api/me")
def me(uid=Depends(require_auth)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT gmail, discord_id FROM users WHERE id=%s", (uid,))
        u = cur.fetchone()
    return {"email": u[0], "discord_id": u[1]}

# /api/auth/discord
@app.get("/api/auth/discord")
def discord_login():
    return RedirectResponse(
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        "&response_type=code&scope=identify email"
    )

# /api/auth/discord/callback
@app.get("/api/auth/discord/callback")
def discord_callback(code: str):
    token_res = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DISCORD_REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    ).json()

    if "access_token" not in token_res:
        raise HTTPException(400, "Discord auth failed")

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_res['access_token']}"},
    ).json()

    discord_id = user["id"]
    email = user.get("email")

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE discord_id=%s", (discord_id,))
        row = cur.fetchone()
        if row:
            uid = row[0]
        else:
            uid = str(uuid.uuid4())
            cur.execute(
                "INSERT INTO users (id, gmail, discord_id) VALUES (%s,%s,%s)",
                (uid, email, discord_id),
            )
            conn.commit()

    res = RedirectResponse("/dashboard")
    set_cookie(res, create_token(uid))
    return res

# /api/redeem
@app.post("/api/redeem")
def redeem(data: dict = Body(...), uid=Depends(require_auth)):
    key = data.get("key")
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT used_by FROM licenses WHERE key=%s", (key,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(400, "Invalid key")
        if row[0]:
            raise HTTPException(400, "Already used")
        cur.execute(
            "UPDATE licenses SET used_by=%s, used_at=NOW() WHERE key=%s",
            (uid, key),
        )
        conn.commit()
    return {"ok": True}

# /api/generate_license
@app.post("/api/generate_license")
def generate_license(
    admin_secret: str = Query(...),
    product: str = Query("roblox"),
    duration: str = Query("1month"),
):
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(403)

    key = f"{product.upper()}-{secrets.token_hex(8).upper()}"
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO licenses (key, product, duration) VALUES (%s,%s,%s)",
            (key, product, duration),
        )
        conn.commit()

    return {"key": key, "product": product, "duration": duration}
