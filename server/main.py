import os
import uuid
import requests
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Form, Request, Depends, Body, Query
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from passlib.context import CryptContext
from jose import jwt, JWTError
import psycopg2
from dotenv import load_dotenv
# ENV
# =====================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("ELY_JWT_SECRET")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")

ALGO = "HS256"
TOKEN_DAYS = 7

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =====================
# APP
# =====================


app = FastAPI()
import os
import uuid
import secrets
import requests
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Form, Request, Depends, Body, Query
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from passlib.context import CryptContext
from jose import jwt, JWTError
import psycopg2
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# Config
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("ELY_JWT_SECRET", "changeme")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "elyadmin")

ALGO = "HS256"
TOKEN_DAYS = int(os.getenv("TOKEN_DAYS", 7))

# If running on Vercel (or in production), mark secure cookies
USE_SECURE_COOKIES = bool(os.getenv("VERCEL")) or os.getenv("ENV") == "production"

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# App
app = FastAPI()

# Serve static files from the `Static` folder at /static
static_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Static"))
if os.path.isdir(static_root):
    app.mount("/static", StaticFiles(directory=static_root, html=True), name="static-root")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database helper
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg2.connect(DATABASE_URL)


@app.on_event("startup")
def init_db():
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                gmail TEXT UNIQUE,
                password_hash TEXT,
                discord_id TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT NOW()
            )
            """
        )
        conn.commit()

# Auth utilities
def create_token(uid: str) -> str:
    return jwt.encode(
        {"sub": uid, "exp": datetime.utcnow() + timedelta(days=TOKEN_DAYS)},
        JWT_SECRET,
        algorithm=ALGO,
    )


def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
        return payload.get("sub")
    except JWTError:
        return None


def set_cookie(res, token: str):
    res.set_cookie(
        key="ely_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=USE_SECURE_COOKIES,
        max_age=TOKEN_DAYS * 86400,
        path="/",
    )


def auth_user(req: Request):
    token = req.cookies.get("ely_token")
    if not token:
        raise HTTPException(401, "Not logged in")
    uid = decode_token(token)
    if not uid:
        raise HTTPException(401, "Invalid token")
    return uid


# Basic routes and redirects
@app.get("/login.html")
def login_html():
    return RedirectResponse("/static/login.html")


@app.get("/register.html")
def register_html():
    return RedirectResponse("/static/register.html")


@app.get("/dashboard.html")
def dashboard_html():
    return RedirectResponse("/static/dashboard.html")


@app.get("/index.html")
def index_html():
    return RedirectResponse("/static/index.html")


@app.get("/", response_class=HTMLResponse)
def root():
    index_path = os.path.join(os.path.dirname(__file__), "..", "Static", "index.html")
    if os.path.isfile(index_path):
        with open(index_path, encoding="utf-8") as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>Welcome</h1>")


@app.get("/login")
def login_redirect():
    return RedirectResponse("/login.html")


@app.get("/register")
def register_redirect():
    return RedirectResponse("/register.html")


@app.get("/dashboard")
def dashboard_redirect(request: Request):
    token = request.cookies.get("ely_token")
    if not token or not decode_token(token):
        return RedirectResponse("/login.html")
    return RedirectResponse("/dashboard.html")


# Email auth
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
        raise HTTPException(400, "Email already exists")

    res = JSONResponse({"ok": True, "redirect": "/static/dashboard.html"})
    set_cookie(res, create_token(uid))
    return res


@app.post("/api/login")
def login(email: str = Form(...), password: str = Form(...)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password_hash FROM users WHERE gmail=%s",
            (email,),
        )
        row = cur.fetchone()

    if not row or not row[1] or not pwd.verify(password, row[1]):
        raise HTTPException(401, "Invalid credentials")

    token = create_token(row[0])
    res = JSONResponse({"ok": True, "redirect": "/static/dashboard.html"})
    set_cookie(res, token)
    return res


@app.post("/api/logout")
def logout():
    res = JSONResponse({"ok": True})
    res.delete_cookie("ely_token", path="/")
    return res


# Discord OAuth
@app.get("/api/auth/discord")
def discord_login():
    return RedirectResponse(
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        "&response_type=code"
        "&scope=identify email"
    )


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

    discord_user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_res['access_token']}"},
    ).json()

    discord_id = discord_user["id"]
    email = discord_user.get("email")

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE discord_id=%s", (discord_id,))
        row = cur.fetchone()

        if row:
            uid = row[0]
        else:
            uid = str(uuid.uuid4())
            cur.execute(
                "INSERT INTO users (id, gmail, password_hash, discord_id) VALUES (%s,%s,NULL,%s)",
                (uid, email, discord_id),
            )
            conn.commit()

    token = create_token(uid)
    res = RedirectResponse("/dashboard")
    set_cookie(res, token)
    return res


# User info
@app.get("/api/me")
def me(uid=Depends(auth_user)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT gmail, discord_id FROM users WHERE id=%s", (uid,))
        u = cur.fetchone()

    return {"email": u[0], "discord_id": u[1]}


# Dashboard (server-rendered fallback)
@app.get("/dashboard")
def dashboard(uid=Depends(auth_user)):
    return HTMLResponse("""
    <h1>Dashboard</h1>
    <p>You are logged in.</p>
    <form method="post" action="/api/logout">
        <button>Logout</button>
    </form>
    """)


# License helpers
def ensure_licenses_table(conn):
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            product TEXT,
            duration TEXT,
            used_by TEXT,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        )
        """
    )
    conn.commit()


def redeem(key: str, uid: str):
    if not key or not isinstance(key, str):
        return False, "No license key provided"
    with db() as conn:
        ensure_licenses_table(conn)
        cur = conn.cursor()
        cur.execute("SELECT key, used_by FROM licenses WHERE key=%s", (key,))
        row = cur.fetchone()
        if not row:
            return False, "License key not found."
        if row[1]:
            return False, "License key already used."
        cur.execute("UPDATE licenses SET used_by=%s, used_at=NOW() WHERE key=%s", (uid, key))
        conn.commit()
    return True, "License redeemed!"


@app.post("/api/redeem")
def redeem_license(data: dict = Body(...), uid=Depends(auth_user)):
    key = data.get("key")
    ok, message = redeem(key, uid)
    if ok:
        return JSONResponse({"ok": True, "message": message})
    else:
        return JSONResponse({"ok": False, "message": message}, status_code=400)


# License generation (admin)
@app.post("/api/generate_license")
def generate_license(
    admin_secret: str = Query(...),
    product: str = Query("roblox", regex="^(roblox|cs2)$"),
    duration: str = Query("1week", regex="^(1week|1month|1year|lifetime)$"),
):
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(403, "Forbidden")
    key = f"{product.upper()}-{secrets.token_hex(8).upper()}"
    with db() as conn:
        ensure_licenses_table(conn)
        cur = conn.cursor()
        cur.execute("INSERT INTO licenses (key, product, duration) VALUES (%s, %s, %s)", (key, product, duration))
        conn.commit()
    return {"ok": True, "key": key, "product": product, "duration": duration}

# =====================
# RUN
# =====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)