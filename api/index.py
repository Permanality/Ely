from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()

@app.get("/")
def root():
    return {"status": "ely online"}

@app.get("/_health")
def health():
    return {"ok": True}

handler = Mangum(app)
