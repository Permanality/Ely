from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()

@app.get("/_health")
def health():
    return {"ok": True}

handler = Mangum(app)
