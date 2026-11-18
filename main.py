from fastapi import FastAPI

app = FastAPI(title="Secure Vault")


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
