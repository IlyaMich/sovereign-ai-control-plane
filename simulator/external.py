"""Out-of-boundary *simulator*, on a separate network; never forwards to the internet."""
import hashlib
from fastapi import FastAPI
from simulator.main import GenerateRequest

app = FastAPI(title="External Destination Simulator")

@app.post("/generate")
def generate(request: GenerateRequest):
    digest = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()[:16]
    return {"model_id": "external-simulator", "output": f"[EXTERNAL SIMULATOR] SHA-256 prefix: {digest}"}
