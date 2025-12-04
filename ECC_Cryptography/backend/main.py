from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from logging_config import logger
from attacks.replay import run_replay_attack
from attacks.weak_k import run_weak_k_attack
from attacks.forgery import run_forgery_attack
from attacks.mitm import run_mitm_attack
from attacks.malleability import run_malleability_attack

app = FastAPI()

# Allow your React app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store connected UI clients
connected_clients = []


# ------------ REAL‑TIME LOG STREAMING ------------
@app.websocket("/ws/logs")
async def websocket_logs(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    try:
        while True:
            pass  # idle; messages are pushed externally
    except:
        connected_clients.remove(ws)


# Helper: push logs to clients
async def broadcast(message: str):
    for ws in connected_clients:
        await ws.send_text(message)


# Override logger to also push to WebSocket
def push_log(msg: str):
    logger.info(msg)
    import asyncio
    asyncio.create_task(broadcast(msg))


# ------------ API ROUTES ------------
@app.get("/attack/replay")
async def replay():
    push_log("Running replay attack…")
    result = run_replay_attack(push_log)
    return {"result": result}


@app.get("/attack/weak-k")
async def weak_k():
    push_log("Running weak‑k attack…")
    result = run_weak_k_attack(push_log)
    return {"result": result}


@app.get("/attack/forgery")
async def forgery():
    push_log("Running signature forgery attempt…")
    result = run_forgery_attack(push_log)
    return {"result": result}


@app.get("/attack/mitm")
async def mitm():
    push_log("Running MITM tampering attack…")
    result = run_mitm_attack(push_log)
    return {"result": result}


@app.get("/attack/malleability")
async def malleability():
    push_log("Running signature malleability demo…")
    result = run_malleability_attack(push_log)
    return {"result": result}
