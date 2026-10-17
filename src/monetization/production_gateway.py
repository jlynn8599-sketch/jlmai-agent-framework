#!/usr/bin/env python3
"""
JLMAI Revenue Gateway — CORRECTED version.

Fixes vs. the pasted draft:
1. NO hardcoded API key. The old draft had a default "live" key baked in,
   so the service would run with a publicly-known key if the env var
   was missing. This version REFUSES to start without JLMAI_API_KEY.
2. NO fake settlement. The old draft logged "Routing 0.0005 ETH
   micropayment" and returned "micropayment_settled_eth" without ever
   building, signing, or sending a transaction — no payment happened.
   This version honestly reports "settlement": "not_performed".
   Real settlement needs a signer + a signed on-chain transfer and is
   NOT in this endpoint.
3. NO fake metrics. The old draft hardcoded the dispatched-tasks
   counter to 5000. This version uses a real in-memory counter that
   starts at 0 and increments per dispatch. (It resets on restart —
   it is not durable accounting.)
4. NETWORK MATCHES CONFIG: defaults to Base Sepolia testnet
   (chain 84532), and the app refuses to start if the RPC is on a
   different chain than configured — so a mainnet/testnet mix-up
   fails loudly instead of silently.
5. No key material is ever logged. The old draft logged the first
   10 characters of attempted keys.

Do NOT run the sudo cp / systemctl restart commands until you have
reviewed this file and set the required env vars:
  JLMAI_TREASURY_WALLET (required), JLMAI_API_KEY (required),
  JLMAI_RPC_URL (optional), JLMAI_CHAIN_ID (optional),
  JLMAI_NETWORK_NAME (optional).
"""

import hmac
import logging
import os
import time

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from web3 import Web3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("JLMAI-ProdGateway")

app = FastAPI(title="JLMAI Revenue Gateway", version="2.0.0")

# --- Configuration: secrets and network come from the environment only ---
RPC_URL = os.getenv("JLMAI_RPC_URL", "https://sepolia.base.org")
CHAIN_ID = int(os.getenv("JLMAI_CHAIN_ID", "84532"))
NETWORK_NAME = os.getenv("JLMAI_NETWORK_NAME", "base-sepolia")

TREASURY_WALLET_RAW = os.getenv("JLMAI_TREASURY_WALLET", "")
if not TREASURY_WALLET_RAW:
    raise RuntimeError("JLMAI_TREASURY_WALLET is not set. Refusing to start.")
TREASURY_WALLET = Web3.to_checksum_address(TREASURY_WALLET_RAW)

API_KEY_SECRET = os.getenv("JLMAI_API_KEY", "")
if not API_KEY_SECRET:
    raise RuntimeError("JLMAI_API_KEY is not set. Refusing to start without an API key.")

w3 = Web3(Web3.HTTPProvider(RPC_URL))

# Fail fast if the RPC is on a different chain than configured.
# This catches mainnet/testnet mix-ups before serving traffic.
try:
    connected_chain = w3.eth.chain_id
except Exception as err:
    raise RuntimeError(f"Could not reach RPC at {RPC_URL}: {err}")
if connected_chain != CHAIN_ID:
    raise RuntimeError(
        f"Chain mismatch: configured CHAIN_ID={CHAIN_ID} but RPC {RPC_URL} "
        f"reports chain {connected_chain}. Refusing to start."
    )

# Real counters (in-memory only; reset on restart).
tasks_dispatched_success = 0


class DispatchRequest(BaseModel):
    task_id: str
    task_type: str
    payload: dict


def verify_api_key(x_api_key: str = Header(...)):
    # Constant-time comparison; never log key material.
    if not hmac.compare_digest(x_api_key, API_KEY_SECRET):
        logger.warning("[SECURITY] Unauthorized dispatch attempt (key not logged).")
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key


@app.post("/api/v1/dispatch")
async def execute_task_dispatch(req: DispatchRequest, api_key: str = Depends(verify_api_key)):
    global tasks_dispatched_success
    start_time = time.time()

    # HONEST: this endpoint records a dispatch. It performs NO on-chain
    # settlement — no transaction is built, signed, or sent here.
    logger.info(f"[DISPATCH] Processing task {req.task_id} of type {req.task_type}")
    logger.info("[SETTLEMENT] No on-chain settlement performed by this endpoint.")
    tasks_dispatched_success += 1

    execution_latency = (time.time() - start_time) * 1000

    return {
        "status": "success",
        "task_id": req.task_id,
        "network": NETWORK_NAME,
        "chain_id": CHAIN_ID,
        "treasury_vault": TREASURY_WALLET,
        "settlement": "not_performed",
        "latency_ms": round(execution_latency, 2),
        "timestamp": int(time.time()),
    }


@app.get("/metrics")
async def metrics():
    vault_balance_wei = w3.eth.get_balance(TREASURY_WALLET)
    metrics_output = f"""
# HELP jlmai_treasury_balance_wei Live Treasury Vault Balance in Wei
# TYPE jlmai_treasury_balance_wei gauge
jlmai_treasury_balance_wei{{vault="{TREASURY_WALLET}",network="{NETWORK_NAME}"}} {vault_balance_wei}
# HELP jlmai_tasks_dispatched_total Total dispatched agent tasks
# TYPE jlmai_tasks_dispatched_total counter
jlmai_tasks_dispatched_total{{status="success"}} {tasks_dispatched_success}
"""
    return metrics_output.strip()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
