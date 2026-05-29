# TrustProtocol API v2.0 — Module 2: PostgreSQL Ledger persistant
# Circuit Breaker + Trust Attestation + RSA signatures + PostgreSQL

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional
import hashlib, json, uuid, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import psycopg2
from psycopg2.extras import RealDictCursor

# ============================================================
# APP
# ============================================================
app = FastAPI(
    title="TrustProtocol API",
    version="2.0.0",
    description="Circuit Breaker + Trust Attestation — PostgreSQL Ledger"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# DATABASE
# ============================================================
import os
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://tpuser:tppassword@localhost:5432/trustprotocol")

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

# ============================================================
# CRYPTO — RSA key pair
# ============================================================
_key_pem = os.getenv("RSA_PRIVATE_KEY")
if _key_pem:
    _PRIVATE_KEY = serialization.load_pem_private_key(
        _key_pem.encode(), password=None, backend=default_backend()
    )
else:
    _PRIVATE_KEY = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
_PUBLIC_KEY_PEM = _PUBLIC_KEY.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

def sign_payload(payload: str) -> str:
    sig = _PRIVATE_KEY.sign(
        payload.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()

def verify_signature(payload: str, signature_b64: str) -> bool:
    try:
        sig = base64.b64decode(signature_b64)
        _PUBLIC_KEY.verify(
            sig,
            payload.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ============================================================
# AUTH
# ============================================================
import json
_raw = os.environ.get("API_KEYS_JSON", "{}")
API_KEYS = json.loads(_raw)


def get_client(x_api_key: str = Header(...)):
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Cle API invalide")
    return API_KEYS[x_api_key]

# ============================================================
# MODELS
# ============================================================
class ActionRequest(BaseModel):
    agent_id: str
    action: str
    cost_eur: float
    payload: Optional[dict] = {}
    budget_limit: Optional[float] = 0.15

class AttestationResponse(BaseModel):
    attestation_id: str
    agent_id: str
    action: str
    cost_eur: float
    timestamp: str
    hash_sha256: str
    prev_hash: str
    signature: str
    blocked: bool
    block_reason: Optional[str] = None
    chain_height: int

# ============================================================
# HELPERS
# ============================================================
def compute_hash(data: dict) -> str:
    payload_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload_str.encode()).hexdigest()

def get_prev_hash(conn) -> str:
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT hash_sha256 FROM attestations ORDER BY chain_height DESC LIMIT 1")
        row = cur.fetchone()
        return row["hash_sha256"] if row else "0" * 64

def get_chain_height(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM attestations")
        return cur.fetchone()[0]

def get_budget(conn, agent_id: str, limit: float) -> dict:
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM budgets WHERE agent_id = %s", (agent_id,))
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO budgets (agent_id, spent, budget_limit) VALUES (%s, 0, %s) RETURNING *",
                (agent_id, limit)
            )
            conn.commit()
            return {"agent_id": agent_id, "spent": 0.0, "budget_limit": limit}
        return dict(row)

# ============================================================
# ENDPOINTS
# ============================================================
@app.get("/")
def root():
    return {
        "service": "TrustProtocol API",
        "version": "2.0.0",
        "status": "operational",
        "storage": "PostgreSQL"
    }

@app.get("/health")
def health():
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM attestations")
            count = cur.fetchone()[0]
        conn.close()
        return {"status": "ok", "ledger_size": count, "storage": "PostgreSQL"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")

@app.get("/pubkey")
def public_key():
    return {"public_key_pem": _PUBLIC_KEY_PEM}

@app.post("/intercept", response_model=AttestationResponse)
def intercept_action(req: ActionRequest, client: dict = Depends(get_client)):
    conn = get_db()
    try:
        agent_id = req.agent_id
        timestamp = datetime.now(timezone.utc).isoformat()
        attestation_id = str(uuid.uuid4())

        # Circuit Breaker
        budget = get_budget(conn, agent_id, req.budget_limit)
        blocked = False
        block_reason = None
        spent = float(budget["spent"])

        if spent + req.cost_eur > float(budget["budget_limit"]):
            blocked = True
            block_reason = (
                f"Budget depasse: {spent:.4f}EUR depense + "
                f"{req.cost_eur:.4f}EUR demande > limite {budget['budget_limit']:.2f}EUR"
            )
        else:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE budgets SET spent = spent + %s, updated_at = NOW() WHERE agent_id = %s",
                    (req.cost_eur, agent_id)
                )

        # Trust Attestation
        prev_hash = get_prev_hash(conn)
        chain_height = get_chain_height(conn) + 1

        attestation_data = {
            "attestation_id": attestation_id,
            "agent_id": agent_id,
            "client": client["client"],
            "action": req.action,
            "cost_eur": req.cost_eur,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
            "blocked": blocked,
            "block_reason": block_reason,
            "chain_height": chain_height,
            "payload_hash": hashlib.sha256(
                json.dumps(req.payload, sort_keys=True).encode()
            ).hexdigest()
        }

        hash_sha256 = compute_hash(attestation_data)
        signature = sign_payload(json.dumps(attestation_data, sort_keys=True))

        # Append to PostgreSQL ledger (append-only)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO attestations 
                (attestation_id, agent_id, client, action, cost_eur, timestamp,
                 hash_sha256, prev_hash, signature, blocked, block_reason, chain_height, payload_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                attestation_id, agent_id, client["client"], req.action,
                req.cost_eur, timestamp, hash_sha256, prev_hash,
                signature, blocked, block_reason, chain_height,
                attestation_data["payload_hash"]
            ))
        conn.commit()

        return AttestationResponse(
            attestation_id=attestation_id,
            agent_id=agent_id,
            action=req.action,
            cost_eur=req.cost_eur,
            timestamp=timestamp,
            hash_sha256=hash_sha256,
            prev_hash=prev_hash,
            signature=signature,
            blocked=blocked,
            block_reason=block_reason,
            chain_height=chain_height
        )

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/ledger")
def get_ledger(agent_id: Optional[str] = None, client: dict = Depends(get_client)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if agent_id:
                cur.execute(
                    "SELECT * FROM attestations WHERE agent_id = %s ORDER BY chain_height ASC",
                    (agent_id,)
                )
            else:
                cur.execute("SELECT * FROM attestations ORDER BY chain_height ASC")
            entries = [dict(r) for r in cur.fetchall()]
            # Convert non-serializable types
            for e in entries:
                e["cost_eur"] = float(e["cost_eur"])
                e["attestation_id"] = str(e["attestation_id"])
                if e.get("timestamp"):
                    e["timestamp"] = e["timestamp"].isoformat()
                if e.get("created_at"):
                    e["created_at"] = e["created_at"].isoformat()
        return {"total": len(entries), "entries": entries}
    finally:
        conn.close()

@app.get("/verify/{attestation_id}")
def verify_attestation(attestation_id: str, client: dict = Depends(get_client)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM attestations WHERE attestation_id = %s",
                (attestation_id,)
            )
            entry = cur.fetchone()
        if not entry:
            raise HTTPException(status_code=404, detail="Attestation introuvable")

        entry = dict(entry)
        entry["cost_eur"] = float(entry["cost_eur"])
        entry["attestation_id"] = str(entry["attestation_id"])
        if entry.get("timestamp"):
            entry["timestamp"] = entry["timestamp"].isoformat()

        data_for_hash = {k: v for k, v in entry.items()
                         if k not in ["hash_sha256", "signature", "id", "created_at"]}
        expected_hash = compute_hash(data_for_hash)
        hash_valid = expected_hash == entry["hash_sha256"]
        payload_str = json.dumps(data_for_hash, sort_keys=True)
        sig_valid = verify_signature(payload_str, entry["signature"])

        return {
            "attestation_id": attestation_id,
            "hash_valid": hash_valid,
            "signature_valid": sig_valid,
            "integrity": hash_valid and sig_valid,
            "timestamp": entry["timestamp"],
            "agent_id": entry["agent_id"],
            "action": entry["action"],
            "blocked": entry["blocked"]
        }
    finally:
        conn.close()

@app.get("/verify-chain")
def verify_chain(client: dict = Depends(get_client)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT hash_sha256, prev_hash, chain_height FROM attestations ORDER BY chain_height ASC"
            )
            entries = cur.fetchall()

        valid = True
        for i in range(1, len(entries)):
            if entries[i]["prev_hash"] != entries[i-1]["hash_sha256"]:
                valid = False
                break

        return {
            "chain_valid": valid,
            "chain_length": len(entries),
            "storage": "PostgreSQL"
        }
    finally:
        conn.close()

@app.get("/budget/{agent_id}")
def get_budget_status(agent_id: str, client: dict = Depends(get_client)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM budgets WHERE agent_id = %s", (agent_id,))
            row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Agent introuvable")
        spent = float(row["spent"])
        limit = float(row["budget_limit"])
        return {
            "agent_id": agent_id,
            "spent": round(spent, 6),
            "limit": limit,
            "remaining": round(limit - spent, 6),
            "blocked": spent >= limit
        }
    finally:
        conn.close()

@app.delete("/budget/{agent_id}/reset")
def reset_budget(agent_id: str, client: dict = Depends(get_client)):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE budgets SET spent = 0, updated_at = NOW() WHERE agent_id = %s",
                (agent_id,)
            )
        conn.commit()
        return {"agent_id": agent_id, "budget_reset": True}
    finally:
        conn.close()
