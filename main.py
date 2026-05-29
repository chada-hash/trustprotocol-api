# TrustProtocol API v2.1 — Complete with Admin + Client Management
# Circuit Breaker + Trust Attestation + RSA signatures + PostgreSQL

from fastapi import FastAPI, HTTPException, Depends, Header, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional
import hashlib, json, uuid, os, secrets
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
    version="2.1.0",
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
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://tpuser:tppassword@localhost:5432/trustprotocol")

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def init_db():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Clients table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id SERIAL PRIMARY KEY,
                    client_name VARCHAR(255) NOT NULL,
                    api_key VARCHAR(255) UNIQUE NOT NULL,
                    plan VARCHAR(50) DEFAULT 'starter',
                    active BOOLEAN DEFAULT true,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            # Demo requests table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS demo_requests (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255),
                    email VARCHAR(255) NOT NULL,
                    company VARCHAR(255),
                    message TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            # Migrate env-based keys to DB (idempotent)
            env_keys = json.loads(os.environ.get("API_KEYS_JSON", "{}"))
            for key, info in env_keys.items():
                cur.execute("""
                    INSERT INTO clients (client_name, api_key, plan)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (api_key) DO NOTHING
                """, (info.get('client', key), key, info.get('plan', 'starter')))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"init_db error: {e}")
    finally:
        conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

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
# AUTH — Client
# ============================================================
def get_client(x_api_key: str = Header(...)):
    try:
        conn = get_db()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT client_name as client, plan FROM clients WHERE api_key = %s AND active = true",
                (x_api_key,)
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=401, detail="Cle API invalide")
        return dict(row)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Erreur authentification")

# ============================================================
# AUTH — Admin
# ============================================================
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

def get_admin(x_admin_key: str = Header(...)):
    if not ADMIN_KEY:
        raise HTTPException(status_code=503, detail="Admin non configure")
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Acces admin refuse")
    return True

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

class BudgetUpdateRequest(BaseModel):
    limit_eur: float

class CreateClientRequest(BaseModel):
    client_name: str
    plan: str = "starter"

class DemoRequest(BaseModel):
    name: str
    email: str
    company: Optional[str] = ""
    message: Optional[str] = ""

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
# PUBLIC ENDPOINTS
# ============================================================
@app.get("/")
def root():
    return {"service": "TrustProtocol API", "version": "2.1.0", "status": "operational"}

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

@app.post("/demo")
def request_demo(req: DemoRequest):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO demo_requests (name, email, company, message) VALUES (%s, %s, %s, %s)",
                (req.name, req.email, req.company, req.message)
            )
        conn.commit()
        return {"received": True, "message": "Votre demande a ete enregistree."}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# ============================================================
# CLIENT ENDPOINTS
# ============================================================
@app.post("/intercept", response_model=AttestationResponse)
def intercept_action(req: ActionRequest, client: dict = Depends(get_client)):
    conn = get_db()
    try:
        agent_id = req.agent_id
        timestamp = datetime.now(timezone.utc).isoformat()
        attestation_id = str(uuid.uuid4())

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
            for e in entries:
                e["cost_eur"] = float(e["cost_eur"])
                e["attestation_id"] = str(e["attestation_id"])
                if e.get("timestamp"):
                    e["timestamp"] = e["timestamp"].isoformat()
                if e.get("created_at"):
                    e["created_at"] = e["created_at"].isoformat()
        return {
            "total": len(entries),
            "entries": entries,
            "client": client["client"],
            "plan": client["plan"]
        }
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
            "cost_eur": entry["cost_eur"],
            "blocked": entry["blocked"],
            "hash_sha256": entry["hash_sha256"],
            "chain_height": entry["chain_height"]
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

        return {"chain_valid": valid, "chain_length": len(entries), "storage": "PostgreSQL"}
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

@app.post("/budget/{agent_id}")
def update_budget_limit(agent_id: str, req: BudgetUpdateRequest, client: dict = Depends(get_client)):
    if req.limit_eur < 0:
        raise HTTPException(status_code=400, detail="La limite doit etre positive")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE budgets SET budget_limit = %s, updated_at = NOW() WHERE agent_id = %s",
                (req.limit_eur, agent_id)
            )
            if cur.rowcount == 0:
                cur.execute(
                    "INSERT INTO budgets (agent_id, spent, budget_limit) VALUES (%s, 0, %s)",
                    (agent_id, req.limit_eur)
                )
        conn.commit()
        return {"agent_id": agent_id, "new_limit": req.limit_eur, "updated": True}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
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

# ============================================================
# ADMIN ENDPOINTS
# ============================================================
@app.get("/admin/clients")
def admin_list_clients(admin: bool = Depends(get_admin)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT c.id, c.client_name, c.api_key, c.plan, c.active, c.created_at,
                    COUNT(a.id) as total_attestations,
                    COALESCE(SUM(a.cost_eur), 0) as total_cost,
                    MAX(a.created_at) as last_activity
                FROM clients c
                LEFT JOIN attestations a ON a.client = c.client_name
                GROUP BY c.id
                ORDER BY c.created_at DESC
            """)
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r['total_cost'] = float(r['total_cost'])
            r['total_attestations'] = int(r['total_attestations'])
            key = r['api_key']
            r['api_key_masked'] = key[:6] + '...' + key[-4:] if len(key) > 10 else '***'
            if r.get('created_at'):
                r['created_at'] = r['created_at'].isoformat()
            if r.get('last_activity'):
                r['last_activity'] = r['last_activity'].isoformat()
        return {"clients": rows, "total": len(rows)}
    finally:
        conn.close()

@app.post("/admin/clients")
def admin_create_client(req: CreateClientRequest, admin: bool = Depends(get_admin)):
    api_key = f"tp-{secrets.token_urlsafe(24)}"
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO clients (client_name, api_key, plan) VALUES (%s, %s, %s)",
                (req.client_name, api_key, req.plan)
            )
        conn.commit()
        return {"client_name": req.client_name, "api_key": api_key, "plan": req.plan, "created": True}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.put("/admin/clients/{client_id}/revoke")
def admin_revoke_client(client_id: int, admin: bool = Depends(get_admin)):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE clients SET active = false WHERE id = %s", (client_id,))
        conn.commit()
        return {"client_id": client_id, "revoked": True}
    finally:
        conn.close()

@app.put("/admin/clients/{client_id}/activate")
def admin_activate_client(client_id: int, admin: bool = Depends(get_admin)):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE clients SET active = true WHERE id = %s", (client_id,))
        conn.commit()
        return {"client_id": client_id, "activated": True}
    finally:
        conn.close()

@app.get("/admin/stats")
def admin_stats(admin: bool = Depends(get_admin)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) as total FROM clients WHERE active = true")
            active_clients = int(cur.fetchone()['total'])
            cur.execute("SELECT COUNT(*) as total FROM clients")
            all_clients = int(cur.fetchone()['total'])
            cur.execute("SELECT COUNT(*) as total, COALESCE(SUM(cost_eur), 0) as cost FROM attestations")
            row = cur.fetchone()
            total_attestations = int(row['total'])
            total_cost = float(row['cost'])
            cur.execute("SELECT COUNT(*) as total FROM demo_requests")
            demo_count = int(cur.fetchone()['total'])
        return {
            "clients_actifs": active_clients,
            "clients_total": all_clients,
            "attestations_totales": total_attestations,
            "cout_total_eur": round(total_cost, 4),
            "demandes_demo": demo_count
        }
    finally:
        conn.close()

@app.get("/admin/demo-requests")
def admin_demo_requests(admin: bool = Depends(get_admin)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM demo_requests ORDER BY created_at DESC")
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r.get('created_at'):
                r['created_at'] = r['created_at'].isoformat()
        return {"requests": rows, "total": len(rows)}
    finally:
        conn.close()
