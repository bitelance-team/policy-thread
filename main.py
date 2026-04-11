from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import httpx
import os
import re
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

def get_client():
    return httpx.Client(base_url=f"{SUPABASE_URL}/rest/v1", headers=HEADERS)

app = FastAPI(
    title="PolicyThread",
    description="Define what your AI must always do and never do. PolicyThread watches every live interaction and tells you when it breaks the rules.",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    condition: Dict[str, Any]
    severity: str
    on_violation: Optional[str] = "alert"

class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    severity: Optional[str] = None
    on_violation: Optional[str] = None

class InteractionSubmit(BaseModel):
    user_input: str
    ai_output: str
    session_id: Optional[str] = None
    model_used: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}

class BatchSubmit(BaseModel):
    interactions: List[InteractionSubmit]

# --- Evaluation Engine (Layer 1 — Deterministic) ---

def evaluate_condition(condition: dict, user_input: str, ai_output: str) -> tuple[bool, str]:
    ctype = condition.get("type")
    text = ai_output.lower()

    if ctype == "keyword_exclude":
        keywords = [k.lower() for k in condition.get("keywords", [])]
        for kw in keywords:
            if kw in text:
                return False, f"Output contains excluded keyword: '{kw}'"
        return True, ""

    if ctype == "keyword_require":
        keywords = [k.lower() for k in condition.get("keywords", [])]
        for kw in keywords:
            if kw not in text:
                return False, f"Output missing required keyword: '{kw}'"
        return True, ""

    if ctype == "regex_exclude":
        pattern = condition.get("pattern", "")
        if re.search(pattern, ai_output, re.IGNORECASE):
            return False, f"Output matched excluded pattern: '{pattern}'"
        return True, ""

    if ctype == "regex_require":
        pattern = condition.get("pattern", "")
        if not re.search(pattern, ai_output, re.IGNORECASE):
            return False, f"Output did not match required pattern: '{pattern}'"
        return True, ""

    if ctype == "max_length":
        max_len = condition.get("max_length", 1000)
        if len(ai_output) > max_len:
            return False, f"Output length {len(ai_output)} exceeds maximum {max_len}"
        return True, ""

    if ctype == "input_keyword_exclude":
        keywords = [k.lower() for k in condition.get("keywords", [])]
        input_text = user_input.lower()
        for kw in keywords:
            if kw in input_text:
                return False, f"User input contains excluded keyword: '{kw}'"
        return True, ""

    return True, ""

def run_evaluation(interaction_id: str, user_input: str, ai_output: str) -> dict:
    with get_client() as client:
        r = client.get("/policies", params={"active": "eq.true", "select": "*"})
        policies = r.json()

    results = []
    all_passed = True

    for policy in policies:
        condition = policy.get("condition", {})
        passed, reason = evaluate_condition(condition, user_input, ai_output)

        with get_client() as client:
            client.post("/evaluations", json={
                "interaction_id": interaction_id,
                "policy_id": policy["id"],
                "passed": passed,
                "violation_reason": reason if not passed else None
            })

        if not passed:
            all_passed = False
            with get_client() as client:
                client.post("/violations", json={
                    "interaction_id": interaction_id,
                    "policy_id": policy["id"],
                    "policy_name": policy["name"],
                    "severity": policy["severity"],
                    "violation_reason": reason,
                    "on_violation": policy["on_violation"]
                })

            results.append({
                "policy_id": policy["id"],
                "policy_name": policy["name"],
                "severity": policy["severity"],
                "on_violation": policy["on_violation"],
                "reason": reason
            })

    return {
        "passed": all_passed,
        "violations": results
    }

# --- Routes ---

@app.get("/")
def root():
    return {
        "tool": "PolicyThread",
        "version": "0.1.0",
        "status": "running",
        "description": "Define what your AI must always do and never do. PolicyThread watches every live interaction and tells you when it breaks the rules."
    }

@app.get("/health")
def health():
    try:
        with get_client() as client:
            r = client.get("/policies", params={"limit": "1"})
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}

# Policies

@app.post("/policies")
def create_policy(data: PolicyCreate):
    if data.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical, high, medium, or low")
    if data.on_violation not in ("block", "alert", "log_only"):
        raise HTTPException(status_code=400, detail="on_violation must be block, alert, or log_only")
    with get_client() as client:
        r = client.post("/policies", json={
            "name": data.name,
            "description": data.description,
            "condition": data.condition,
            "severity": data.severity,
            "on_violation": data.on_violation,
            "active": True,
            "version": 1
        })
    return r.json()[0]

@app.get("/policies")
def list_policies():
    with get_client() as client:
        r = client.get("/policies", params={"active": "eq.true", "order": "created_at.desc"})
    return r.json()

@app.get("/policies/{policy_id}")
def get_policy(policy_id: str):
    with get_client() as client:
        r = client.get("/policies", params={"id": f"eq.{policy_id}"})
    data = r.json()
    if not data:
        raise HTTPException(status_code=404, detail="Policy not found")
    return data[0]

@app.put("/policies/{policy_id}")
def update_policy(policy_id: str, data: PolicyUpdate):
    with get_client() as client:
        r = client.get("/policies", params={"id": f"eq.{policy_id}"})
    existing = r.json()
    if not existing:
        raise HTTPException(status_code=404, detail="Policy not found")
    current = existing[0]

    # Archive current version
    with get_client() as client:
        client.post("/policy_history", json={
            "policy_id": policy_id,
            "name": current["name"],
            "description": current["description"],
            "condition": current["condition"],
            "severity": current["severity"],
            "on_violation": current["on_violation"],
            "version": current["version"]
        })

    updates = {k: v for k, v in data.dict().items() if v is not None}
    updates["version"] = current["version"] + 1
    updates["updated_at"] = datetime.utcnow().isoformat()

    with get_client() as client:
        r = client.patch(f"/policies?id=eq.{policy_id}", json=updates)
    return r.json()[0]

@app.delete("/policies/{policy_id}")
def deactivate_policy(policy_id: str):
    with get_client() as client:
        r = client.patch(f"/policies?id=eq.{policy_id}", json={"active": False})
    if not r.json():
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"deactivated": True, "policy_id": policy_id}

@app.get("/policies/{policy_id}/history")
def get_policy_history(policy_id: str):
    with get_client() as client:
        r = client.get("/policy_history", params={
            "policy_id": f"eq.{policy_id}",
            "order": "version.desc"
        })
    return r.json()

# Evaluate

@app.post("/evaluate")
def evaluate_interaction(data: InteractionSubmit):
    with get_client() as client:
        r = client.post("/interactions", json={
            "user_input": data.user_input,
            "ai_output": data.ai_output,
            "session_id": data.session_id,
            "model_used": data.model_used,
            "metadata": data.metadata
        })
    interaction = r.json()[0]
    interaction_id = interaction["id"]

    result = run_evaluation(interaction_id, data.user_input, data.ai_output)

    return {
        "interaction_id": interaction_id,
        "passed": result["passed"],
        "violations": result["violations"]
    }

@app.post("/evaluate/batch")
def evaluate_batch(data: BatchSubmit):
    results = []
    for item in data.interactions:
        with get_client() as client:
            r = client.post("/interactions", json={
                "user_input": item.user_input,
                "ai_output": item.ai_output,
                "session_id": item.session_id,
                "model_used": item.model_used,
                "metadata": item.metadata
            })
        interaction = r.json()[0]
        interaction_id = interaction["id"]
        result = run_evaluation(interaction_id, item.user_input, item.ai_output)
        results.append({
            "interaction_id": interaction_id,
            "passed": result["passed"],
            "violations": result["violations"]
        })
    return {"results": results, "total": len(results)}

# Violations

@app.get("/violations")
def list_violations(severity: Optional[str] = None, policy_id: Optional[str] = None, resolved: Optional[bool] = None):
    params = {"order": "created_at.desc"}
    filters = []
    if severity:
        filters.append(f"severity=eq.{severity}")
    if policy_id:
        filters.append(f"policy_id=eq.{policy_id}")
    if resolved is not None:
        filters.append(f"resolved=eq.{'true' if resolved else 'false'}")
    with get_client() as client:
        r = client.get("/violations", params={**params, **{f.split("=")[0]: f.split("=")[1] for f in filters}})
    return r.json()

@app.get("/violations/{violation_id}")
def get_violation(violation_id: str):
    with get_client() as client:
        r = client.get("/violations", params={"id": f"eq.{violation_id}"})
    data = r.json()
    if not data:
        raise HTTPException(status_code=404, detail="Violation not found")
    return data[0]

@app.patch("/violations/{violation_id}/resolve")
def resolve_violation(violation_id: str):
    with get_client() as client:
        r = client.patch(f"/violations?id=eq.{violation_id}", json={
            "resolved": True,
            "resolved_at": datetime.utcnow().isoformat()
        })
    if not r.json():
        raise HTTPException(status_code=404, detail="Violation not found")
    return r.json()[0]

# Interactions

@app.get("/interactions")
def list_interactions():
    with get_client() as client:
        r = client.get("/interactions", params={"order": "evaluated_at.desc", "limit": "50"})
    return r.json()

@app.get("/interactions/{interaction_id}")
def get_interaction(interaction_id: str):
    with get_client() as client:
        r = client.get("/interactions", params={"id": f"eq.{interaction_id}"})
    data = r.json()
    if not data:
        raise HTTPException(status_code=404, detail="Interaction not found")
    interaction = data[0]
    with get_client() as client:
        evals = client.get("/evaluations", params={"interaction_id": f"eq.{interaction_id}"})
        viols = client.get("/violations", params={"interaction_id": f"eq.{interaction_id}"})
    interaction["evaluations"] = evals.json()
    interaction["violations"] = viols.json()
    return interaction

# Dashboard

@app.get("/dashboard/stats")
def dashboard_stats():
    with get_client() as client:
        interactions = client.get("/interactions", params={"select": "id"})
        violations = client.get("/violations", params={"select": "id,severity,resolved"})
        policies = client.get("/policies", params={"active": "eq.true", "select": "id"})

    total_interactions = len(interactions.json())
    all_violations = violations.json()
    total_violations = len(all_violations)
    unresolved = len([v for v in all_violations if not v["resolved"]])
    critical = len([v for v in all_violations if v["severity"] == "critical"])
    pass_rate = round(100 * (total_interactions - total_violations) / total_interactions, 2) if total_interactions > 0 else 100.0

    return {
        "total_interactions": total_interactions,
        "total_violations": total_violations,
        "unresolved_violations": unresolved,
        "critical_violations": critical,
        "active_policies": len(policies.json()),
        "pass_rate": pass_rate
    }