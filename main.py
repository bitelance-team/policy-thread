from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import httpx
import os
import re
import csv
import io
import json
import hashlib
import anthropic
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
CHAINTHREAD_URL = os.getenv("CHAINTHREAD_URL", "https://chain-thread.onrender.com")
TESTTHREAD_URL = os.getenv("TESTTHREAD_URL", "https://test-thread-production.up.railway.app")

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
    version="1.3.0"
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

class SessionEvaluate(BaseModel):
    session_id: str
    user_input: str
    ai_output: str
    model_used: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}

class BatchSubmit(BaseModel):
    interactions: List[InteractionSubmit]

class WebhookCreate(BaseModel):
    name: str
    url: str
    on_critical: Optional[bool] = True
    on_high: Optional[bool] = True
    on_medium: Optional[bool] = False
    on_low: Optional[bool] = False

class AlertConfigCreate(BaseModel):
    policy_id: str
    min_pass_rate: Optional[float] = 80.0
    webhook_url: Optional[str] = None

class EscalationRuleCreate(BaseModel):
    policy_id: str
    trigger_count: Optional[int] = 3
    within_minutes: Optional[int] = 10
    escalate_to: Optional[str] = "critical"
    webhook_url: Optional[str] = None

class SimulateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    condition: Dict[str, Any]
    severity: str
    on_violation: Optional[str] = "alert"
    start_date: Optional[str] = None
    end_date: Optional[str] = None

class ConflictCheckRequest(BaseModel):
    condition: Dict[str, Any]
    name: Optional[str] = "New Policy"

class PolicyEnvelopeRequest(BaseModel):
    chain_id: str
    envelope_id: str
    sender_id: str
    receiver_id: str
    session_id: Optional[str] = None

# --- Webhook Fire ---

def fire_webhooks(violation: dict):
    severity = violation.get("severity", "low")
    severity_map = {
        "critical": "on_critical",
        "high": "on_high",
        "medium": "on_medium",
        "low": "on_low"
    }
    field = severity_map.get(severity, "on_low")
    with get_client() as client:
        r = client.get("/webhooks", params={"active": "eq.true", field: "eq.true"})
        webhooks = r.json()
    payload = {
        "event": "policy.violation",
        "policy_name": violation.get("policy_name"),
        "severity": severity,
        "violation_reason": violation.get("violation_reason"),
        "interaction_id": violation.get("interaction_id"),
        "timestamp": datetime.utcnow().isoformat()
    }
    for webhook in webhooks:
        try:
            with httpx.Client() as client:
                client.post(webhook["url"], json=payload, timeout=5)
        except Exception:
            pass

def fire_escalation_webhook(url: str, policy_id: str, policy_name: str, trigger_count: int, within_minutes: int):
    try:
        with httpx.Client() as client:
            client.post(url, json={
                "event": "policy.escalated",
                "policy_id": policy_id,
                "policy_name": policy_name,
                "message": f"Policy escalated to critical: fired {trigger_count} times in {within_minutes} minutes",
                "timestamp": datetime.utcnow().isoformat()
            }, timeout=5)
    except Exception:
        pass

# --- Escalation Check (v0.8.0) ---

def check_escalation(policy_id: str, policy_name: str):
    with get_client() as client:
        rules = client.get("/escalation_rules", params={
            "policy_id": f"eq.{policy_id}",
            "active": "eq.true"
        }).json()

    for rule in rules:
        within_minutes = rule.get("within_minutes", 10)
        trigger_count = rule.get("trigger_count", 3)
        since = (datetime.utcnow() - timedelta(minutes=within_minutes)).isoformat()

        with get_client() as client:
            recent = client.get("/violations", params={
                "policy_id": f"eq.{policy_id}",
                "created_at": f"gte.{since}",
                "select": "id"
            }).json()

        if len(recent) >= trigger_count:
            with get_client() as client:
                client.patch(f"/policies?id=eq.{policy_id}", json={
                    "severity": rule.get("escalate_to", "critical"),
                    "updated_at": datetime.utcnow().isoformat()
                })
            if rule.get("webhook_url"):
                fire_escalation_webhook(
                    rule["webhook_url"], policy_id, policy_name,
                    trigger_count, within_minutes
                )

# --- Attestation (v0.9.0) ---

def create_attestation(interaction_id: str, policy_id: str, policy_name: str, passed: bool):
    with get_client() as client:
        prev = client.get("/policy_attestations", params={
            "policy_id": f"eq.{policy_id}",
            "order": "created_at.desc",
            "limit": "1"
        }).json()

    previous_hash = prev[0]["chain_hash"] if prev else "GENESIS"
    now = datetime.utcnow().isoformat()

    eval_data = json.dumps({
        "interaction_id": interaction_id,
        "policy_id": policy_id,
        "policy_name": policy_name,
        "passed": passed,
        "timestamp": now
    }, sort_keys=True)

    evaluation_hash = hashlib.sha256(eval_data.encode()).hexdigest()
    chain_input = f"{previous_hash}:{evaluation_hash}"
    chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()

    with get_client() as client:
        client.post("/policy_attestations", json={
            "interaction_id": interaction_id,
            "policy_id": policy_id,
            "policy_name": policy_name,
            "passed": passed,
            "evaluation_hash": evaluation_hash,
            "previous_hash": previous_hash,
            "chain_hash": chain_hash
        })

# --- Evaluation Engine ---

def evaluate_deterministic(condition: dict, user_input: str, ai_output: str) -> tuple[bool, str]:
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

def evaluate_semantic(condition: dict, user_input: str, ai_output: str, policy_description: str, context: Optional[List[dict]] = None) -> tuple[bool, str]:
    if not ANTHROPIC_API_KEY:
        return True, "Semantic evaluation skipped — no API key configured"

    rule = condition.get("rule", policy_description)
    context_block = ""
    if context:
        context_block = "\n\nPrior conversation context:\n"
        for c in context[-5:]:
            context_block += f"User: {c.get('user_input', '')}\nAI: {c.get('ai_output', '')}\n"

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=200,
            messages=[{
                "role": "user",
                "content": f"""You are a compliance evaluator. Evaluate whether the following AI interaction violates the given policy rule.

Policy rule: {rule}{context_block}

User input: {user_input}

AI output: {ai_output}

Respond with ONLY a JSON object in this exact format:
{{"passed": true, "reason": ""}}
or
{{"passed": false, "reason": "brief explanation of the violation"}}

No other text. Just the JSON."""
            }]
        )
        response_text = message.content[0].text.strip()
        result = json.loads(response_text)
        return result.get("passed", True), result.get("reason", "")
    except Exception as e:
        return True, f"Semantic evaluation error: {str(e)}"

def run_evaluation(interaction_id: str, user_input: str, ai_output: str, context: Optional[List[dict]] = None) -> dict:
    with get_client() as client:
        r = client.get("/policies", params={"active": "eq.true", "select": "*"})
        policies = r.json()

    results = []
    all_passed = True

    for policy in policies:
        condition = policy.get("condition", {})
        ctype = condition.get("type", "")

        if ctype == "semantic":
            passed, reason = evaluate_semantic(condition, user_input, ai_output, policy.get("description", ""), context)
        else:
            passed, reason = evaluate_deterministic(condition, user_input, ai_output)

        with get_client() as client:
            client.post("/evaluations", json={
                "interaction_id": interaction_id,
                "policy_id": policy["id"],
                "passed": passed,
                "violation_reason": reason if not passed else None
            })

        create_attestation(interaction_id, policy["id"], policy["name"], passed)

        if not passed:
            all_passed = False
            with get_client() as client:
                vr = client.post("/violations", json={
                    "interaction_id": interaction_id,
                    "policy_id": policy["id"],
                    "policy_name": policy["name"],
                    "severity": policy["severity"],
                    "violation_reason": reason,
                    "on_violation": policy["on_violation"]
                })
            violation_record = vr.json()[0] if vr.json() else {}
            fire_webhooks(violation_record)
            check_escalation(policy["id"], policy["name"])

            results.append({
                "policy_id": policy["id"],
                "policy_name": policy["name"],
                "severity": policy["severity"],
                "on_violation": policy["on_violation"],
                "reason": reason
            })

    return {"passed": all_passed, "violations": results}

# --- Conflict Detection (v1.1.0) ---

def detect_conflicts(new_condition: dict, new_name: str, exclude_id: Optional[str] = None) -> List[dict]:
    with get_client() as client:
        policies = client.get("/policies", params={"active": "eq.true", "select": "*"}).json()

    conflicts = []
    new_type = new_condition.get("type", "")
    new_keywords = set(k.lower() for k in new_condition.get("keywords", []))

    for policy in policies:
        if exclude_id and policy["id"] == exclude_id:
            continue

        existing_condition = policy.get("condition", {})
        existing_type = existing_condition.get("type", "")
        existing_keywords = set(k.lower() for k in existing_condition.get("keywords", []))

        conflict = None

        if new_type == "keyword_require" and existing_type == "keyword_exclude":
            overlap = new_keywords & existing_keywords
            if overlap:
                conflict = {
                    "conflicting_policy_id": policy["id"],
                    "conflicting_policy_name": policy["name"],
                    "conflict_type": "require_exclude_overlap",
                    "explanation": f"'{new_name}' requires keywords {overlap} but '{policy['name']}' excludes them. Both cannot be satisfied simultaneously."
                }

        elif new_type == "keyword_exclude" and existing_type == "keyword_require":
            overlap = new_keywords & existing_keywords
            if overlap:
                conflict = {
                    "conflicting_policy_id": policy["id"],
                    "conflicting_policy_name": policy["name"],
                    "conflict_type": "exclude_require_overlap",
                    "explanation": f"'{new_name}' excludes keywords {overlap} but '{policy['name']}' requires them. Both cannot be satisfied simultaneously."
                }

        elif new_type == "max_length" and existing_type == "keyword_require":
            max_len = new_condition.get("max_length", 1000)
            required = existing_condition.get("keywords", [])
            if max_len < 50 and required:
                conflict = {
                    "conflicting_policy_id": policy["id"],
                    "conflicting_policy_name": policy["name"],
                    "conflict_type": "length_keyword_tension",
                    "explanation": f"'{new_name}' restricts output to {max_len} characters but '{policy['name']}' requires specific keywords that may need more space."
                }

        elif new_type == existing_type == "keyword_exclude":
            overlap = new_keywords & existing_keywords
            if overlap:
                conflict = {
                    "conflicting_policy_id": policy["id"],
                    "conflicting_policy_name": policy["name"],
                    "conflict_type": "duplicate_exclusion",
                    "explanation": f"'{new_name}' and '{policy['name']}' both exclude keywords {overlap}. Consider consolidating into one policy."
                }

        if conflict:
            conflicts.append(conflict)

    return conflicts

# --- Routes ---

@app.get("/")
def root():
    return {
        "tool": "PolicyThread",
        "version": "1.3.0",
        "status": "running",
        "description": "Define what your AI must always do and never do. PolicyThread watches every live interaction and tells you when it breaks the rules."
    }

@app.get("/health")
def health():
    try:
        with get_client() as client:
            client.get("/policies", params={"limit": "1"})
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

    conflicts = detect_conflicts(data.condition, data.name)

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
    policy = r.json()[0]
    policy["conflicts_detected"] = conflicts
    return policy

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

    conflicts = []
    if "condition" in updates:
        conflicts = detect_conflicts(updates["condition"], current["name"], exclude_id=policy_id)

    with get_client() as client:
        r = client.patch(f"/policies?id=eq.{policy_id}", json=updates)
    policy = r.json()[0]
    policy["conflicts_detected"] = conflicts
    return policy

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

@app.post("/policies/simulate")
def simulate_policy(data: SimulateRequest):
    params = {"order": "evaluated_at.desc"}
    if data.start_date:
        params["evaluated_at"] = f"gte.{data.start_date}"
    if data.end_date:
        params["evaluated_at"] = f"lte.{data.end_date}T23:59:59"

    with get_client() as client:
        interactions = client.get("/interactions", params=params).json()

    would_violate = []
    would_pass = []

    for interaction in interactions:
        ctype = data.condition.get("type", "")
        if ctype == "semantic":
            passed, reason = evaluate_semantic(
                data.condition,
                interaction.get("user_input", ""),
                interaction.get("ai_output", ""),
                data.description or ""
            )
        else:
            passed, reason = evaluate_deterministic(
                data.condition,
                interaction.get("user_input", ""),
                interaction.get("ai_output", "")
            )

        entry = {
            "interaction_id": interaction["id"],
            "session_id": interaction.get("session_id"),
            "evaluated_at": interaction.get("evaluated_at"),
            "user_input_preview": interaction.get("user_input", "")[:100],
            "ai_output_preview": interaction.get("ai_output", "")[:100],
        }

        if not passed:
            entry["violation_reason"] = reason
            would_violate.append(entry)
        else:
            would_pass.append(entry)

    total = len(interactions)
    return {
        "simulation_only": True,
        "nothing_logged": True,
        "policy_name": data.name,
        "severity": data.severity,
        "total_interactions_tested": total,
        "would_violate_count": len(would_violate),
        "would_pass_count": len(would_pass),
        "violation_rate": round(100 * len(would_violate) / total, 2) if total > 0 else 0.0,
        "would_violate": would_violate,
        "would_pass": would_pass
    }

@app.post("/policies/conflict-check")
def conflict_check(data: ConflictCheckRequest):
    conflicts = detect_conflicts(data.condition, data.name)
    return {
        "policy_name": data.name,
        "conflicts_found": len(conflicts),
        "has_conflicts": len(conflicts) > 0,
        "conflicts": conflicts
    }

# Escalation Rules

@app.post("/escalation-rules")
def create_escalation_rule(data: EscalationRuleCreate):
    if data.escalate_to not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="escalate_to must be a valid severity level")
    with get_client() as client:
        r = client.post("/escalation_rules", json={
            "policy_id": data.policy_id,
            "trigger_count": data.trigger_count,
            "within_minutes": data.within_minutes,
            "escalate_to": data.escalate_to,
            "webhook_url": data.webhook_url,
            "active": True
        })
    return r.json()[0]

@app.get("/escalation-rules/{policy_id}")
def get_escalation_rules(policy_id: str):
    with get_client() as client:
        r = client.get("/escalation_rules", params={"policy_id": f"eq.{policy_id}"})
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

@app.post("/evaluate/session")
def evaluate_session(data: SessionEvaluate):
    with get_client() as client:
        prior = client.get("/interactions", params={
            "session_id": f"eq.{data.session_id}",
            "order": "evaluated_at.asc",
            "limit": "10"
        }).json()

    context = [
        {"user_input": p.get("user_input", ""), "ai_output": p.get("ai_output", "")}
        for p in prior
    ]

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

    result = run_evaluation(interaction_id, data.user_input, data.ai_output, context=context)
    return {
        "interaction_id": interaction_id,
        "session_id": data.session_id,
        "prior_turns_used": len(context),
        "passed": result["passed"],
        "violations": result["violations"]
    }

# Violations

@app.get("/violations")
def list_violations(severity: Optional[str] = None, policy_id: Optional[str] = None, resolved: Optional[bool] = None):
    params = {"order": "created_at.desc"}
    if severity:
        params["severity"] = f"eq.{severity}"
    if policy_id:
        params["policy_id"] = f"eq.{policy_id}"
    if resolved is not None:
        params["resolved"] = f"eq.{'true' if resolved else 'false'}"
    with get_client() as client:
        r = client.get("/violations", params=params)
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

# Analytics

@app.get("/analytics/policies")
def analytics_policies():
    with get_client() as client:
        policies = client.get("/policies", params={"active": "eq.true", "select": "*"}).json()
        all_evaluations = client.get("/evaluations", params={"select": "*"}).json()

    results = []
    for policy in policies:
        pid = policy["id"]
        policy_evals = [e for e in all_evaluations if e["policy_id"] == pid]
        total = len(policy_evals)
        passed = len([e for e in policy_evals if e["passed"]])
        failed = total - passed
        pass_rate = round(100 * passed / total, 2) if total > 0 else 100.0
        results.append({
            "policy_id": pid,
            "policy_name": policy["name"],
            "severity": policy["severity"],
            "total_evaluations": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": pass_rate
        })

    results.sort(key=lambda x: x["pass_rate"])
    return {"policies": results}

@app.get("/analytics/severity")
def analytics_severity():
    with get_client() as client:
        violations = client.get("/violations", params={"select": "*", "order": "created_at.asc"}).json()

    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_date = {}

    for v in violations:
        sev = v.get("severity", "low")
        breakdown[sev] = breakdown.get(sev, 0) + 1
        date = v.get("created_at", "")[:10]
        if date:
            if date not in by_date:
                by_date[date] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            by_date[date][sev] = by_date[date].get(sev, 0) + 1

    return {
        "total_violations": len(violations),
        "breakdown": breakdown,
        "by_date": [{"date": d, **counts} for d, counts in sorted(by_date.items())]
    }

# Audit Report

@app.get("/reports/audit")
def audit_report(
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None)
):
    params = {"order": "evaluated_at.desc"}
    if start_date:
        params["evaluated_at"] = f"gte.{start_date}"
    if end_date:
        params["evaluated_at"] = f"lte.{end_date}T23:59:59"

    with get_client() as client:
        interactions = client.get("/interactions", params=params).json()
        violations = client.get("/violations", params={"order": "created_at.desc"}).json()

    violations_by_interaction = {}
    for v in violations:
        iid = v["interaction_id"]
        if iid not in violations_by_interaction:
            violations_by_interaction[iid] = []
        violations_by_interaction[iid].append(v)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "interaction_id", "session_id", "model_used", "evaluated_at",
        "passed", "violation_count", "policy_names", "severities", "violation_reasons"
    ])

    for interaction in interactions:
        iid = interaction["id"]
        viols = violations_by_interaction.get(iid, [])
        passed = len(viols) == 0
        writer.writerow([
            iid,
            interaction.get("session_id", ""),
            interaction.get("model_used", ""),
            interaction.get("evaluated_at", ""),
            passed,
            len(viols),
            " | ".join([v["policy_name"] for v in viols]),
            " | ".join([v["severity"] for v in viols]),
            " | ".join([v["violation_reason"] for v in viols])
        ])

    output.seek(0)
    filename = f"policythread_audit_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# Webhooks

@app.post("/webhooks")
def create_webhook(data: WebhookCreate):
    with get_client() as client:
        r = client.post("/webhooks", json={
            "name": data.name,
            "url": data.url,
            "on_critical": data.on_critical,
            "on_high": data.on_high,
            "on_medium": data.on_medium,
            "on_low": data.on_low,
            "active": True
        })
    return r.json()[0]

@app.get("/webhooks")
def list_webhooks():
    with get_client() as client:
        r = client.get("/webhooks", params={"order": "created_at.desc"})
    return r.json()

@app.delete("/webhooks/{webhook_id}")
def deactivate_webhook(webhook_id: str):
    with get_client() as client:
        r = client.patch(f"/webhooks?id=eq.{webhook_id}", json={"active": False})
    if not r.json():
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"deactivated": True, "webhook_id": webhook_id}

# Alert Configs

@app.post("/alerts/config")
def create_alert_config(data: AlertConfigCreate):
    with get_client() as client:
        r = client.post("/alert_configs", json={
            "policy_id": data.policy_id,
            "min_pass_rate": data.min_pass_rate,
            "webhook_url": data.webhook_url,
            "active": True
        })
    return r.json()[0]

@app.get("/alerts/config/{policy_id}")
def get_alert_config(policy_id: str):
    with get_client() as client:
        r = client.get("/alert_configs", params={"policy_id": f"eq.{policy_id}"})
    data = r.json()
    if not data:
        raise HTTPException(status_code=404, detail="Alert config not found")
    return data[0]

# Attestations

@app.get("/attestations/{interaction_id}")
def get_attestations(interaction_id: str):
    with get_client() as client:
        r = client.get("/policy_attestations", params={
            "interaction_id": f"eq.{interaction_id}",
            "order": "created_at.asc"
        })
    return r.json()

@app.get("/attestations/chain/{policy_id}")
def get_attestation_chain(policy_id: str):
    with get_client() as client:
        r = client.get("/policy_attestations", params={
            "policy_id": f"eq.{policy_id}",
            "order": "created_at.asc"
        })
    chain = r.json()

    verified = True
    for i, record in enumerate(chain):
        expected_previous = chain[i-1]["chain_hash"] if i > 0 else "GENESIS"
        if record.get("previous_hash") != expected_previous:
            verified = False
            break

    return {
        "policy_id": policy_id,
        "chain_length": len(chain),
        "chain_verified": verified,
        "attestations": chain
    }

# Thread Suite Bridge

@app.get("/bridge/status")
def bridge_status():
    suite_status = {}
    tools = {
        "iron-thread": "https://iron-thread-production.up.railway.app/health",
        "test-thread": f"{TESTTHREAD_URL}/health",
        "prompt-thread": "https://prompt-thread.onrender.com/health",
        "chain-thread": f"{CHAINTHREAD_URL}/health"
    }
    for name, url in tools.items():
        try:
            with httpx.Client() as client:
                r = client.get(url, timeout=5)
            suite_status[name] = "online" if r.status_code == 200 else "degraded"
        except Exception:
            suite_status[name] = "offline"

    return {
        "policy_thread": "online",
        "suite": suite_status,
        "urls": {
            "iron-thread": "https://iron-thread-production.up.railway.app",
            "test-thread": TESTTHREAD_URL,
            "prompt-thread": "https://prompt-thread.onrender.com",
            "chain-thread": CHAINTHREAD_URL,
            "policy-thread": "https://policy-thread.onrender.com"
        }
    }

@app.post("/bridge/chainthread")
def bridge_chainthread(envelope_id: str, chain_id: str, sender_id: str, policy_ids: Optional[List[str]] = None):
    with get_client() as client:
        violations = client.get("/violations", params={
            "resolved": "eq.false",
            "order": "created_at.desc",
            "limit": "10"
        }).json()

    return {
        "envelope_id": envelope_id,
        "chain_id": chain_id,
        "sender_id": sender_id,
        "policy_violations_found": len(violations),
        "violations": violations,
        "chainthread_url": CHAINTHREAD_URL,
        "message": f"PolicyThread found {len(violations)} unresolved violation(s) linked to this chain context."
    }

@app.post("/bridge/chainthread/policy-envelope")
def policy_envelope(data: PolicyEnvelopeRequest):
    with get_client() as client:
        policies = client.get("/policies", params={"active": "eq.true", "select": "*"}).json()

    active_policy_snapshot = [
        {
            "policy_id": p["id"],
            "name": p["name"],
            "severity": p["severity"],
            "on_violation": p["on_violation"],
            "condition_type": p.get("condition", {}).get("type", "unknown")
        }
        for p in policies
    ]

    envelope_hash = hashlib.sha256(json.dumps({
        "chain_id": data.chain_id,
        "envelope_id": data.envelope_id,
        "sender_id": data.sender_id,
        "policy_count": len(active_policy_snapshot),
        "timestamp": datetime.utcnow().isoformat()
    }, sort_keys=True).encode()).hexdigest()

    session_violations = []
    if data.session_id:
        with get_client() as client:
            session_interactions = client.get("/interactions", params={
                "session_id": f"eq.{data.session_id}",
                "select": "id"
            }).json()
        interaction_ids = [i["id"] for i in session_interactions]
        for iid in interaction_ids:
            with get_client() as client:
                viols = client.get("/violations", params={
                    "interaction_id": f"eq.{iid}",
                    "resolved": "eq.false",
                    "select": "policy_name,severity,violation_reason"
                }).json()
            session_violations.extend(viols)

    return {
        "policy_envelope": {
            "chain_id": data.chain_id,
            "envelope_id": data.envelope_id,
            "sender_id": data.sender_id,
            "receiver_id": data.receiver_id,
            "active_policies": active_policy_snapshot,
            "policy_count": len(active_policy_snapshot),
            "envelope_hash": envelope_hash,
            "session_violations": session_violations,
            "session_violation_count": len(session_violations),
            "generated_at": datetime.utcnow().isoformat()
        },
        "message": "Policy envelope generated. Attach to ChainThread handoff payload for inherited compliance context."
    }