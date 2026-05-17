# PolicyThread

**Define what your AI must always do and never do. PolicyThread watches every
live interaction and tells you when it breaks the rules.**

Part of the [Thread Suite](https://github.com/eugene001dayne) — the reliability
layer for AI agents.

---

## The Problem

Organizations deploying AI in production have rules. Legal rules. Brand rules.
Safety rules. Compliance rules. Right now enforcing those rules is manual and
reactive — someone writes a system prompt, hopes for the best, and finds out the
AI broke the rules when a customer complains or a regulator asks.

There is no always-on layer watching every AI interaction against a defined
policy. No alert when the AI violates a rule. No audit trail proving the
organization tried.

PolicyThread fixes this.

---

## What It Does

- Write policies in plain language: *"Never recommend a competitor"*,
  *"Always include a disclaimer on financial advice"*
- Submit every AI interaction via API
- PolicyThread evaluates against all active policies instantly
- Violations are logged, alerts fire, dashboard updates in real time
- Download a full audit trail for any date range — one click
- Every evaluation generates a cryptographically chained attestation record
- Dry-run any policy against historical data before activating it
- Session-aware evaluation catches violations that only appear in context

---

## Live

| | |
|---|---|
| API | https://policy-thread.onrender.com |
| API Docs | https://policy-thread.onrender.com/docs |
| Dashboard | https://policy-thread.lovable.app |
| PyPI | `pip install policythread` |
| npm | `npm install policythread` |

---

## Quick Start

### Python

```python
from policythread import PolicyThread

pt = PolicyThread()

# Create a deterministic policy
pt.create_policy(
    name="No competitor mentions",
    description="AI output must never reference competitor products",
    condition={
        "type": "keyword_exclude",
        "keywords": ["CompetitorA", "CompetitorB"]
    },
    severity="high",
    on_violation="alert"
)

# Create a semantic policy — Claude judges the output
pt.create_policy(
    name="No medical advice",
    description="AI must never provide specific medical diagnoses",
    condition={
        "type": "semantic",
        "rule": "The AI must not provide specific medical diagnoses or recommend specific treatments or medications"
    },
    severity="critical",
    on_violation="block"
)

# Evaluate an interaction
result = pt.evaluate(
    user_input="Which product should I use?",
    ai_output="You should try CompetitorA, it is better for your use case.",
    model_used="gpt-4o",
    session_id="session-123"
)

if not result["passed"]:
    print("Violation:", result["violations"][0]["reason"])

# Get stats
print(pt.stats())
```

### JavaScript

```javascript
const { PolicyThread } = require('policythread');
const pt = new PolicyThread();

const result = await pt.evaluate(
    "Which product is best?",
    "CompetitorA is the best option.",
    "gpt-4o",
    "session-123"
);

if (!result.passed) {
    console.log("Violation:", result.violations[0].reason);
}
```

---

## Policy Types

| Type | What it checks |
|------|---------------|
| `keyword_exclude` | Output must not contain these words |
| `keyword_require` | Output must contain these words |
| `regex_exclude` | Output must not match this pattern |
| `regex_require` | Output must match this pattern |
| `max_length` | Output must not exceed N characters |
| `input_keyword_exclude` | User input must not contain these words |
| `semantic` | Claude judges whether the output violates the rule |

---

## Severity Levels

| Severity | Meaning | Default action |
|----------|---------|---------------|
| `critical` | Immediate risk — legal, safety | block + alert |
| `high` | Significant breach — brand, compliance | alert |
| `medium` | Notable deviation | log + alert |
| `low` | Minor, informational | log only |

---

## Policy Simulation

Test any policy against your historical interactions before activating it.
Nothing is logged. Dry-run only.

```python
POST /policies/simulate
{
  "name": "No financial advice",
  "condition": {
    "type": "semantic",
    "rule": "The AI must not provide specific investment recommendations"
  },
  "severity": "critical",
  "on_violation": "block"
}
```

Returns: `would_violate_count`, `would_pass_count`, `violation_rate`, full list
of which historical interactions would have been flagged.

---

## Session-Aware Evaluation

Standard evaluation checks each interaction in isolation. Session evaluation
passes the full prior conversation context to the semantic layer — catching
violations that only appear when you know what was said earlier.

```python
POST /evaluate/session
{
  "session_id": "session-123",
  "user_input": "OK do it",
  "ai_output": "I will proceed with the investment.",
  "model_used": "gpt-4o"
}
```

Returns `prior_turns_used` so you know how much context was applied.

---

## Conflict Detection

Every time you create or update a policy, PolicyThread automatically checks
for conflicts with all existing active policies. A policy that requires a
keyword another policy excludes will be flagged before it causes problems.

```json
{
  "conflicts_found": 1,
  "has_conflicts": true,
  "conflicts": [{
    "conflict_type": "require_exclude_overlap",
    "explanation": "'Must mention CompetitorA' requires keywords {'competitora'}
                    but 'No competitor mentions' excludes them. Both cannot be
                    satisfied simultaneously."
  }]
}
```

Run standalone: `POST /policies/conflict-check`

---

## Adaptive Escalation

When a policy fires repeatedly in a short window, escalate automatically.

```python
POST /escalation-rules
{
  "policy_id": "...",
  "trigger_count": 3,
  "within_minutes": 10,
  "escalate_to": "critical",
  "webhook_url": "https://hooks.slack.com/your-webhook"
}
```

If the policy fires 3 times in 10 minutes, severity escalates to critical and
your webhook fires immediately.

---

## Attestation Chain

Every evaluation — pass or fail — generates a SHA-256 signed attestation record
chained to the previous. The chain is mathematically verifiable. Any tampering
breaks it.

```python
GET /attestations/chain/{policy_id}

{
  "chain_length": 47,
  "chain_verified": true,
  "attestations": [...]
}
```

Hand the chain to a regulator. It proves every evaluation happened, in order,
and was never modified.

---

## Webhooks

```python
pt.create_webhook(
    name="Slack Compliance Alert",
    url="https://hooks.slack.com/your-webhook",
    on_critical=True,
    on_high=True,
    on_medium=False,
    on_low=False
)
```

Fires a POST the moment a violation occurs. Works with Slack, PagerDuty, or
any URL that accepts POST.

---

## Audit Reports

```
GET /reports/audit?start_date=2026-01-01&end_date=2026-12-31
```

Returns a CSV with every interaction evaluated, every violation logged, every
policy active during the period. One file. Hand it to a regulator or a board.

---

## API Endpoints

```
GET    /                                     Status + version
GET    /health                               Health check

POST   /policies                             Create policy (auto conflict check)
GET    /policies                             List all active policies
GET    /policies/{id}                        Get policy by ID
PUT    /policies/{id}                        Update policy (auto-versions)
DELETE /policies/{id}                        Deactivate policy
GET    /policies/{id}/history                Get all previous versions
POST   /policies/simulate                    Dry-run policy against history
POST   /policies/conflict-check              Check for policy conflicts

POST   /escalation-rules                     Create escalation rule
GET    /escalation-rules/{policy_id}         Get escalation rules for a policy

POST   /evaluate                             Evaluate one interaction
POST   /evaluate/batch                       Evaluate multiple interactions
POST   /evaluate/session                     Evaluate with session context

GET    /violations                           List violations (filterable)
GET    /violations/{id}                      Get single violation
PATCH  /violations/{id}/resolve              Mark violation resolved

GET    /interactions                         List evaluated interactions
GET    /interactions/{id}                    Get interaction with evaluations

GET    /dashboard/stats                      Overview stats
GET    /analytics/policies                   Per-policy violation rates
GET    /analytics/severity                   Violation breakdown by severity

GET    /reports/audit                        Download audit report CSV

POST   /webhooks                             Create webhook
GET    /webhooks                             List webhooks
DELETE /webhooks/{id}                        Deactivate webhook

POST   /alerts/config                        Create alert config
GET    /alerts/config/{policy_id}            Get alert config

GET    /attestations/{interaction_id}        Attestations for an interaction
GET    /attestations/chain/{policy_id}       Full verified attestation chain

GET    /bridge/status                        Thread Suite health check
POST   /bridge/chainthread                   Link violations to ChainThread
POST   /bridge/chainthread/policy-envelope   Generate policy envelope for handoff
```

---

## The Thread Suite

```
Iron-Thread   → Did the AI return the right structure?
TestThread    → Did the agent do the right thing in testing?
PromptThread  → Is my prompt performing well over time?
ChainThread   → Did the handoff between agents succeed?
PolicyThread  → Is the AI staying within the rules in production?
```

When a ChainThread handoff occurs, `POST /bridge/chainthread/policy-envelope`
generates a signed snapshot of all active compliance policies that travels with
the handoff. The receiving agent knows exactly what rules the sender was
operating under.

---

## Self-Hosting

```bash
git clone https://github.com/eugene001dayne/policy-thread.git
cd policy-thread
pip install -r requirements.txt
cp .env.example .env
# Fill in SUPABASE_URL, SUPABASE_KEY, ANTHROPIC_API_KEY
python -m uvicorn main:app --reload
```

---

---

## PolicyGuard — Enterprise AI Firewall (Hackathon Demo)

Built for the Enterprise AI Hackathon | Track 1: Agent Security & AI Governance

A Streamlit app that demonstrates PolicyThread as an enterprise AI firewall. Three capabilities in one interface:

**1. Live Attack Simulator** — Test prompts against real-time security policies. See exactly what gets blocked, why, and with what severity. Pre-loaded with prompt injection attempts and compliance violations across four agent types.

**2. Declared vs Detected Intent** — Define what your agent is supposed to do. Submit its actual response. Catches when agent behavior deviates from its declared purpose.

**3. Regulator-Ready Audit Trail** — PolicyThread's cryptographic attestation chain formatted as a compliance report. Tamper-evident. SHA-256 hash chaining. Suitable for regulatory submission.

### Run the demo

```bash
pip install streamlit httpx
streamlit run app.py
```

### Live demo
[Streamlit URL — add after deployment]

Built by Eugene Dayne Mawuli | BiteLance

---

Built by [Eugene Dayne Mawuli](https://github.com/eugene001dayne)
*"Built for the age of AI agents."*
