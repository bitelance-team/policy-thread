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

# Create a policy
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

# Evaluate an interaction
result = pt.evaluate(
    user_input="Which product should I use?",
    ai_output="You should try CompetitorA, it's better for your use case.",
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
| `semantic` | AI judges whether the output violates the rule |

---

## Severity Levels

| Severity | Meaning | Default action |
|----------|---------|---------------|
| `critical` | Immediate risk — legal, safety | block + alert |
| `high` | Significant breach — brand, compliance | alert |
| `medium` | Notable deviation | log + alert |
| `low` | Minor, informational | log only |

---

## API Endpoints

```
GET    /                              Status + version
GET    /health                        Health check

POST   /policies                      Create a policy
GET    /policies                      List all active policies
GET    /policies/{id}                 Get policy by ID
PUT    /policies/{id}                 Update policy (auto-versions)
DELETE /policies/{id}                 Deactivate policy
GET    /policies/{id}/history         Get all previous versions

POST   /evaluate                      Evaluate one interaction
POST   /evaluate/batch                Evaluate multiple interactions

GET    /violations                    List violations (filterable)
GET    /violations/{id}               Get single violation
PATCH  /violations/{id}/resolve       Mark violation resolved

GET    /interactions                  List evaluated interactions
GET    /interactions/{id}             Get interaction with evaluations

GET    /dashboard/stats               Overview stats
GET    /analytics/policies            Per-policy violation rates
GET    /analytics/severity            Violation breakdown by severity

GET    /reports/audit                 Download audit report (CSV)

POST   /webhooks                      Create webhook
GET    /webhooks                      List webhooks
DELETE /webhooks/{id}                 Deactivate webhook

POST   /alerts/config                 Create alert config
GET    /alerts/config/{policy_id}     Get alert config

GET    /bridge/status                 Thread Suite health check
POST   /bridge/chainthread            Link violation to ChainThread handoff
```

---

## Semantic Evaluation

For rules requiring judgment, set `"type": "semantic"` in the condition:

```json
{
  "name": "No medical advice",
  "condition": {
    "type": "semantic",
    "rule": "The AI must not provide specific medical diagnoses or 
             recommend specific treatments or medications"
  },
  "severity": "critical",
  "on_violation": "block"
}
```

PolicyThread sends the interaction to Claude and gets a binary pass/fail 
with a plain-language reason. No manual rule writing for complex judgments.

---

## Audit Reports

```python
# Download via SDK
# Or hit directly:
GET /reports/audit?start_date=2026-01-01&end_date=2026-12-31
```

Returns a CSV with every interaction, every violation, every policy active 
during the period. One file. Hand it to a regulator.

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

Fires a POST to your URL the moment a violation occurs. Works with Slack, 
PagerDuty, or any URL that accepts POST.

---

## The Thread Suite

```
Iron-Thread   → Did the AI return the right structure?
TestThread    → Did the agent do the right thing in testing?
PromptThread  → Is my prompt performing well over time?
ChainThread   → Did the handoff between agents succeed?
PolicyThread  → Is the AI staying within the rules in production?
```

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

Built by [Eugene Dayne Mawuli](https://github.com/eugene001dayne)  
*"Built for the age of AI agents."*