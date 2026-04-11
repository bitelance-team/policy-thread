# policythread

Define what your AI must always do and never do. PolicyThread watches every live interaction and tells you when it breaks the rules.

## Install

pip install policythread

## Usage

from policythread import PolicyThread

pt = PolicyThread()

policy = pt.create_policy(
    name="No competitor mentions",
    description="AI output must never reference competitors",
    condition={"type": "keyword_exclude", "keywords": ["CompetitorA", "CompetitorB"]},
    severity="high",
    on_violation="alert"
)

result = pt.evaluate(
    user_input="Which product should I use?",
    ai_output="You should try CompetitorA.",
    model_used="gpt-4o",
    session_id="session-123"
)

if not result["passed"]:
    print("Violation:", result["violations"][0]["reason"])

stats = pt.stats()