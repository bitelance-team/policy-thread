import httpx

class PolicyThread:
    def __init__(self, base_url="https://policy-thread.onrender.com"):
        self.base_url = base_url.rstrip("/")

    def _get(self, path, params=None):
        with httpx.Client() as client:
            r = client.get(f"{self.base_url}{path}", params=params)
            r.raise_for_status()
            return r.json()

    def _post(self, path, data):
        with httpx.Client() as client:
            r = client.post(f"{self.base_url}{path}", json=data)
            r.raise_for_status()
            return r.json()

    def _patch(self, path, data=None):
        with httpx.Client() as client:
            r = client.patch(f"{self.base_url}{path}", json=data or {})
            r.raise_for_status()
            return r.json()

    def _delete(self, path):
        with httpx.Client() as client:
            r = client.delete(f"{self.base_url}{path}")
            r.raise_for_status()
            return r.json()

    # Policies
    def create_policy(self, name, description=None, condition=None, severity="high", on_violation="alert"):
        return self._post("/policies", {
            "name": name,
            "description": description,
            "condition": condition or {},
            "severity": severity,
            "on_violation": on_violation
        })

    def list_policies(self):
        return self._get("/policies")

    def get_policy(self, policy_id):
        return self._get(f"/policies/{policy_id}")

    def update_policy(self, policy_id, **kwargs):
        return self._post(f"/policies/{policy_id}", kwargs)

    def deactivate_policy(self, policy_id):
        return self._delete(f"/policies/{policy_id}")

    def get_policy_history(self, policy_id):
        return self._get(f"/policies/{policy_id}/history")

    # Evaluate
    def evaluate(self, user_input, ai_output, session_id=None, model_used=None, metadata=None):
        return self._post("/evaluate", {
            "user_input": user_input,
            "ai_output": ai_output,
            "session_id": session_id,
            "model_used": model_used,
            "metadata": metadata or {}
        })

    def evaluate_batch(self, interactions):
        return self._post("/evaluate/batch", {"interactions": interactions})

    # Violations
    def list_violations(self, severity=None, policy_id=None, resolved=None):
        params = {}
        if severity:
            params["severity"] = severity
        if policy_id:
            params["policy_id"] = policy_id
        if resolved is not None:
            params["resolved"] = resolved
        return self._get("/violations", params=params)

    def get_violation(self, violation_id):
        return self._get(f"/violations/{violation_id}")

    def resolve_violation(self, violation_id):
        return self._patch(f"/violations/{violation_id}/resolve")

    # Interactions
    def list_interactions(self):
        return self._get("/interactions")

    def get_interaction(self, interaction_id):
        return self._get(f"/interactions/{interaction_id}")

    # Dashboard
    def stats(self):
        return self._get("/dashboard/stats")

    def health(self):
        return self._get("/health")