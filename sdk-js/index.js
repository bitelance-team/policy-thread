class PolicyThread {
  constructor(baseUrl = "https://policy-thread.onrender.com") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async _get(path, params = {}) {
    const url = new URL(`${this.baseUrl}${path}`);
    Object.entries(params).forEach(([k, v]) => url.searchParams.append(k, v));
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
    return res.json();
  }

  async _post(path, data) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`POST ${path} failed: ${res.status}`);
    return res.json();
  }

  async _patch(path, data = {}) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`PATCH ${path} failed: ${res.status}`);
    return res.json();
  }

  async _delete(path) {
    const res = await fetch(`${this.baseUrl}${path}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`DELETE ${path} failed: ${res.status}`);
    return res.json();
  }

  // Policies
  async createPolicy(name, description, condition, severity = "high", onViolation = "alert") {
    return this._post("/policies", { name, description, condition, severity, on_violation: onViolation });
  }

  async listPolicies() {
    return this._get("/policies");
  }

  async getPolicy(policyId) {
    return this._get(`/policies/${policyId}`);
  }

  async deactivatePolicy(policyId) {
    return this._delete(`/policies/${policyId}`);
  }

  async getPolicyHistory(policyId) {
    return this._get(`/policies/${policyId}/history`);
  }

  // Evaluate
  async evaluate(userInput, aiOutput, modelUsed = null, sessionId = null, metadata = {}) {
    return this._post("/evaluate", {
      user_input: userInput,
      ai_output: aiOutput,
      model_used: modelUsed,
      session_id: sessionId,
      metadata
    });
  }

  async evaluateBatch(interactions) {
    return this._post("/evaluate/batch", { interactions });
  }

  // Violations
  async listViolations(params = {}) {
    return this._get("/violations", params);
  }

  async getViolation(violationId) {
    return this._get(`/violations/${violationId}`);
  }

  async resolveViolation(violationId) {
    return this._patch(`/violations/${violationId}/resolve`);
  }

  // Interactions
  async listInteractions() {
    return this._get("/interactions");
  }

  async getInteraction(interactionId) {
    return this._get(`/interactions/${interactionId}`);
  }

  // Dashboard
  async stats() {
    return this._get("/dashboard/stats");
  }

  async health() {
    return this._get("/health");
  }
}

module.exports = { PolicyThread };